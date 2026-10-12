"""Versioned lifecycle stores; Seed source/signing lineage remains unchanged.

The legacy physical schema is never migrated. Modern receipt creation can be
disabled during rollback while all signed history remains readable/closable.
"""
from hashlib import sha256
import json,os,uuid
from pathlib import Path
from typing import Any

from .signing import Ed25519Signer,TrustedKey
from .canonical import canonical_bytes
from .turn_memory import TurnMemoryError, TurnMemoryStore,_signed_receipt,_verify_receipt,_utc_now

COVERAGE_PROTOCOL='integrity-guardian/turn-memory-coverage/v2'
PROFILES=('legacy-v1','native-intent-v1')

def _sync_directory(path:Path)->None:
    if os.name!='posix':
        raise TurnMemoryError('native bootstrap requires POSIX directory durability')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
    try:os.fsync(fd)
    finally:os.close(fd)

class VersionedTurnMemoryService:
    def __init__(self,legacy_path:Path,*,namespace:str,signer:Ed25519Signer,
                 native_path:Path|None=None,modern_creation_enabled:bool=True,
                 initialize_native:bool=False):
        if not isinstance(modern_creation_enabled,bool) or not isinstance(initialize_native,bool):
            raise TurnMemoryError('turn-memory profile policy flag is invalid')
        legacy=Path(legacy_path)
        native=Path(native_path) if native_path is not None else legacy.with_name('native-intent-v1.sqlite3')
        if not legacy.is_absolute() or not native.is_absolute() or legacy.resolve()==native.resolve():
            raise TurnMemoryError('turn-memory profile paths must be distinct absolute paths')
        self.namespace=namespace
        self.modern_creation_enabled=modern_creation_enabled
        self.paths={'legacy-v1':legacy,'native-intent-v1':native}
        self.stores:dict[str,TurnMemoryStore|None]={key:None for key in PROFILES}
        self.failures:dict[str,str]={}
        for profile in PROFILES:
            try:
                if profile=='native-intent-v1' and initialize_native and self.stores['legacy-v1'] is None:
                    raise TurnMemoryError('native bootstrap requires verified existing legacy lineage')
                if profile=='native-intent-v1':
                    self._verify_or_bootstrap_native(native,namespace,signer,initialize_native)
                self.stores[profile]=TurnMemoryStore(self.paths[profile],namespace=namespace,signer=signer,
                    identity_profile=profile,create=False)
            except Exception as exc:
                self.failures[profile]=sha256((type(exc).__name__+':'+str(exc)).encode()).hexdigest()

    @staticmethod
    def _verify_or_bootstrap_native(native:Path,namespace:str,signer:Ed25519Signer,initialize:bool)->None:
        marker=native.with_name(native.name+'.bootstrap.json')
        trusted=TrustedKey(signer.key_id,signer.public_key)
        if marker.exists() or marker.is_symlink():
            if marker.is_symlink() or not marker.is_file() or marker.stat().st_size>16384:
                raise TurnMemoryError('native bootstrap custody is invalid')
            observed=_verify_receipt(json.loads(marker.read_bytes()),schema='turn-memory-native-bootstrap',
                protocol='integrity-guardian/turn-memory-native-bootstrap/v1',
                id_domain='turn-memory-native-bootstrap-v1',trusted_key=trusted)
            if observed['namespace_fingerprint']!=namespace or observed['native_path']!=str(native):
                raise TurnMemoryError('native bootstrap subject mismatch')
            if observed['phase']!='complete':raise TurnMemoryError('native bootstrap outcome requires owning reconciliation')
            if not native.is_file():raise TurnMemoryError('consumed native bootstrap cannot recreate missing history')
            return
        if not initialize or native.exists() or native.is_symlink():
            raise TurnMemoryError('native profile has no verified one-shot bootstrap custody')
        core={'protocol':'integrity-guardian/turn-memory-native-bootstrap/v1',
            'namespace_fingerprint':namespace,'native_path':str(native),'phase':'reserved',
            'created_at':_utc_now(),'production_authority':False}
        reserved=_signed_receipt(core,id_domain='turn-memory-native-bootstrap-v1',signer=signer)
        raw=canonical_bytes(reserved)
        fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        _sync_directory(marker.parent)
        # Reservation stays consumed on failure. Normal startup never repairs it.
        TurnMemoryStore(native,namespace=namespace,signer=signer,identity_profile='native-intent-v1',create=True)
        complete=_signed_receipt({**core,'phase':'complete'},id_domain='turn-memory-native-bootstrap-v1',signer=signer)
        temporary=marker.with_name(marker.name+'.complete-'+uuid.uuid4().hex)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(canonical_bytes(complete));stream.flush();os.fsync(stream.fileno())
            if marker.is_symlink() or marker.read_bytes()!=raw:raise TurnMemoryError('native bootstrap reservation changed')
            os.replace(temporary,marker)
            _sync_directory(marker.parent)
        finally:
            if temporary.exists():temporary.unlink()

    @property
    def complete(self)->bool:
        return all(self.stores[p] is not None for p in PROFILES)

    def _store(self,profile:str)->TurnMemoryStore:
        result=self.stores[profile]
        if result is None:raise TurnMemoryError('turn-memory identity profile is unavailable: '+profile)
        return result

    def open_turn(self,**arguments)->dict[str,Any]:
        profile='native-intent-v1' if arguments.get('intent_id') is not None else 'legacy-v1'
        if 'allow_create' in arguments:raise TurnMemoryError('caller cannot supply profile creation policy')
        return self._store(profile).open_turn(**arguments,
            allow_create=(self.modern_creation_enabled if profile=='native-intent-v1' else True))

    def _registration_owner(self,registration_id:str)->tuple[str,TurnMemoryStore]:
        # Every lookup completes before either store can receive a mutation.
        # An unavailable/corrupt store is UNKNOWN, not a missing registration.
        matches=[]
        for profile in PROFILES:
            store=self._store(profile)
            try:receipt=store.find_registration(registration_id)
            except Exception as exc:
                raise TurnMemoryError('turn-memory registration routing is unobservable') from exc
            if receipt is not None:matches.append((profile,store))
        if len(matches)!=1:
            raise TurnMemoryError('turn-memory registration routing requires exactly one verified owner')
        return matches[0]

    def close_turn(self,*,registration_id:str,**arguments)->dict[str,Any]:
        _,store=self._registration_owner(registration_id)
        return store.close_turn(registration_id=registration_id,**arguments)

    def observe_gap(self,*,registration_id:str,**arguments)->dict[str,Any]:
        _,store=self._registration_owner(registration_id)
        return store.observe_gap(registration_id=registration_id,**arguments)

    def profile_for_registration(self,registration_id:str)->str:
        return self._registration_owner(registration_id)[0]

    def coverage(self,*,machine_id:str|None=None,thread_id:str|None=None,limit:int=100)->dict[str,Any]:
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=500:
            raise TurnMemoryError('coverage limit is invalid')
        known={key:0 for key in ('registered','terminal','events','no_event','unresolved')}
        from datetime import datetime,timezone
        stores=[];unresolved=[];complete=True;receipt_sample=[];size_limited=False
        sample_budget=262_144
        for profile in PROFILES:
            try:
                observed=self._store(profile).coverage(machine_id=machine_id,thread_id=thread_id,limit=limit)
                if observed['namespace_fingerprint']!=self.namespace:
                    raise TurnMemoryError('turn-memory profile coverage namespace mismatch')
                policy=self._store(profile).creation_policy() if profile=='native-intent-v1' else None
                for key in known:known[key]+=observed['counts'][key]
                unresolved.extend({**entry,'store_id':profile} for entry in observed['unresolved'])
                sample=observed['receipt_sample']
                if sample['absence_is_retry_authority'] is not False or sample['canonical_writes'] != 0 or len(canonical_bytes(sample)) > sample_budget:
                    raise TurnMemoryError('receipt sample validation failed')
                size_limited=size_limited or sample['size_limited']
                receipt_sample.extend({**entry,'store_id':profile} for entry in sample['receipts'])
                stores.append({'store_id':profile,'status':'ready','counts':observed['counts'],
                    'namespace_fingerprint':self.namespace})
                if policy is not None:stores[-1]['creation_policy']=policy
            except Exception as exc:
                complete=False
                stores.append({'store_id':profile,'status':'unavailable','counts':None,
                    'namespace_fingerprint':self.namespace,
                    'failure_digest':'sha256:'+sha256((type(exc).__name__+':'+str(exc)).encode()).hexdigest()})
        # Stable bounded union; each registration belongs to one signed profile.
        unresolved=sorted(unresolved,key=lambda item:(item['registration_id'],item['store_id']))[:limit]
        # Per-profile samples are newest-first and bounded before the union.
        # A signed positive match remains usable; omission never authorizes replay.
        sample_ids=[entry['registration_id'] for entry in receipt_sample]
        if len(set(sample_ids)) != len(sample_ids):
            raise TurnMemoryError('ambiguous receipt profile sample')
        receipt_sample=sorted(receipt_sample,key=lambda entry:(datetime.fromisoformat(entry['registration_receipt']['opened_at'].replace('Z','+00:00')).astimezone(timezone.utc),entry['registration_id'],entry['store_id']),reverse=True)
        bounded=[]
        sample_header={'protocol':'integrity-guardian/turn-memory-receipt-sample/v1',
            'receipts':[],'limit':limit,'returned_count':0,'complete':False,'has_more':False,
            'size_limited':False,'byte_budget':sample_budget,
            'absence_is_retry_authority':False,'canonical_writes':0}
        for entry in receipt_sample:
            if len(bounded) >= limit:break
            proposed={**sample_header,'receipts':bounded+[entry],'returned_count':len(bounded)+1}
            if len(canonical_bytes(proposed)) <= sample_budget:bounded.append(entry)
            else:size_limited=True
        receipt_sample=bounded
        policy=next((row.get('creation_policy') for row in stores if row['store_id']=='native-intent-v1'),None)
        return {'protocol':COVERAGE_PROTOCOL,'namespace_fingerprint':self.namespace,
            'complete':complete,'counts':known if complete else None,'known_counts':known,
            'stores':stores,'unresolved':unresolved,'returned_count':len(unresolved),
            'receipt_sample':{'protocol':'integrity-guardian/turn-memory-receipt-sample/v1',
                'receipts':receipt_sample,'limit':limit,'returned_count':len(receipt_sample),
                'complete':complete and known['registered']==len(receipt_sample),'has_more':(known['registered']>len(receipt_sample)) if complete else None,
                'size_limited':size_limited,'byte_budget':sample_budget,
                'absence_is_retry_authority':False,'canonical_writes':0},
            'modern_creation_enabled':(self.modern_creation_enabled and policy['mode']=='enabled') if policy is not None else None,
            'production_authority':False}

    def close(self)->None:
        # Store calls close their SQLite connections; no persistent resources.
        pass
