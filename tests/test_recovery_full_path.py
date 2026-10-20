"""Actual admission/open/append/close; isolated cryptographic and HTTP stand."""
import pytest
from recovery_stand_fixture import Stand
from recovery_stand_fixture import digest
from integrity_guardian import memory_synapse_mcp as mcp
from integrity_client_memory import operation_ledger, recovery_client


@pytest.mark.parametrize('retained',[True,False])
def test_real_stdio_process_full_lifecycle(tmp_path,retained):
    """OS pipes -> real MCP serve -> Native -> actual HTTP Action Log."""
    import json,os,selectors,sqlite3,subprocess,sys,uuid
    from pathlib import Path
    if os.name!='posix':pytest.skip('isolated Linux wire stand')
    worker_root=tmp_path/'wire-worker'
    process=subprocess.Popen([sys.executable,'-u',str(Path(__file__).with_name('recovery_stdio_worker.py')),
        str(worker_root),*([] if retained else ['--capacity-exhausted'])],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    class WireStand(Stand):
        def __init__(self):
            self.subject_thread=str(uuid.uuid4());self.admissions={};self.wire=[];self.next_id=0
        def rpc(self,f,method,params):
            self.next_id+=1
            self.wire.append({'method':method,'tool':params.get('name')})
            message={'jsonrpc':'2.0','id':self.next_id,'method':method,'params':params}
            process.stdin.write(json.dumps(message).encode()+b'\n');process.stdin.flush()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                assert selector.select(12),'bounded real stdio response timed out'
            response=json.loads(process.stdout.readline())
            assert response.get('id')==self.next_id and 'error' not in response,response
            return response['result']
    remote=WireStand()
    try:
        replay,caps=remote.initialize(None)
        assert caps[mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY]['reservation_status']==('reserved' if retained else 'unavailable')
        admission=remote.admit(None,1,replay if retained else None)
        opened=remote.tool(None,'integrity_turn_memory_open',remote.args)
        assert opened['session_recovery']['available'] is retained
        event=remote.append(None,admission,'actual-stdio')
        terminal=remote.close_turn(None,opened,event)
        assert terminal['receipt']['registration_id']==opened['receipt']['receipt_id']
        assert sum(x.get('tool')=='integrity_context_admission' for x in remote.wire)==1
        assert sum(x.get('tool')=='integrity_turn_memory_open' for x in remote.wire)==1
        process.stdin.close();process.wait(timeout=8)
        assert process.returncode==0
        with sqlite3.connect((worker_root/'stand-events.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
            assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==2
    finally:
        if process.poll() is None:
            process.terminate();process.wait(timeout=5)
        process.stdout.close();process.stderr.close()


class RealConnection:
    """Actual protocol dispatch; inject only the transport delivery outcome."""
    def __init__(self, stand, facade, *, fault=None, restore=False):
        self.stand, self.facade, self.fault = stand, facade, fault
        self.requires_restore = restore
        self.send_count = 0

    def send(self, tool, arguments):
        self.send_count += 1
        if self.fault in {'unsent', 'unknown-unsent'}:
            raise recovery_client.DeliveryFault(request_sent=self.fault=='unknown-unsent', retryable=True)
        result = self.stand.rpc(self.facade, 'tools/call', {'name':tool,'arguments':arguments})
        if self.fault == 'lost-after-commit':
            raise recovery_client.DeliveryFault(request_sent=True, retryable=True)
        return result

    def status(self, params):
        return self.stand.rpc(self.facade, 'integrity/operation_status', params)

    def recover(self, params):
        return self.stand.rpc(self.facade, mcp.RECOVERY_METHOD, params)

    def close(self):
        self.facade.close()


def real_client(stand, facade, opened, *, fault=None):
    controls = stand.controls(1, opened)
    registration = controls.pop('registration_id')
    connections = [RealConnection(stand, facade, fault=fault)]
    custody = stand.root / 'client-custody'
    custody.mkdir(mode=0o700, exist_ok=True)
    ledger = operation_ledger.OperationLedger(custody / 'operations.sqlite3')
    def connect():
        f = stand.facade()
        stand.initialize(f, control_only=True)
        current = RealConnection(stand, f, restore=True)
        connections.append(current)
        return current
    # This harness does not substitute for the actual vendor ownership adapter.
    # Exact owner/receipt matching below is within the isolated synthetic producer.
    def validate():
        assert opened['receipt']['identity'] == {k:stand.args[k] for k in
            ('machine_id','thread_id','turn_id','intent_id')}
    client = recovery_client.RecoveryClient(ledger, validate_own=validate, connect=connect)
    return client, ledger, connections, registration, controls


@pytest.mark.parametrize('tool', ['integrity_append_event','integrity_turn_memory_close'])
@pytest.mark.parametrize('fault', ['lost-after-commit','unsent'])
def test_real_client_reconciles_delivery_without_duplicate_or_readmission(stand, tool, fault):
    f=stand.facade();replay,_=stand.initialize(f)
    admitted=stand.admit(f,1,replay)
    opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
    assert opened['session_recovery']['available'] is True
    client,ledger,connections,registration,control=real_client(stand,f,opened,fault=fault)
    if tool=='integrity_append_event':
        arguments={'context_admission_id':admitted['context_admission_id'],
            'event_uid':'client:stand46:'+stand.subject_thread+':lost',
            'kind':'thought','summary':'Actual HTTP append with bounded transport failure'}
    else:
        arguments={'registration_id':registration,'outcome':'no-event','no_event_reason':'read-only'}
    result=client.execute(tool,arguments,registration_id=registration,control=control,
        connection=connections[0])
    assert recovery_client.confirmed_result(tool,arguments,result)
    assert len(connections)==2
    assert [c.send_count for c in connections] == ([1,0] if fault=='lost-after-commit' else [1,1])
    assert ledger.get(registration,recovery_client.operation_key(tool,arguments))['state']=='committed'
    assert sum(x.get('tool')=='integrity_context_admission' for x in stand.wire)==1
    assert sum(x.get('tool')=='integrity_turn_memory_open' for x in stand.wire)==1
    cold_client=recovery_client.RecoveryClient(ledger,validate_own=client.validate_own,connect=client.connect)
    cached=cold_client.execute(tool,arguments,registration_id=registration,control=control,
        connection=connections[-1])
    assert cached==result
    assert sum(c.send_count for c in connections)==(1 if fault=='lost-after-commit' else 2)
    if tool=='integrity_append_event':
        body=recovery_client.unpack(result)
        closing={'registration_id':registration,'outcome':'events',
            'events':[{k:body['receipt'][k] for k in ('event_id','event_uid','request_sha256')}]}
        terminal=client.execute('integrity_turn_memory_close',closing,
            registration_id=registration,control=control,connection=connections[-1])
        assert recovery_client.confirmed_result('integrity_turn_memory_close',closing,terminal)
        assert stand.event_count()==2
    else:
        assert stand.event_count()==1
    assert f.turn_memory.coverage()['counts']['registered']==1
    assert f.turn_memory.coverage()['counts']['terminal']==1


def test_real_client_unknown_absence_does_not_blindly_resend(stand):
    f=stand.facade();replay,_=stand.initialize(f)
    admitted=stand.admit(f,1,replay);opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
    client,ledger,connections,registration,control=real_client(stand,f,opened,fault='unknown-unsent')
    arguments={'context_admission_id':admitted['context_admission_id'],
        'event_uid':'client:stand46:'+stand.subject_thread+':unresolved',
        'kind':'thought','summary':'Unresolved transport result must remain explicit debt'}
    with pytest.raises(recovery_client.DeliveryPending,match='no blind replay'):
        client.execute('integrity_append_event',arguments,registration_id=registration,
            control=control,connection=connections[0])
    assert [c.send_count for c in connections]==[1,0]
    assert ledger.get(registration,recovery_client.operation_key('integrity_append_event',arguments))['state']=='unknown'
    assert stand.event_count()==1
    assert f.turn_memory.coverage()['counts']['terminal']==0

@pytest.fixture
def stand(tmp_path,monkeypatch):
    if __import__('os').name!='posix':pytest.skip('actual POSIX recovery custody requires Linux stand')
    result=Stand(tmp_path,monkeypatch)
    yield result
    result.stop()

def test_no_reserve_actual_admission_open_append_close(stand):
    filler=stand.facade();stand.initialize(filler)
    assert stand.fill_reservations(filler)>0
    f=stand.facade();_,caps=stand.initialize(f)
    assert caps['integrity/session-recovery']['protocol']=='integrity-client/session-recovery/v1'
    replay=caps[mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY]
    assert replay['reservation_status']=='unavailable'
    admission=stand.admit(f,1)
    opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
    assert opened['session_recovery']['available'] is False
    assert opened['session_recovery']['reason']=='admission-not-retained'
    event=stand.append(f,admission)
    assert event['receipt']['action_outcome']=='confirmed-success'
    terminal=stand.close_turn(f,opened,event)
    assert terminal['receipt']['registration_id']==opened['receipt']['receipt_id']
    assert f.turn_memory.coverage()['counts']['registered']==1
    assert f.turn_memory.coverage()['counts']['terminal']==1
    assert stand.event_count()==2

def test_retained_actual_admission_open_append_close(stand):
    f=stand.facade();replay,caps=stand.initialize(f)
    assert caps[mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY]['reservation_status']=='reserved'
    admission=stand.admit(f,1,replay)
    opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
    assert opened['session_recovery']['available'] is True,{
        'availability':opened['session_recovery'],'diagnostic':opened.get('_stand_safe_diagnostic')}
    event=stand.append(f,admission)
    assert event['receipt']['action_outcome']=='confirmed-success'
    stand.close_turn(f,opened,event)
    assert (stand.event_count(),f.turn_memory.coverage()['counts']['registered'])==(2,1)

def test_successor_without_reserve_cannot_reuse_retained_predecessor(stand):
    f=stand.facade();replay,_=stand.initialize(f)
    stand.admit(f,1,replay)
    first=stand.tool(f,'integrity_turn_memory_open',stand.args)
    controls=stand.controls(1,first)
    assert stand.fill_reservations(f)>0
    second_admission=stand.admit(f,2)
    second=stand.tool(f,'integrity_turn_memory_open',stand.args)
    assert second['session_recovery']['available'] is False
    assert second['receipt']['receipt_id']!=first['receipt']['receipt_id']
    with pytest.raises(AssertionError):stand.rpc(f,mcp.RECOVERY_METHOD,controls)
    wrong=stand.rpc(f,'tools/call',{'name':'integrity_turn_memory_close','arguments':{
        'registration_id':first['receipt']['receipt_id'],'outcome':'no-event','no_event_reason':'read-only'}})
    assert wrong['isError'] is True
    event=stand.append(f,second_admission,'successor')
    stand.close_turn(f,second,event)
    assert f.turn_memory.coverage()['counts']['registered']==2
    assert f.turn_memory.coverage()['counts']['terminal']==1
    assert stand.event_count()==2

def test_idle_cleanup_then_exact_recovery_no_readmission_or_reopen(stand):
    f=stand.facade();replay,_=stand.initialize(f)
    admitted=stand.admit(f,1,replay)
    opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
    controls=stand.controls(1,opened)
    assert f.release_idle_context()
    restored=stand.rpc(f,mcp.RECOVERY_METHOD,controls)
    assert restored['restored'] and restored['same_session'] and not restored['read_only']
    assert restored['context_admission_id']==admitted['context_admission_id']
    event=stand.append(f,admitted,'after-idle')
    stand.close_turn(f,opened,event)
    assert f.turn_memory.coverage()['counts']['registered']==1
    assert sum(x.get('tool')=='integrity_context_admission' for x in stand.wire)==1
    assert sum(x.get('tool')=='integrity_turn_memory_open' for x in stand.wire)==1

def test_cold_facade_control_only_restores_original_signed_registration(stand):
    first=stand.facade();replay,_=stand.initialize(first)
    admitted=stand.admit(first,1,replay)
    opened=stand.tool(first,'integrity_turn_memory_open',stand.args)
    controls=stand.controls(1,opened)
    first.close()
    cold=stand.facade();_,caps=stand.initialize(cold,control_only=True)
    assert caps['integrity/session-recovery']['protocol']=='integrity-client/session-recovery/v1'
    restored=stand.rpc(cold,mcp.RECOVERY_METHOD,controls)
    assert restored['registration_id']==opened['receipt']['receipt_id']
    event=stand.append(cold,admitted,'after-cold')
    stand.close_turn(cold,opened,event)
    assert cold.turn_memory.coverage()['counts']['registered']==1
    assert stand.event_count()==2

def test_foreign_and_changed_retained_proofs_stay_denied(stand):
    f=stand.facade();replay,_=stand.initialize(f)
    stand.admit(f,1,replay);opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
    controls=stand.controls(1,opened)
    assert f.release_idle_context()
    for bad in [dict(controls,response_digest=digest('changed')),
                dict(controls,registration_id=digest('foreign-registration'))]:
        with pytest.raises(AssertionError):stand.rpc(f,mcp.RECOVERY_METHOD,bad)
    assert stand.event_count()==1
    assert f.turn_memory.coverage()['counts']['registered']==1
    stand.rpc(f,mcp.RECOVERY_METHOD,controls)
    stand.close_turn(f,opened)

def test_derived_binding_failure_preserves_receipt_and_keeps_replay_fail_closed(stand):
    f=stand.facade();replay,_=stand.initialize(f)
    admitted=stand.admit(f,1,replay)
    (stand.archroot/'same-session-recovery-v1.sqlite3').mkdir(mode=0o700)
    opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
    assert opened['session_recovery']['available'] is False
    assert opened['session_recovery']['reason']=='derived-binding-unavailable'
    assert opened['receipt']['signature']
    assert f.turn_memory.coverage()['counts']['registered']==1
    denied=stand.rpc(f,'tools/call',{'name':'integrity_append_event','arguments':{
        'context_admission_id':admitted['context_admission_id'],'event_uid':'client:stand46:denied',
        'kind':'thought','summary':'Must not bypass retained binding failure'}})
    assert denied['isError'] is True
    assert stand.event_count()==1
