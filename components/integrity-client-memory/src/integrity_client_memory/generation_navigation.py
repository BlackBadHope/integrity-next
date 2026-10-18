"""Pure exact-preimage generation navigation renderer.

This module performs no I/O, application reload, identity creation or authority
change. The caller supplies its own captured config digest and selected broker.
"""
from copy import deepcopy
import hashlib
import json
import re
import tomllib

class NavigationError(ValueError):
    """A config cannot be proven to be the requested input or exact postimage."""

SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def render_config(payload:bytes, *, expected_sha256:str, generation:str,
                  command:str, broker_script:str)->bytes:
    """Add one inert NAV field, preserving all other config bytes and meaning.

    Applying returned bytes and requesting a normal MCP refresh are separate
    owner actions. This source helper grants neither permission nor identity.
    """
    if (not isinstance(expected_sha256,str) or re.fullmatch(r'[a-f0-9]{64}',expected_sha256) is None
            or not isinstance(generation,str) or re.fullmatch(r'[a-f0-9]{64}',generation) is None
            or not isinstance(command,str) or not command
            or not isinstance(broker_script,str) or not broker_script):
        raise NavigationError('navigation_inputs_invalid')
    GENERATION=generation
    SERVER='integrity_client_memory'
    KEY='INTEGRITY_MCP_GENERATION_NAV'
    COMMAND=command
    SHIM=broker_script

    def _parse(payload):
        if type(payload) is not bytes or len(payload)>4*1024*1024:raise NavigationError('config_bytes_invalid')
        try:
            text=payload.decode('utf-8');original=tomllib.loads(text)
        except (UnicodeError,tomllib.TOMLDecodeError):raise NavigationError('invalid_config_encoding_or_toml') from None
        public=original.get('mcp_servers',{}).get(SERVER)
        if not isinstance(public,dict) or public.get('command')!=COMMAND or not isinstance(public.get('args'),list) or SHIM not in public['args']:
            raise NavigationError('public_selector_config_mismatch')
        env=public.get('env',{})
        if not isinstance(env,dict):raise NavigationError('invalid_env_type')
        if KEY in env and env[KEY]!=GENERATION:raise NavigationError('existing_different_navigation_field')
        return text,original,public,env

    def _headers(text):
        root=re.compile(r'(?m)^\[mcp_servers\.integrity_client_memory\][ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)')
        env=re.compile(r'(?m)^\[mcp_servers\.integrity_client_memory\.env\][ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)')
        return list(root.finditer(text)),list(env.finditer(text))

    def _same_is_proven_postimage(text,preimage):
        # Reverse only exact bytes this renderer adds; never accept unrelated drift.
        value=json.dumps(GENERATION);keyline=KEY+' = '+value
        candidates=[]
        for newline in ('\n','\r\n'):
            suffix=newline+'[mcp_servers.'+SERVER+'.env]'+newline+keyline+newline
            if text.endswith(suffix):candidates.append(text[:-len(suffix)])
            roots,envs=_headers(text)
            for header in envs:
                if text[header.end():].startswith(keyline+newline):
                    candidate=text[:header.end()]+text[header.end()+len(keyline+newline):]
                    candidates.append(candidate)
                    if candidate[:header.end()].endswith(newline):
                        candidates.append(candidate[:header.end()-len(newline)]+candidate[header.end():])
            for marker in (' '+keyline+', ',' '+keyline+' '):
                for match in re.finditer(re.escape('{'+marker),text):
                    candidates.append(text[:match.start()+1]+text[match.end():])
        return any(SHA(candidate.encode())==preimage for candidate in candidates)

    def _render(payload:bytes,preimage:str)->bytes:
        """Internal transformation; callers use render_config() with their exact preimage."""
        text,original,public,env=_parse(payload)
        if KEY in env:
            if SHA(payload)==preimage or _same_is_proven_postimage(text,preimage):return payload
            raise NavigationError('idempotent_postimage_unproven')
        if SHA(payload)!=preimage:raise NavigationError('config_preimage_mismatch')
        newline='\r\n' if '\r\n' in text else '\n';value=json.dumps(GENERATION)
        if 'env' not in public:
            candidate=text+newline+'[mcp_servers.'+SERVER+'.env]'+newline+KEY+' = '+value+newline
        else:
            roots,envs=_headers(text)
            if len(envs)==1:
                header=envs[0];separator='' if text[header.start():header.end()].endswith('\n') else newline
                candidate=text[:header.end()]+separator+KEY+' = '+value+newline+text[header.end():]
            elif envs:raise NavigationError('duplicate_env_header')
            else:
                if len(roots)!=1:raise NavigationError('unsupported_public_header')
                start=roots[0].end();next_header=re.search(r'(?m)^\[',text[start:]);end=start+next_header.start() if next_header else len(text)
                body=text[start:end];marker=' '+KEY+' = '+value+(', ' if env else ' ')
                updated,count=re.subn(r'(?m)^([ \t]*env[ \t]*=[ \t]*)\{',lambda m:m[1]+'{'+marker,body)
                if count!=1:raise NavigationError('unsupported_env_form')
                candidate=text[:start]+updated+text[end:]
        expected=deepcopy(original);expected['mcp_servers'][SERVER]['env']={**env,KEY:GENERATION}
        try:actual=tomllib.loads(candidate)
        except tomllib.TOMLDecodeError:raise NavigationError('rendered_toml_invalid') from None
        if actual!=expected:raise NavigationError('unexpected_semantic_change')
        return candidate.encode('utf-8')

    return _render(payload,expected_sha256)
