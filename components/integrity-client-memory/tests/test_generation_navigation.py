"""The caller-owned config is preserved; NAV neither executes nor changes identity."""
import hashlib
import tomllib
import pytest
from integrity_client_memory.generation_navigation import render_config,NavigationError

GENERATION='a'*64
COMMAND='python'
BROKER='/example/owner/broker.py'

def change(raw,**changes):
    args={'expected_sha256':hashlib.sha256(raw).hexdigest(),'generation':GENERATION,
          'command':COMMAND,'broker_script':BROKER}
    args.update(changes)
    return render_config(raw,**args)

@pytest.mark.parametrize('env',['','env = {}\n','env = { RETAIN = "owner-value" }\n','[mcp_servers.integrity_client_memory.env]\nRETAIN = "owner-value"\n'])
def test_only_navigation_semantics_and_raw_insertion(env):
    raw=('[mcp_servers.other]\ncommand = "unrelated"\n\n'
         '[mcp_servers.integrity_client_memory]\ncommand = "python"\n'
         'args = ["/example/owner/broker.py", "--project", "тест"]\n'+env).encode()
    output=change(raw);before=tomllib.loads(raw.decode());after=tomllib.loads(output.decode())
    before['mcp_servers']['integrity_client_memory'].setdefault('env',{})['INTEGRITY_MCP_GENERATION_NAV']=GENERATION
    assert after==before
    assert b'command = "unrelated"' in output and 'тест'.encode() in output
    assert change(output,expected_sha256=hashlib.sha256(raw).hexdigest())==output
    with pytest.raises(NavigationError):
        change(output+b'\n# unrelated drift\n',expected_sha256=hashlib.sha256(raw).hexdigest())

def test_wrong_preimage_or_broker_never_accepted():
    raw=b'[mcp_servers.integrity_client_memory]\ncommand="python"\nargs=["/example/owner/broker.py"]\n'
    with pytest.raises(NavigationError):change(raw,expected_sha256='0'*64)
    with pytest.raises(NavigationError):change(raw,broker_script='/different/broker.py')
    with pytest.raises(NavigationError):change(raw,generation='invalid')

def test_pure_render_performs_no_file_or_process_operations(monkeypatch):
    import builtins,subprocess,socket
    def denied(*args,**kwargs):pytest.fail('renderer attempted an external action')
    monkeypatch.setattr(builtins,'open',denied)
    monkeypatch.setattr(subprocess,'Popen',denied)
    monkeypatch.setattr(socket,'socket',denied)
    raw=b'[mcp_servers.integrity_client_memory]\ncommand="python"\nargs=["/example/owner/broker.py"]\n'
    assert b'INTEGRITY_MCP_GENERATION_NAV' in change(raw)
