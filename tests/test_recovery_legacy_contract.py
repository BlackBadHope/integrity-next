"""Packaged-server compatibility with the currently installed 22-tool broker."""
import os,uuid
import pytest
from recovery_stand_fixture import Stand,digest
from integrity_guardian import memory_synapse_mcp as mcp


@pytest.mark.parametrize('retained',[True,False])
def test_installed_legacy_contract_complete_path(tmp_path,monkeypatch,retained):
    if os.name!='posix':pytest.skip('actual Linux Native custody stand')
    stand=Stand(tmp_path,monkeypatch)
    try:
        if not retained:
            filler=stand.facade();stand.initialize(filler)
            assert stand.fill_reservations(filler)>0
        f=stand.facade()
        replay=digest('legacy-reservation-'+uuid.uuid4().hex)
        tool_hash=mcp._tool_surface_sha256(mcp.tools(profile=mcp.PRE_NATIVE_INTENT_TOOL_CONTRACT_PROFILE))
        assert tool_hash=='sha256:ea7b2748a61581a5ee9f7a7e548c84f3bf6503d47a28ad7c4d2e525393fd15a9'
        # Preserve the old declaration exactly: no session-recovery opt-in.
        capabilities={mcp.BROKER_TOOL_SURFACE_CAPABILITY:{'protocol':mcp.BROKER_TOOL_SURFACE_PROTOCOL,
            'tools_surface_sha256':tool_hash},mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY:{
            'protocol':mcp.CONTEXT_ADMISSION_REPLAY_PROTOCOL,'request_identity_field':mcp.CONTEXT_ADMISSION_REPLAY_FIELD,
            'request_identity_format':'sha256/v1','reservation_id':replay},
            mcp.CONTEXT_REATTACH_CAPABILITY:{'protocol':mcp.CONTEXT_REATTACH_PROTOCOL}}
        initialized=stand.rpc(f,'initialize',{'protocolVersion':'2025-06-18',
            'clientInfo':{'name':'integrity-client-turn-broker','version':'1.6.0'},
            'capabilities':{'experimental':capabilities}})
        ack=initialized['capabilities']['experimental'][mcp.BROKER_TOOL_SURFACE_CAPABILITY]
        assert ack['accepted_tools_surface_sha256']==tool_hash
        listing=stand.rpc(f,'tools/list',{})
        assert mcp._tool_surface_sha256(listing['tools'])==tool_hash
        admitted=stand.admit(f,1,replay if retained else None)
        opened=stand.tool(f,'integrity_turn_memory_open',stand.args)
        event=stand.append(f,admitted,'legacy-compat')
        assert event['receipt']['action_outcome']=='confirmed-success'
        terminal=stand.close_turn(f,opened,event)
        assert terminal['receipt']['registration_id']==opened['receipt']['receipt_id']
        assert f.turn_memory.coverage()['counts']['registered']==1
        assert f.turn_memory.coverage()['counts']['terminal']==1
        assert stand.event_count()==2
    finally:
        stand.stop()
