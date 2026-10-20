"""Disposable actual MCP stdio server; synthetic producer, RAM-only Native keys."""
from pathlib import Path
import sys
import pytest
from recovery_stand_fixture import Stand
from integrity_guardian import memory_synapse_mcp as mcp

if __name__=='__main__':
    root=Path(sys.argv[1]).resolve()
    assert root.is_absolute() and not root.exists()
    root.mkdir(mode=0o700)
    patch=pytest.MonkeyPatch()
    stand=Stand(root,patch)
    try:
        if '--capacity-exhausted' in sys.argv[2:]:
            filler=stand.facade()
            stand.initialize(filler)
            assert stand.fill_reservations(filler)>0
        raise SystemExit(mcp.serve(stand.facade()))
    finally:
        stand.stop()
        patch.undo()
