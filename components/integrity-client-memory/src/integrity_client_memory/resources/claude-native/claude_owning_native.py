# SPDX-License-Identifier: Apache-2.0
"""Own Claude CLI proof from its actual ancestor, ledger and full transcript.

No Codex Native context, random UUID, transcript UUID substitution, session
switch, admission, append, lease or target authority is supplied here.
"""

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
from contextlib import closing
import datetime, hashlib, json, os, re, sqlite3, subprocess, time
from pathlib import Path
SESSION = _integrity_value('claude_session_id')
ROOT = Path(_integrity_value('claude_state_home'))
OWNER = Path(_integrity_value('claude_owner_file'))
OWNER_PIN = _integrity_value('claude_owner_sha256')
LEDGER = Path(_integrity_value('claude_ledger'))
TRANSCRIPT = Path(_integrity_value('claude_transcript'))
PUBLISHER_SCRIPT = Path(_integrity_value('claude_publisher_script'))
PUBLISHER_SHA = _integrity_value('claude_publisher_sha256')
PUBLISHER_OWNER_SHA = _integrity_value('claude_publisher_owner_sha256')
PUBLISHER_EXE = Path(_integrity_value('claude_publisher_python'))
PUBLISHER_EXE_SHA = _integrity_value('claude_publisher_python_sha256')
UUID = re.compile('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\\Z')

class ClaudeOwnError(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise ClaudeOwnError(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def plain(path, maximum):
    need(path.is_absolute() and path.is_file(), 'claude_own_path_missing')
    for p in (path, *path.parents):
        need(not p.is_symlink() and (not getattr(p.stat(), 'st_file_attributes', 0) & 1024), 'claude_own_reparse_ancestry')
    need(0 < path.stat().st_size <= maximum, 'claude_own_file_bound')
    return path

def strict(raw):

    def pairs(values):
        out = {}
        for key, value in values:
            need(key not in out, 'claude_own_duplicate_json_key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ClaudeOwnError('claude_own_nonfinite_json')))

def ledger_head():
    plain(LEDGER, 32 * 1024 * 1024)
    with closing(sqlite3.connect(LEDGER.as_uri() + '?mode=ro', uri=True, timeout=3)) as db:
        task = db.execute('SELECT session_id FROM tasks WHERE id=?', (SESSION,)).fetchone()
        row = db.execute('SELECT id,prompt,status,created,updated FROM turns WHERE task_id=? ORDER BY created DESC LIMIT 1', (SESSION,)).fetchone()
    need(task and task[0] == SESSION and row, 'claude_own_session_not_enrolled')
    need(UUID.fullmatch(row[0]) and isinstance(row[1], str) and (0 < len(row[1].encode()) <= 262144) and (row[2] in {'starting', 'running', 'completed', 'failed', 'interrupted', 'unknown'}) and all((type(v) in (int, float) for v in row[3:])), 'claude_own_ledger_head_invalid')
    return {'id': row[0], 'prompt': row[1], 'status': row[2], 'created': row[3], 'updated': row[4]}

def last_input(raw, session):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 8 * 1024 * 1024 and raw.endswith(b'\n'), 'claude_own_transcript_incomplete')
    current = None
    for line in raw.splitlines():
        need(len(line) <= 2 * 1024 * 1024, 'claude_own_transcript_line_bound')
        item = strict(line)
        need(isinstance(item, dict), 'claude_own_transcript_invalid')
        if item.get('type') != 'user':
            continue
        need(item.get('sessionId') == session and item.get('isSidechain') is False, 'claude_own_transcript_subject_mismatch')
        message = item.get('message')
        need(isinstance(message, dict) and message.get('role') == 'user', 'claude_own_transcript_role_invalid')
        content = message.get('content')
        if isinstance(content, list) and content and all((isinstance(v, dict) and v.get('type') == 'tool_result' for v in content)):
            continue
        need(isinstance(content, str) and content and (not item.get('truncated')) and (not item.get('contentTruncated')), 'claude_own_input_incomplete')
        need(UUID.fullmatch(str(item.get('uuid', ''))), 'claude_own_item_uuid_invalid')
        current = item
    need(current is not None, 'claude_own_input_missing')
    return current

def validate_join(head, item, process, *, session, now):
    need(session == SESSION and process.get('session_id') == session and (process.get('verified_binary') is True) and (process.get('verified_publisher') is True) and (type(process.get('pid')) is int) and (process['pid'] > 0) and process.get('birth'), 'claude_own_live_ancestor_missing')
    need(head['status'] in {'starting', 'running'} and UUID.fullmatch(head['id']), 'claude_own_delivery_not_live')
    need(item['sessionId'] == session and item['message']['content'] == head['prompt'], 'claude_own_exact_input_mismatch')
    try:
        stamp = datetime.datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
        need(stamp.utcoffset() is not None, 'claude_own_input_time_invalid')
        timestamp = stamp.timestamp()
        started = datetime.datetime.fromisoformat(str(process['birth']).replace('Z', '+00:00')).timestamp()
    except (KeyError, TypeError, ValueError):
        raise ClaudeOwnError('claude_own_input_time_invalid') from None
    need(head['created'] <= started <= now and head['created'] <= timestamp <= now and (timestamp - head['created'] <= 300), 'claude_own_input_time_invalid')
    return {'protocol': 'integrity/claude-own-native/v1', 'native_thread_id': session, 'native_turn_id': head['id'], 'native_item_id': item['uuid'], 'input_sha256': sha(head['prompt'].encode()), 'input_bytes': len(head['prompt'].encode()), 'cli_pid': process['pid'], 'cli_birth': process['birth'], 'native_status': 'inProgress', 'source_kind': 'cli-delivery', 'sender_authority': 'not-proven', 'target_action_authority': 'not-evaluated', 'text': head['prompt'], 'truncated': False}

def live_ancestor(config, *, require_publisher=True):
    need(os.name == 'nt', 'claude_own_windows_required')
    script = '$ErrorActionPreference=\'Stop\';$nodeId=[int]$env:INTEGRITY_CLAUDE_OBSERVER_PID;$found=$null\nfor($i=0;$i -lt 16 -and $nodeId -gt 0;$i++){\n $p=Get-CimInstance Win32_Process -Filter (\'ProcessId=\'+$nodeId)\n if(-not $p){break}\n if($p.ExecutablePath -ceq $env:INTEGRITY_CLAUDE_EXPECTED_EXE){\n  $m=[regex]::Matches([string]$p.CommandLine,\'(?:^|\\s)--(?:resume|session-id)\\s+"?([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})"?(?=\\s|$)\')\n  if($m.Count -ne 1){throw \'claude_own_ancestor_session_missing\'}\n  if($env:INTEGRITY_CLAUDE_REQUIRE_PUBLISHER -eq \'0\'){\n    $found=@{pid=[int]$p.ProcessId;session_id=$m[0].Groups[1].Value;birth=$p.CreationDate.ToUniversalTime().ToString(\'o\')};break\n  }\n  $publisher=Get-CimInstance Win32_Process -Filter (\'ProcessId=\'+[int]$p.ParentProcessId)\n  $listeners=@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 49481 -State Listen -ErrorAction Stop)\n  $cmd=([string]$publisher.CommandLine).Replace(\'/\',\'\\\')\n  if(-not $publisher -or $publisher.ExecutablePath -cne $env:INTEGRITY_CLAUDE_PUBLISHER_EXE -or\n    -not $cmd.Contains($env:INTEGRITY_CLAUDE_PUBLISHER_SCRIPT) -or\n    -not $cmd.Contains(\'--claude-config\') -or -not $cmd.Contains($env:INTEGRITY_CLAUDE_OWNER_CONFIG) -or\n    @($listeners | Where-Object OwningProcess -eq $publisher.ProcessId).Count -ne 1){throw \'claude_own_publisher_mismatch\'}\n  $found=@{pid=[int]$p.ProcessId;session_id=$m[0].Groups[1].Value;birth=$p.CreationDate.ToUniversalTime().ToString(\'o\');\n    publisher_pid=[int]$publisher.ProcessId;publisher_birth=$publisher.CreationDate.ToUniversalTime().ToString(\'o\')};break\n }\n if($p.ParentProcessId -eq $nodeId){break};$nodeId=[int]$p.ParentProcessId\n}\nif(-not $found){throw \'claude_own_live_ancestor_missing\'}\n$found | ConvertTo-Json -Compress'
    binary = plain(Path(config['binary']), 512 * 1024 * 1024)
    need(file_sha(binary) == config['binary_sha256'], 'claude_own_binary_pin_changed')
    publisher_files = ((PUBLISHER_SCRIPT, PUBLISHER_SHA), (PUBLISHER_SCRIPT.with_name('claude_owner.py'), PUBLISHER_OWNER_SHA), (PUBLISHER_EXE, PUBLISHER_EXE_SHA)) if require_publisher else ()
    for path, pin in publisher_files:
        need(file_sha(plain(path, 4 * 1024 * 1024)) == pin, 'claude_own_publisher_pin_changed')
    env = {**os.environ, 'INTEGRITY_CLAUDE_OBSERVER_PID': str(os.getpid()), 'INTEGRITY_CLAUDE_EXPECTED_EXE': str(binary), 'INTEGRITY_CLAUDE_PUBLISHER_EXE': str(PUBLISHER_EXE), 'INTEGRITY_CLAUDE_PUBLISHER_SCRIPT': str(PUBLISHER_SCRIPT), 'INTEGRITY_CLAUDE_OWNER_CONFIG': str(OWNER), 'INTEGRITY_CLAUDE_REQUIRE_PUBLISHER': '1' if require_publisher else '0'}
    result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], env=env, capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    need(result.returncode == 0 and len(result.stdout) <= 4096, 'claude_own_live_ancestor_missing')
    value = strict(result.stdout)
    value['verified_binary'] = True
    value['verified_publisher'] = require_publisher
    return value

def pending_own(payload):
    """UserPromptSubmit precedes JSONL persistence; this is pending proof only."""
    need(isinstance(payload, dict) and payload.get('session_id') == SESSION and (payload.get('agent_id') in (None, '', SESSION)), 'claude_own_hook_subject_mismatch')
    need(payload.get('cwd') == _integrity_value('claude_project_root') and payload.get('transcript_path') == str(TRANSCRIPT), 'claude_own_hook_roots_mismatch')
    raw = plain(OWNER, 65536).read_bytes()
    need(sha(raw) == OWNER_PIN, 'claude_own_owner_pin_changed')
    config = strict(raw)
    process = live_ancestor(config)
    head = ledger_head()
    need(head['status'] in {'starting', 'running'} and process['session_id'] == SESSION, 'claude_own_delivery_not_live')
    value = payload.get('turn_id') or payload.get('turnId')
    need(value is None or value == head['id'], 'claude_own_supplied_native_mismatch')
    if payload.get('hook_event_name') == 'UserPromptSubmit':
        need(payload.get('prompt') == head['prompt'], 'claude_own_hook_prompt_mismatch')
    again = ledger_head()
    need(again['id'] == head['id'] and again['prompt'] == head['prompt'] and (again['status'] in {'starting', 'running'}), 'claude_own_changed_during_read')
    return {'id': head['id'], 'status': 'inProgress', 'pending_only': True, 'native_thread_id': SESSION, 'input_sha256': sha(head['prompt'].encode()), 'cli_pid': process['pid'], 'cli_birth': process['birth']}

def current_owning_turn(identity):
    need(identity == SESSION, 'claude_own_foreign_native_head')
    proof = observe_own({'session_id': identity, 'cwd': _integrity_value('claude_project_root'), 'transcript_path': str(TRANSCRIPT)})
    return {'id': proof['native_turn_id'], 'status': proof['native_status']}

def observe_own(payload):
    need(isinstance(payload, dict) and payload.get('session_id') == SESSION and (payload.get('agent_id') in (None, '', SESSION)), 'claude_own_hook_subject_mismatch')
    need(payload.get('cwd') == _integrity_value('claude_project_root') and payload.get('transcript_path') == str(TRANSCRIPT), 'claude_own_hook_roots_mismatch')
    raw = plain(OWNER, 65536).read_bytes()
    need(sha(raw) == OWNER_PIN, 'claude_own_owner_pin_changed')
    config = strict(raw)
    process = live_ancestor(config)
    head = ledger_head()
    item = last_input(plain(TRANSCRIPT, 8 * 1024 * 1024).read_bytes(), SESSION)
    proof = validate_join(head, item, process, session=SESSION, now=time.time())
    supplied = payload.get('turn_id') or payload.get('turnId')
    need(supplied is None or supplied == head['id'], 'claude_own_supplied_native_mismatch')
    if payload.get('hook_event_name') == 'UserPromptSubmit':
        need(payload.get('prompt') == head['prompt'], 'claude_own_hook_prompt_mismatch')
    head2 = ledger_head()
    process2 = live_ancestor(config)
    item2 = last_input(plain(TRANSCRIPT, 8 * 1024 * 1024).read_bytes(), SESSION)
    need(head2['id'] == head['id'] and head2['prompt'] == head['prompt'] and (head2['status'] in {'starting', 'running'}) and (process2 == process) and (item2 == item), 'claude_own_changed_during_read')
    return proof

def diagnostic():
    head = ledger_head()
    return {'native_thread_id': SESSION, 'latest_cli_native_turn_id': head['id'], 'status': head['status'], 'owning_live_proof': False, 'state_writes': 0, 'canonical_calls': 0}
if __name__ == "__main__":
    _integrity_require_config()

if __name__ == '__main__':
    print(json.dumps(diagnostic()))
