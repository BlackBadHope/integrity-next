"""Non-authoritative search hints bound to one broker-owned thread hash."""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path

PROTOCOL = 'integrity-topic-search-context/v1'
SHA = re.compile(r'sha256:[a-f0-9]{64}\Z')
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')
ADDRESS = re.compile(r'[a-z0-9-]{2,32}\Z')

def validate_hint(value):
    keys = {'protocol','address','topic','thread_sha256','registry_sha256','authority'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('retrieval hint shape invalid')
    if (value['protocol'] != PROTOCOL or value['authority'] != 'none'
            or not isinstance(value['address'], str) or not ADDRESS.fullmatch(value['address'])
            or not all(isinstance(value[k], str) and SHA.fullmatch(value[k]) for k in ('thread_sha256','registry_sha256'))
            or not isinstance(value['topic'], str) or not value['topic'].strip() or len(value['topic']) > 200
            or any(ord(c) < 32 for c in value['topic'])):
        raise ValueError('retrieval hint invalid')
    return dict(value)

def registry_hint_for_hash(thread_sha256, registry_path):
    """Read only the exact own subject. Never use CODEX_THREAD_ID or a parent."""
    if not isinstance(thread_sha256, str) or not SHA.fullmatch(thread_sha256):
        return None
    path = Path(registry_path)
    try:
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink() or ancestor.is_junction():
                return None
        if path.stat().st_size > 65536:
            return None
        raw = path.read_bytes()
        if len(raw) > 65536:
            return None
        root = json.loads(raw.decode('utf-8'))
        agents = root.get('agents')
        if not isinstance(agents, dict):
            return None
        matches = []
        for address, entry in agents.items():
            if (not isinstance(address, str) or not ADDRESS.fullmatch(address)
                    or not isinstance(entry, dict) or entry.get('harness') != 'codex'
                    or not isinstance(entry.get('thread'), str) or not UUID.fullmatch(entry['thread'])):
                continue
            identity = 'sha256:' + hashlib.sha256(entry['thread'].encode('utf-8')).hexdigest()
            if identity == thread_sha256:
                matches.append((address, entry))
        if len(matches) != 1:
            return None
        address, entry = matches[0]
        return validate_hint({'protocol':PROTOCOL,'address':address,'topic':entry.get('topic'),
            'thread_sha256':thread_sha256,'registry_sha256':'sha256:'+hashlib.sha256(raw).hexdigest(),'authority':'none'})
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
        return None
