"""Read-only workbench bootstrap over the existing owner-enrolled hub.

Does not open a Seed file, infer access, dispatch execution, or persist transcripts.
The lab backend and all existing tools retain their own checks.
"""
import json

class WorkspaceBackend:
    def __init__(self, lab_backend, hub):
        self.lab_backend = lab_backend
        self.hub = hub

    def call(self, name, arguments):
        if name != "integrity_projects":
            return self.lab_backend.call(name, arguments)
        if arguments:
            raise ValueError("workspace bootstrap accepts no arguments")
        result = self.hub.call("codex_list_hosts", {})
        if not isinstance(result, dict) or result.get("isError"):
            raise ValueError("workspace host inventory unavailable")
        data = result.get("structuredContent")
        if not isinstance(data, dict):
            for item in result.get("content", []):
                if item.get("type") == "text":
                    try:
                        data = json.loads(item["text"])
                    except (ValueError, KeyError):
                        continue
                    if isinstance(data, dict):
                        break
        if not isinstance(data, dict) or not isinstance(data.get("hosts"), list):
            raise ValueError("workspace host inventory malformed")
        hosts = []
        seen = set()
        for row in data["hosts"]:
            if not isinstance(row, dict) or not isinstance(row.get("host_id"), str):
                raise ValueError("workspace host identity absent")
            host_id = row["host_id"]
            if not host_id or host_id in seen:
                raise ValueError("workspace host identity ambiguous")
            seen.add(host_id)
            hosts.append({k: row[k] for k in ("host_id", "label", "route", "availability")
                          if k in row})
        return {"mode": "workspace", "read_only": True, "hosts": hosts,
                "coverage": "Existing enrolled Codex hosts and explicitly enrolled cloud chats only",
                "canonical_completion_claim": False}

