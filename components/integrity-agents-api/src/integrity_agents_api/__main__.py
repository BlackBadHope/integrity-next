"""Offline only. No API key lookup, model call, deployment or automatic installation."""
import argparse

from .audit import demo
from .contracts import VERSION, encode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("capabilities", "demo"))
    args = parser.parse_args()
    result = demo() if args.operation == "demo" else {
        "schema": "integrity-agents-capabilities/v1", "version": VERSION,
        "provider": "openai-agents-api", "wire_protocol": "agents=v1",
        "default_environment": "none", "default_cli_offline": True,
        "automatic_retry": False, "automatic_merge": False, "canonical_writer": False,
        "live_acceptance": False, "independent_security_review": False,
        "trace_api_export_supported": False, "production_authority": False,
        "implemented": ["session_lifecycle", "paginated_recovery", "bounded_sse",
                        "durable_tool_results", "existing_sdk_gate", "privacy_export_gate",
                        "budget_reservations", "tool_policy_compiler", "observer_separation",
                        "handoff_candidate", "snapshot_audit"],
    }
    print(encode(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
