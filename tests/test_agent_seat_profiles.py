"""Known agent profiles include the additional seat clients."""
from integrity_guardian.agent_identity import KNOWN_PROFILES, declare_agent, verify_agent_identity


def test_optional_seat_id_does_not_change_an_unseated_identity():
    first = declare_agent(vendor="openai", product="codex", instance_id="instance-1")
    second = declare_agent(vendor="openai", product="codex", instance_id="instance-1")
    assert "seat_id" not in first
    assert first["agent_id"] == second["agent_id"]
    verify_agent_identity(first)


def test_additional_profiles_accept_a_seat_id():
    assert ("anthropic", "claude-code") in KNOWN_PROFILES
    assert ("google", "antigravity") in KNOWN_PROFILES
    assert ("openai", "chatgpt-web") in KNOWN_PROFILES
    seated = declare_agent(
        vendor="anthropic",
        product="claude-code",
        instance_id="instance-2",
        seat_id="alice",
    )
    assert seated["seat_id"] == "alice"
    verify_agent_identity(seated)
    plain = declare_agent(
        vendor="anthropic", product="claude-code", instance_id="instance-2"
    )
    assert seated["agent_id"] != plain["agent_id"]
