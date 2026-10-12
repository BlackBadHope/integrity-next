# Installed Integrity source variants

This component retains code-only source variants of Guardian and Adapter SDK,
client and workstation memory packages, reusable client/server hooks, Seed
synchronization and Action Log. It is a source reference, not an installer,
release activation or a claim that the variants form one compatible runtime.
The main package keeps its own source and release contracts. Older package code
is retained in its named variant rather than replacing the main package.

`SOURCE-INVENTORY.json` binds the private retained bytes. Capture origins remain
outside the repository. The public projection sanitizes source text, excludes
this private inventory and carries its own complete export manifest.

Personal tunnel integrations, Hub/bridge/host-node adapters, native tunnel
executables, connection profiles, credentials, deployment pins, private task
bindings, runtime databases, prompts, memory events, logs and rollback state
are excluded from this update. Generic examples grant no access or authority
over any maintainer system.

For an independently configured developer connection, follow the
[developer setup below](#your-own-openai-developer-tunnel). Every developer creates
and owns their own organization, tunnel, credentials and access policy.

## Your own OpenAI developer tunnel

Configure a separate connection under your own account and access policy.
This repository contains no maintainer connection profile or tunnel identity.

1. In your own [Platform organization](https://host-82ce46d1b71f.example.invalid/settings/organization/tunnels),
   create a tunnel and associate only the intended organizations/workspaces.
   Creating it requires permission to manage tunnels; operating it requires
   permission to use them. ChatGPT workspace permissions are separate.
2. Download the official client through Platform settings. Keep your runtime key
   outside the repository in `CONTROL_PLANE_API_KEY`. Set `YOUR_TUNNEL_ID` to
   your new tunnel and `YOUR_MCP_COMMAND` to your own local server command.
3. Configure, inspect and run your separate development profile:

```sh
tunnel-client init --sample sample_mcp_stdio_local --profile developer-example --tunnel-id "$YOUR_TUNNEL_ID" --mcp-command "$YOUR_MCP_COMMAND"
tunnel-client doctor --profile developer-example --explain
tunnel-client run --profile developer-example
```

4. In ChatGPT Plugins, add a custom MCP connection using your tunnel and your
   server's authentication. First verify tool discovery and a harmless read-only
   call. Recheck organization/workspace access if discovery fails.

Keep the server private: the client connects outward over HTTPS. Avoid inbound
port forwarding, shared credentials and production data in development tests.

See [OpenAI's Secure MCP Tunnel documentation](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
for current installation, permissions, HTTP-server configuration and troubleshooting.
