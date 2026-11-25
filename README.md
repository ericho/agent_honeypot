# agent_honeypot

A logging-only Cloudflare Worker for studying which AI agents, crawlers and bots
discover a newly listed MCP server, and what they send it. It replicates the
"Ziwei" observation from a Reddit thread on r/claude: an agent that pushes A2A
`message/send` payloads at MCP endpoints.

Nothing sits behind it. The Worker never executes, fetches or echoes what it
receives. It answers just enough of the MCP handshake (`initialize`,
`tools/list`, one harmless `server_time` tool) for clients to go past the
first request, and returns JSON-RPC "Method not found" for everything else,
including A2A methods.

## What gets logged

Every request is stored in a D1 (SQLite) table, `requests`:

- Time, IP, method, host, path, query string, user agent
- JSON-RPC method(s) parsed from the body
- Cloudflare network data: ASN, AS organization, country, city, data center
- All headers (as JSON) and the first 64 KB of the body

Writes are capped at 120 per IP per minute (best-effort, per Worker isolate).
Console logs are also kept for a few days in the Cloudflare dashboard.

## Endpoints

| Path | Response |
| --- | --- |
| `POST /mcp` | Minimal MCP over streamable HTTP |
| `GET /llms.txt` | Description of the endpoint |
| `GET /.well-known/agent.json`, `GET /mcp/.well-known/agent.json` | Minimal A2A agent card |
| `POST` anything else | JSON-RPC `-32601 Method not found` |
| `GET` anything else | 404 |

## Deploy

Requires Node.js 20+ and a Cloudflare account.

```powershell
npm install
npx wrangler login
npx wrangler d1 create honeypot-logs
```

Copy the `database_id` it prints into `wrangler.toml`, then:

```powershell
npm run db:init:remote
npm run deploy
```

Wrangler prints the URL, for example `https://agent-honeypot.<subdomain>.workers.dev`.
Check that it works:

```powershell
curl.exe -s -X POST https://YOUR-HOST/mcp -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}'
npx wrangler d1 execute honeypot-logs --remote --command "SELECT ts, ua, path FROM requests ORDER BY id DESC LIMIT 5"
```

## List it in the MCP Registry

This is how the honeypot gets found. Install `mcp-publisher` (see the
[registry docs](https://github.com/modelcontextprotocol/registry)), then:

```powershell
mcp-publisher init
```

Edit the generated `server.json`:

- `name`: `io.github.<your-github-user>/agent-honeypot`
- `description`: say honestly what it is, for example "Research logging
  endpoint for studying agent discovery. Logs all requests. No real service."
- `remotes`: `[{"type": "streamable-http", "url": "https://YOUR-HOST/mcp"}]`

```powershell
mcp-publisher login github
mcp-publisher publish
```

Write down the time you published, to compare against first-seen times.
The registry listing is public and shows your GitHub username.

## Watch and analyze

Live traffic:

```powershell
npm run tail
```

Stored traffic: see [queries.sql](queries.sql) for ready-made queries (top user
agents, networks, first-seen times, JSON-RPC methods, probed paths, the Ziwei
fingerprints, burst rate). Run one with:

```powershell
npx wrangler d1 execute honeypot-logs --remote --command "SELECT ua, COUNT(*) n FROM requests GROUP BY ua ORDER BY n DESC LIMIT 20"
```

### Ziwei fingerprints (from the Reddit report)

- User agent `Ziwei-Seat/1.0` or `ziwei-variant/1.0`
- Headers `Ziwei-Beacon: V1` and `Ziwei-Card: <GitHub-hosted agent.json URL>`
- `initialize`, then `GET /mcp/.well-known/agent.json`, then repeated
  `message/send` with a ~4,400-character Chinese letter in
  `params.message.parts[0].text`
- Sweeps of `/mcp/mcp`, `/mcp/a2a`, `/mcp/sse`, `/v1/mcp` and similar
- Tencent Cloud, Tencent Singapore or China Telecom IPv6 (`240e:`) addresses

## Safety

- Treat every logged body as untrusted. Read payloads yourself or in a chat
  with no tools. Never give them to an agent that has tools or memory, and
  never "accept delivery" or reply to the sender.
- Don't fetch URLs found in headers or bodies from a machine you care about.
- Logs contain IP addresses. Keep them private, delete them when you're done
  (a retention query is in `queries.sql`), and redact IPs before publishing.

## Local development

```powershell
npm install
npm run db:init:local
npm run dev
```

The Worker runs at `http://127.0.0.1:8787` with a local D1 database under
`.wrangler/` (git-ignored). Query it with `--local` instead of `--remote`.

## Shutting down

1. Deprecate or remove the registry entry.
2. `npx wrangler delete` to remove the Worker.
3. Export what you need, then `npx wrangler d1 delete honeypot-logs`.
