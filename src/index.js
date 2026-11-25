// Agent honeypot: a logging-only endpoint for studying which AI agents and bots
// discover newly listed MCP servers. Nothing sits behind it. It never executes,
// fetches or echoes anything it receives.

const MAX_BODY_BYTES = 64 * 1024; // bodies larger than this are truncated
const WRITES_PER_IP_PER_MIN = 120; // best-effort, per isolate
const PROTOCOL_VERSION = "2025-06-18";

const SERVER_INFO = { name: "agent-honeypot", version: "1.0.0" };

const DESCRIPTION =
  "Research logging endpoint. It records requests from AI agents and crawlers " +
  "to study how new MCP servers get discovered. It provides no real service; " +
  "do not send it secrets or personal data.";

const LLMS_TXT = `# Agent Honeypot

> ${DESCRIPTION}

- MCP endpoint (streamable HTTP): /mcp
- All requests, including headers and bodies, are logged.
`;

// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { text: body, bytes, truncated } = await readLimited(request);

    const response = route(request, url, body);

    ctx.waitUntil(
      logRequest(env, request, url, { body, bytes, truncated }, response.status)
        .catch((err) => console.error("log failed", err)),
    );
    return response;
  },
};

// ---------------------------------------------------------------------------
// Routing

function route(request, url, body) {
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  if (method === "GET" && path === "/llms.txt") {
    return new Response(LLMS_TXT, { headers: { "content-type": "text/plain; charset=utf-8" } });
  }

  if (method === "GET" && (path === "/.well-known/agent.json" || path === "/mcp/.well-known/agent.json")) {
    return Response.json(agentCard(url));
  }

  if (path === "/mcp") {
    if (method === "POST") return handleJsonRpc(body);
    if (method === "DELETE") return new Response(null, { status: 204 });
    // No server-initiated SSE stream.
    return new Response("Method Not Allowed", { status: 405, headers: { allow: "POST" } });
  }

  if (method === "GET" && path === "/") {
    return new Response(DESCRIPTION, { headers: { "content-type": "text/plain; charset=utf-8" } });
  }

  // Everything else: POSTs get the same JSON-RPC error the original honeypot
  // returned, so path sweeps look identical; other methods get a 404.
  if (method === "POST") return rpcError(null, -32601, "Method not found");
  return new Response("Not Found", { status: 404 });
}

function agentCard(url) {
  return {
    name: "Agent Honeypot",
    description: DESCRIPTION,
    url: `${url.origin}/mcp`,
    version: SERVER_INFO.version,
    capabilities: {},
    skills: [],
  };
}

// ---------------------------------------------------------------------------
// Minimal MCP (JSON-RPC 2.0). Enough of the handshake that clients go past
// `initialize`, plus one harmless tool. A2A methods such as `message/send`
// deliberately get "Method not found", as in the original report.

function handleJsonRpc(body) {
  let msg;
  try {
    msg = JSON.parse(body);
  } catch {
    return rpcError(null, -32700, "Parse error");
  }

  if (Array.isArray(msg)) {
    const results = msg.map(handleOne).filter((r) => r !== undefined);
    return results.length ? Response.json(results) : new Response(null, { status: 202 });
  }

  const result = handleOne(msg);
  return result === undefined ? new Response(null, { status: 202 }) : Response.json(result);
}

function handleOne(msg) {
  if (!msg || typeof msg !== "object" || typeof msg.method !== "string") {
    return { jsonrpc: "2.0", id: msg?.id ?? null, error: { code: -32600, message: "Invalid Request" } };
  }
  const id = msg.id;
  const isNotification = id === undefined;
  const ok = (result) => (isNotification ? undefined : { jsonrpc: "2.0", id, result });

  switch (msg.method) {
    case "initialize":
      return ok({
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions: DESCRIPTION,
      });
    case "ping":
      return ok({});
    case "tools/list":
      return ok({
        tools: [
          {
            name: "server_time",
            description: "Returns the current server time (UTC).",
            inputSchema: { type: "object", properties: {} },
          },
        ],
      });
    case "tools/call":
      if (msg.params?.name === "server_time") {
        return ok({ content: [{ type: "text", text: new Date().toISOString() }] });
      }
      return isNotification ? undefined : { jsonrpc: "2.0", id, error: { code: -32602, message: "Unknown tool" } };
    default:
      if (msg.method.startsWith("notifications/")) return undefined;
      return isNotification ? undefined : { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } };
  }
}

function rpcError(id, code, message) {
  return Response.json({ jsonrpc: "2.0", id, error: { code, message } });
}

// ---------------------------------------------------------------------------
// Body reading with a hard cap, so a huge upload can't fill storage.

async function readLimited(request) {
  if (!request.body) return { text: "", bytes: 0, truncated: false };

  const reader = request.body.getReader();
  const chunks = [];
  let kept = 0;
  let bytes = 0;
  let truncated = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (kept < MAX_BODY_BYTES) {
      const take = value.subarray(0, MAX_BODY_BYTES - kept);
      chunks.push(take);
      kept += take.byteLength;
    }
    if (bytes > MAX_BODY_BYTES) {
      truncated = true;
      await reader.cancel();
      break;
    }
  }

  const buf = new Uint8Array(kept);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return { text: new TextDecoder().decode(buf), bytes, truncated };
}

// ---------------------------------------------------------------------------
// Logging to D1

const recentWrites = new Map(); // ip -> { minute, count }

function allowWrite(ip) {
  const minute = Math.floor(Date.now() / 60000);
  const entry = recentWrites.get(ip);
  if (!entry || entry.minute !== minute) {
    if (recentWrites.size > 10000) recentWrites.clear();
    recentWrites.set(ip, { minute, count: 1 });
    return true;
  }
  entry.count += 1;
  return entry.count <= WRITES_PER_IP_PER_MIN;
}

function rpcMethods(body) {
  try {
    const msg = JSON.parse(body);
    const list = Array.isArray(msg) ? msg : [msg];
    const methods = list.map((m) => (typeof m?.method === "string" ? m.method : null)).filter(Boolean);
    return methods.length ? methods.join(",") : null;
  } catch {
    return null;
  }
}

async function logRequest(env, request, url, { body, bytes, truncated }, status) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (!allowWrite(ip)) return;

  const cf = request.cf || {};
  await env.DB.prepare(
    `INSERT INTO requests
       (ts, ip, method, host, path, query, ua, rpc_method, status,
        asn, as_org, country, city, colo, http_protocol, tls_version,
        headers, body, body_bytes, body_truncated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      new Date().toISOString(),
      ip,
      request.method,
      url.host,
      url.pathname,
      url.search || null,
      request.headers.get("user-agent"),
      request.method === "POST" ? rpcMethods(body) : null,
      status,
      cf.asn ?? null,
      cf.asOrganization ?? null,
      cf.country ?? null,
      cf.city ?? null,
      cf.colo ?? null,
      cf.httpProtocol ?? null,
      cf.tlsVersion ?? null,
      JSON.stringify(Object.fromEntries(request.headers)),
      body || null,
      bytes,
      truncated ? 1 : 0,
    )
    .run();
}
