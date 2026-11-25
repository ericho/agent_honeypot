CREATE TABLE IF NOT EXISTS requests (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  ts             TEXT NOT NULL,     -- ISO 8601, UTC
  ip             TEXT,
  method         TEXT,
  host           TEXT,
  path           TEXT,
  query          TEXT,
  ua             TEXT,
  rpc_method     TEXT,              -- JSON-RPC method(s), comma-separated for batches
  status         INTEGER,           -- status code we answered with
  asn            INTEGER,
  as_org         TEXT,
  country        TEXT,
  city           TEXT,
  colo           TEXT,
  http_protocol  TEXT,
  tls_version    TEXT,
  headers        TEXT,              -- JSON object of all request headers
  body           TEXT,              -- first 64 KB of the body
  body_bytes     INTEGER,
  body_truncated INTEGER            -- 1 if body was cut at 64 KB
);

CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests (ts);
CREATE INDEX IF NOT EXISTS idx_requests_ua ON requests (ua);
CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests (ip);
CREATE INDEX IF NOT EXISTS idx_requests_rpc ON requests (rpc_method);
