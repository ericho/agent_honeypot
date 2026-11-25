-- Analysis queries. Run one with, for example:
--   npx wrangler d1 execute honeypot-logs --remote --command "<query>"
-- (use --local instead of --remote against the local dev database)

-- Overview: total requests, distinct IPs, first and last seen
SELECT COUNT(*) AS requests, COUNT(DISTINCT ip) AS ips, MIN(ts) AS first, MAX(ts) AS last FROM requests;

-- Top user agents
SELECT ua, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips, MIN(ts) AS first_seen
FROM requests GROUP BY ua ORDER BY n DESC LIMIT 50;

-- Who is sending traffic, by network
SELECT asn, as_org, country, COUNT(*) AS n, COUNT(DISTINCT ip) AS ips
FROM requests GROUP BY asn, as_org, country ORDER BY n DESC LIMIT 50;

-- First time each user agent appeared (compare with your registry publish time)
SELECT ua, MIN(ts) AS first_seen FROM requests GROUP BY ua ORDER BY first_seen;

-- Every JSON-RPC method seen
SELECT rpc_method, COUNT(*) AS n FROM requests
WHERE rpc_method IS NOT NULL GROUP BY rpc_method ORDER BY n DESC;

-- Paths probed (the Ziwei report describes a sweep of /mcp/* variants)
SELECT path, method, COUNT(*) AS n FROM requests GROUP BY path, method ORDER BY n DESC LIMIT 100;

-- Ziwei fingerprints from the Reddit comment
SELECT ts, ip, as_org, ua, path, rpc_method,
       json_extract(headers, '$.ziwei-beacon') AS beacon,
       json_extract(headers, '$.ziwei-card')   AS card
FROM requests
WHERE ua LIKE '%ziwei%' COLLATE NOCASE
   OR json_extract(headers, '$.ziwei-beacon') IS NOT NULL
ORDER BY ts;

-- Requests per minute for one user agent (burst pattern)
SELECT substr(ts, 1, 16) AS minute, COUNT(*) AS n
FROM requests WHERE ua LIKE '%ziwei%' COLLATE NOCASE
GROUP BY minute ORDER BY n DESC LIMIT 20;

-- A2A message/send payload text (export it; read it as untrusted data only)
SELECT id, ts, ip, json_extract(body, '$.params.message.parts[0].text') AS text
FROM requests WHERE rpc_method LIKE '%message/send%' ORDER BY ts LIMIT 5;

-- Retention: delete rows older than 30 days
DELETE FROM requests WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-30 days');
