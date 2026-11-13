# Design decisions

Short rationales for choices that are easy to change accidentally.

## Read-only SQL enforcement via a real parser

`execute_sql` accepts only a single `SELECT`/`WITH` statement. Validation uses
`sqlglot`'s BigQuery dialect rather than regex keyword matching. Regex passes
for comments and string literals are each blind to the other's syntax, which
allows bypasses such as a string literal that hides a comment boundary. A real
parser tokenizes both correctly and rejects more than one statement or any
DML/DDL node.

## Stateless streamable HTTP

The server runs with `stateless_http=True`. Stateful streamable HTTP keeps
session state in process memory, but Cloud Run autoscales across instances
without session affinity, so a client's follow-up request can land on an
instance that never saw the session. Stateless requests remove that
requirement. There is no server-side session store.

## One runtime identity, with per-call audit

All tool calls execute as one runtime service account. The security boundary is
not per-user IAM; it is:

1. An optional app-level OAuth/JWT gate that answers whether a caller can reach
   the service at all.
2. Per-call audit rows that record the verified caller email, tool, payloads,
   latency, and timestamp for after-the-fact accountability.

Finer-grained authorization would require a new mechanism, such as per-user
service-account impersonation or authorization inside tool handlers.

## OAuth authorization server in-process

FastMCP's `auth=` only verifies tokens on the MCP route. It does not publish
discovery metadata or authorization/token endpoints, which real MCP clients
need. The app implements the OAuth 2.1 authorization-code + PKCE surface itself
and proxies the browser-facing legs to Google.

The access token handed to MCP clients is the raw Google ID token. That keeps
one validation path: the same `JWTAuthProvider` checks the token on every
`/mcp` request. A bug in the handshake can block new logins but cannot weaken
the per-request gate.

## Bounded in-memory audit queue

Audit writes must not add latency to tool responses. The decorator appends to a
bounded deque and a background task flushes it to BigQuery. If the queue is
full, new rows are dropped and a stable `audit_queue_overflow_dropped` sentinel
is logged. A sustained non-zero rate means the bound is too small or the
flusher is falling behind.

Audit write failures are logged per row and dropped; they never fail a tool
call. `execute_sql` is never cached, because two identical queries are not
guaranteed to return the same data. Metadata tools use a process-lifetime cache
with no TTL or eviction, trading staleness for avoiding repeated API calls.

## Cost estimates are informational

`estimatedCostUsd` is derived from bytes processed at Google's published
on-demand rate. With a flat-rate reservation there is no true per-byte cost, so
the figure is a notional cost-attribution proxy, not an actual bill. It never
gates query execution.
