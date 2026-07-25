# Bulkhead demo

Run: **`./demo/run.sh`**

You'll watch a real MCP session: Bulkhead lists the mock upstream's tool, routes a
normal `mock__echo` call, then **blocks** a call that targets Bulkhead's own files
(self-protection, `-32602`). Finally it prints the `ledger.jsonl` the session
produced — one `allow` line, one `deny` line with operator detail. Hermetic: it
uses a throwaway `BULKHEAD_HOME` and never touches your real `~/.bulkhead`.
