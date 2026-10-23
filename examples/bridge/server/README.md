# The example stdio server

`fetch-server` is the program `examples/bridge/` puts behind a bridge: a small stdio MCP server
written with the standard library alone, so its wheel builds without a download and is the whole
lock (`examples/bridge/lock.sh`). It speaks the legacy era, one JSON-RPC message per line.

| Tool | What it does |
| --- | --- |
| `echo` | answers its `text` |
| `fetch` | fetches an `https://` URL through the proxy variables the bridge sets and answers the status and the size of what came back, never the body |
| `wait` | writes `waiting <seconds> s` to stderr, then answers after `seconds` (at most 60): a call in flight that a stop must let finish |

It has no update check and sends no telemetry, so the recipe has no switch to turn off. Its tests
(`tests/`) run in place, as the example toolkits' do.
