"""SDK contract tests (design K): what the gateway relies on in the MCP SDK.

They run against the pinned SDK and the fake upstream, and run again on every SDK bump. A
failure after a bump means the fallback for that piece is ours, decided then.
"""
