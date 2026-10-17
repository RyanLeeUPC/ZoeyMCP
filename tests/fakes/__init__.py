"""Fake providers for acceptance tests (design §8.1).

Each fake behaves like a real provider where it matters for ZoeyMCP, and runs as a real server
on loopback, so tests exercise real sockets, headers and streaming.
"""
