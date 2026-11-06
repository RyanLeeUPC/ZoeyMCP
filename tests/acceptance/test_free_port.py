"""The harness's ports (D-256): ``free_port`` hands out ports the kernel never gives a socket on
its own, so no port-0 listener or outgoing connection can take one before the process it is for
binds it, and never the same port twice in a run.
"""

from __future__ import annotations

import socket
import sys

from .procs import PORTS_FROM, ephemeral_ports, free_port


def test_a_port_is_outside_the_ephemeral_range_and_not_handed_out_twice() -> None:
    ephemeral = ephemeral_ports()
    ports = [free_port() for _ in range(32)]
    assert len(set(ports)) == len(ports)
    assert all(PORTS_FROM <= port < 65536 and port not in ephemeral for port in ports)
    if sys.platform == "linux":  # read from the kernel there; elsewhere the default range
        with socket.socket() as taken:
            taken.bind(("127.0.0.1", 0))  # what the kernel gives is never one of ours
            assert taken.getsockname()[1] in ephemeral
    with socket.socket() as process:
        process.bind(("127.0.0.1", ports[-1]))  # each is free for its process to bind
