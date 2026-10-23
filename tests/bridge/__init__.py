"""The bridge as a process (M7 design C, N.1): a real ``zoeymcp bridge`` around the stdio fake.

Linux only (its socket's peer check needs ``SO_PEERCRED``, its stop process groups), and kept
out of ``tests/unit``, mutmut's selection, which runs no process (BP-4).
"""
