"""OAuth 2.0 for the vault: refresh, rotation, seed vs live and login (design §4.3).

``protocol`` and ``pkce`` are pure: no I/O, and clocks and randomness are passed in.
"""
