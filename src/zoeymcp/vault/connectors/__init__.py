"""The vault's connectors: routes the vault answers itself instead of forwarding (design §4.4).

M4 ships one, ``smtp``: send mail to fixed recipients over verified TLS (M4 design J). The pure
decisions live in :mod:`.mailmsg`, :mod:`.tunnel`, :mod:`.smtpflow` and :mod:`.sendjournal`;
:mod:`.smtp` does the I/O.
"""
