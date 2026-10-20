"""Library contract for the portal: M5 design O.3, items 36 onward.

36 pins what the passkey verifier (design D.3) relies on in ``cryptography`` 50.0.2 beyond what
its documentation promises. ``load_der_public_key`` returns whatever key type an SPKI names, as
readily as ours, so the verifier pins the type to the algorithm and checks RSA sizes itself; a
loaded key serializes back to the same SPKI, which is how a ``getPublicKey()`` key is compared
with the template's. DER is parsed strictly. ECDSA verification takes DER signatures only (as
WebAuthn's are) and accepts a high-S one, which is harmless with single-use challenges. PKCS#1
v1.5 and PSS are distinct schemes, an Ed25519 signature is exactly 64 bytes, and a point off the
curve never becomes a key.

37 and 39 pin what admission (design C.2) relies on in h11 0.16, uvicorn 0.54 and Starlette 1.7.
A request with two ``Host`` headers never reaches the app: h11 refuses it and uvicorn answers its
own plain-text 400 (design 0.5), so admission's "exactly one Host" is a pure case. One ``Host``
reaches ``scope["headers"]`` as sent, whatever the request target says, and an absolute-form
target becomes the path, which no portal route has. Starlette's ``request.cookies`` keeps one of
two cookies of one name, so admission reads every value from the raw ``Cookie`` headers.

38 and 40 pin what the portal's listener relies on in uvicorn 0.54 (design B.3). uvicorn's own
answers (a request it can't parse, a head over the cap) are plain text with none of the portal's
headers, so nothing a browser renders comes from them. Its keep-alive timer starts only after a
response and dies at the next byte, so it can't bound a trickled head; ``PortalH11`` keeps a
deadline of its own and a connection cap, given to uvicorn as ``Config(http=<class>)``.

41 pins why the vault binds its TCP sockets itself (design B.3, D17). uvicorn 0.54's
``Server.startup`` calls ``sys.exit`` when it can't bind a host and port, which would end the
vault inside its servers' gather with no line of its own. Given sockets already bound, it listens
on them and serves them, and closes them when it stops.

42's offline half checks what a unit test can: the dev venv is an editable install, so it can't
see a wheel, but the build config and the ignore files show the static files aren't dropped. The
image smoke checks the installed package (from step 17a).
"""

from __future__ import annotations

import asyncio
import fnmatch
import socket
import threading
import time
import tomllib
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import h11
import pytest
import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
    utils,
    x448,
    x25519,
)
from cryptography.utils import CryptographyDeprecationWarning
from starlette.requests import Request
from starlette.types import Receive, Scope, Send
from uvicorn.config import STARTUP_FAILURE
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

from tests.fakes.authenticator import PublicKey, spki
from zoeymcp.portal.app import PortalApp, load_static
from zoeymcp.portal.limits import ADMIN_CONNECTIONS
from zoeymcp.portal.routes import STATIC
from zoeymcp.portal.server import HEAD_LIMIT, portal_protocol

MESSAGE = b"authenticator data and the client data hash"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ES256 = ec.ECDSA(hashes.SHA256())


def der(key: Any) -> bytes:
    """The SPKI DER of any public key."""
    encoded: bytes = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return encoded


# --- 36. what the passkey verifier relies on in cryptography ------------------------------------


def test_the_spki_loader_returns_every_type_it_knows() -> None:
    ours = (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, rsa.RSAPublicKey)
    others = [
        (dsa.generate_private_key(1024).public_key(), dsa.DSAPublicKey),  # noqa: S505 (quick)
        (x25519.X25519PrivateKey.generate().public_key(), x25519.X25519PublicKey),
        (x448.X448PrivateKey.generate().public_key(), x448.X448PublicKey),
        (ed448.Ed448PrivateKey.generate().public_key(), ed448.Ed448PublicKey),
    ]
    for key, expected in others:
        loaded = serialization.load_der_public_key(der(key))
        assert isinstance(loaded, expected)
        assert not isinstance(loaded, ours)
    # A P-384 key loads as an EC key like ours: only its curve tells it from ES256's.
    p384 = serialization.load_der_public_key(
        der(ec.generate_private_key(ec.SECP384R1()).public_key())
    )
    assert isinstance(p384, ec.EllipticCurvePublicKey)
    assert isinstance(p384.curve, ec.SECP384R1)
    # RSA 1024 and e = 3 load as RSA keys: the size and exponent checks are the verifier's.
    weak = rsa.generate_private_key(65537, 1024)  # noqa: S505 (the weak key is the point)
    short = serialization.load_der_public_key(der(weak.public_key()))
    assert isinstance(short, rsa.RSAPublicKey)
    assert short.key_size == 1024
    small_e = serialization.load_der_public_key(der(rsa.generate_private_key(3, 2048).public_key()))
    assert isinstance(small_e, rsa.RSAPublicKey)
    assert small_e.public_numbers().e == 3


def test_the_spki_loader_returns_dh_keys_with_a_deprecation_warning() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        from cryptography.hazmat.primitives.asymmetric import dh

        parameters = dh.generate_parameters(generator=2, key_size=512)
        encoded = der(parameters.generate_private_key().public_key())
        dh_type = dh.DHPublicKey
    with pytest.warns(CryptographyDeprecationWarning):
        loaded = serialization.load_der_public_key(encoded)
    assert isinstance(loaded, dh_type)


def our_key(alg: str) -> PublicKey:
    if alg == "es256":
        return ec.generate_private_key(ec.SECP256R1()).public_key()
    if alg == "eddsa":
        return ed25519.Ed25519PrivateKey.generate().public_key()
    return rsa.generate_private_key(65537, 2048).public_key()


@pytest.mark.parametrize("alg", ["es256", "eddsa", "rs256"])
def test_spki_der_is_strict_and_round_trips(alg: str) -> None:
    encoded = der(our_key(alg))
    assert spki(serialization.load_der_public_key(encoded)) == encoded  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="extra data"):
        serialization.load_der_public_key(encoded + b"\x00")
    with pytest.raises(ValueError, match="short data"):
        serialization.load_der_public_key(encoded[:-1])


def test_spki_with_unused_bits_in_the_key_is_refused() -> None:
    encoded = der(ec.generate_private_key(ec.SECP256R1()).public_key())
    bit_string = encoded.index(bytes.fromhex("03420004"))
    tampered = bytearray(encoded)
    tampered[bit_string + 2] = 0x01  # the BIT STRING's unused-bits count
    # DER refuses it when the key's last bit is set, 50.0's new check when it isn't.
    with pytest.raises(ValueError, match=r"invalid value|Invalid key"):
        serialization.load_der_public_key(bytes(tampered))


def test_a_compressed_point_spki_loads_and_serializes_uncompressed() -> None:
    public = ec.generate_private_key(ec.SECP256R1()).public_key()
    point = public.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    # cryptography only writes uncompressed SPKI, so the compressed one is built by hand.
    prefix = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
    compressed = prefix + point
    loaded = serialization.load_der_public_key(compressed)
    assert spki(loaded) == der(public) != compressed  # type: ignore[arg-type]


def test_ecdsa_verification_takes_der_only() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(MESSAGE, ES256)
    key.public_key().verify(signature, MESSAGE, ES256)
    r, s = utils.decode_dss_signature(signature)
    with pytest.raises(InvalidSignature):  # raw r || s, as WebCrypto would give
        key.public_key().verify(r.to_bytes(32, "big") + s.to_bytes(32, "big"), MESSAGE, ES256)
    with pytest.raises(InvalidSignature):
        key.public_key().verify(signature + b"\x00", MESSAGE, ES256)


def test_a_high_s_ecdsa_signature_is_accepted() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    r, s = utils.decode_dss_signature(key.sign(MESSAGE, ES256))
    high_s = utils.encode_dss_signature(r, P256_ORDER - s)
    key.public_key().verify(high_s, MESSAGE, ES256)


def test_pkcs1v15_and_pss_do_not_cross_verify() -> None:
    key = rsa.generate_private_key(65537, 2048)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    v15 = key.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256())
    key.public_key().verify(v15, MESSAGE, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignature):
        key.public_key().verify(v15, MESSAGE, pss, hashes.SHA256())
    with pytest.raises(InvalidSignature):
        key.public_key().verify(
            key.sign(MESSAGE, pss, hashes.SHA256()), MESSAGE, padding.PKCS1v15(), hashes.SHA256()
        )


def test_an_ed25519_signature_is_exactly_64_bytes() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    signature = key.sign(MESSAGE)
    assert len(signature) == 64
    key.public_key().verify(signature, MESSAGE)
    for wrong in (signature + b"\x00", signature[:-1]):
        with pytest.raises(InvalidSignature):
            key.public_key().verify(wrong, MESSAGE)


def test_a_point_off_the_curve_is_refused() -> None:
    with pytest.raises(ValueError, match="not on the curve"):
        ec.EllipticCurvePublicNumbers(1, 1, ec.SECP256R1()).public_key()
    off_curve = b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
    with pytest.raises(ValueError, match="Invalid EC key"):
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), off_curve)
    with pytest.raises(ValueError, match="32 bytes long"):
        ed25519.Ed25519PublicKey.from_public_bytes(b"\x00" * 31)


# --- 37. two Host headers never reach the app; one reaches it as sent -----------------------------

STARTUP_TIMEOUT = 10.0
CRLF = bytes((13, 10))


class _Recorder:
    """An ASGI app that keeps each scope and answers 200."""

    def __init__(self) -> None:
        self.scopes: list[Scope] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.scopes.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


class _ThreadServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        """Signals belong to the test runner."""


@contextmanager
def _h11_server(app: _Recorder, sockets: list[socket.socket] | None = None) -> Iterator[int]:
    """uvicorn with its h11 protocol, as the portal runs it, on a loopback port (or on
    ``sockets``, which it then binds no socket of its own for)."""
    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, http="h11", lifespan="off", log_level="critical"
    )
    server = _ThreadServer(config)
    thread = threading.Thread(
        target=lambda: asyncio.run(server.serve(sockets=sockets)), daemon=True
    )
    thread.start()
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while not server.started:
        assert thread.is_alive()
        assert time.monotonic() < deadline
        time.sleep(0.01)
    try:
        yield server.servers[0].sockets[0].getsockname()[1]
    finally:
        server.should_exit = True
        thread.join(STARTUP_TIMEOUT)


def _exchange(port: int, raw: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=STARTUP_TIMEOUT) as connection:
        connection.sendall(raw)
        connection.shutdown(socket.SHUT_WR)
        answer = b""
        while chunk := connection.recv(65536):
            answer += chunk
    return answer


def _head(*lines: bytes) -> bytes:
    """A request head: the lines, each ended by CRLF, then the empty line."""
    return b"".join(line + CRLF for line in (*lines, b""))


def test_h11_refuses_two_host_headers() -> None:
    connection = h11.Connection(h11.SERVER)
    connection.receive_data(
        _head(b"GET / HTTP/1.1", b"Host: localhost:8081", b"Host: evil.example")
    )
    with pytest.raises(h11.RemoteProtocolError, match="multiple Host"):
        connection.next_event()


def test_uvicorn_answers_two_host_headers_itself() -> None:
    app = _Recorder()
    with _h11_server(app) as port:
        answer = _exchange(
            port, _head(b"GET / HTTP/1.1", b"Host: localhost:8081", b"Host: localhost:8081")
        )
    head, _, body = answer.partition(CRLF + CRLF)
    lines = head.split(CRLF)
    assert lines[0] == b"HTTP/1.1 400 Bad Request"
    assert b"content-type: text/plain; charset=utf-8" in lines
    assert body == b"Invalid HTTP request received."
    assert app.scopes == []


@pytest.mark.parametrize(
    ("target", "path"),
    [
        (b"/api/session?x=1", "/api/session"),
        (b"http://evil.example/api/session", "http://evil.example/api/session"),
    ],
)
def test_one_host_reaches_the_app_as_sent(target: bytes, path: str) -> None:
    app = _Recorder()
    with _h11_server(app) as port:
        answer = _exchange(
            port,
            _head(b"GET " + target + b" HTTP/1.1", b"Host: LocalHost:8081", b"Connection: close"),
        )
    assert answer.startswith(b"HTTP/1.1 200 OK")
    [scope] = app.scopes
    assert scope["headers"] == [(b"host", b"LocalHost:8081"), (b"connection", b"close")]
    assert scope["path"] == path


# --- 39. a parsed cookie mapping keeps one cookie of a name ---------------------------------------


def test_starlette_keeps_one_of_two_cookies_of_a_name() -> None:
    headers = [(b"cookie", b"zoeymcp-8081-session=planted; zoeymcp-8081-session=ours")]
    request = Request({"type": "http", "headers": headers})
    assert request.cookies == {"zoeymcp-8081-session": "ours"}
    # Across two Cookie headers, the last one wins too.
    two = [(b"cookie", b"zoeymcp-8081-session=ours"), (b"cookie", b"zoeymcp-8081-session=planted")]
    assert Request({"type": "http", "headers": two}).cookies == {"zoeymcp-8081-session": "planted"}


# --- 41. a bind failure exits the process; a socket bound beforehand is served ------------------


def test_uvicorn_exits_when_it_cant_bind() -> None:
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        port = occupied.getsockname()[1]
        config = uvicorn.Config(
            _Recorder(), host="127.0.0.1", port=port, lifespan="off", log_level="critical"
        )
        with pytest.raises(SystemExit) as exited:
            asyncio.run(_ThreadServer(config).serve())
    assert exited.value.code == STARTUP_FAILURE


def test_uvicorn_serves_a_socket_bound_beforehand() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))  # bound only: uvicorn's create_server listens
    app = _Recorder()
    with _h11_server(app, [sock]) as port:
        assert port == sock.getsockname()[1]
        answer = _exchange(port, _head(b"GET / HTTP/1.1", b"Host: localhost", b"Connection: close"))
    assert answer.startswith(b"HTTP/1.1 200 OK")
    assert len(app.scopes) == 1
    assert sock.fileno() == -1  # closed when the server stopped


# --- 38. uvicorn's own answers carry none of the portal's headers ---------------------------------


@contextmanager
def _portal_server(app: Any, *, header_deadline: float = 10.0) -> Iterator[int]:
    """uvicorn with ``PortalH11``, configured as the vault configures the portal's listener."""
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        http=portal_protocol(header_deadline=header_deadline),
        h11_max_incomplete_event_size=HEAD_LIMIT,
        ws="none",
        lifespan="off",
        log_level="critical",
        server_header=False,
        date_header=False,
    )
    server = _ThreadServer(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while not server.started:
        assert thread.is_alive()
        assert time.monotonic() < deadline
        time.sleep(0.01)
    try:
        yield server.servers[0].sockets[0].getsockname()[1]
    finally:
        server.should_exit = True
        thread.join(STARTUP_TIMEOUT)


def _shell() -> PortalApp:
    return PortalApp(["http://localhost:8081"], static=load_static())


def _assert_uvicorns_400(answer: bytes) -> None:
    head, _, body = answer.partition(CRLF + CRLF)
    lines = head.lower().split(CRLF)
    assert lines[0] == b"http/1.1 400 bad request"
    assert b"content-type: text/plain; charset=utf-8" in lines
    assert body == b"Invalid HTTP request received."
    assert not [line for line in lines if line.startswith((b"content-security", b"x-zoeymcp"))]


def test_uvicorns_own_answers_are_plain_text_without_the_portals_headers() -> None:
    with _portal_server(_shell()) as port:
        _assert_uvicorns_400(_exchange(port, b"garbage" + CRLF + CRLF))


def test_a_head_over_the_cap_is_refused_while_it_is_still_coming() -> None:
    """h11 checks ``max_incomplete_event_size`` only while a head is incomplete: a head over it
    is refused once its buffered part passes the cap. (One that arrives whole in a single read
    is parsed whatever its size, up to the transport's read size: the cap bounds what a slow
    head can make the vault hold, not every head.)"""
    pad = b"X-Pad: " + b"a" * (HEAD_LIMIT + 1)
    app = _Recorder()
    with (
        _portal_server(app) as port,
        socket.create_connection(("127.0.0.1", port), timeout=STARTUP_TIMEOUT) as sock,
    ):
        sock.sendall(b"GET / HTTP/1.1" + CRLF + b"Host: localhost:8081" + CRLF)
        time.sleep(0.1)
        sock.sendall(pad)  # still no end to the head; nothing more is sent
        answer = b""
        while chunk := sock.recv(65536):
            answer += chunk
    assert app.scopes == []
    _assert_uvicorns_400(answer)


# --- 40. the keep-alive timer can't carry a head deadline; PortalH11's own timer does ----------


class _Transport:
    """Enough of an asyncio transport for uvicorn's protocol to run on."""

    def __init__(self) -> None:
        self.written = b""
        self.closing = False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return {"peername": ("127.0.0.1", 50000), "sockname": ("127.0.0.1", 8081)}.get(name)

    def write(self, data: bytes) -> None:
        self.written += data

    def is_closing(self) -> bool:
        return self.closing

    def close(self) -> None:
        self.closing = True

    def pause_reading(self) -> None:
        pass

    def resume_reading(self) -> None:
        pass


def test_uvicorns_keep_alive_timer_starts_after_a_response_and_dies_at_any_byte() -> None:
    async def main() -> list[bool]:
        config = uvicorn.Config(_Recorder(), http="h11", lifespan="off", log_level="critical")
        config.load()
        protocol = H11Protocol(config, ServerState(), {}, _loop=asyncio.get_running_loop())
        transport = _Transport()
        protocol.connection_made(transport)  # type: ignore[arg-type]
        armed_at_start = protocol.timeout_keep_alive_task is not None
        protocol.data_received(_head(b"GET / HTTP/1.1", b"Host: localhost:8081"))
        for _ in range(100):
            if protocol.timeout_keep_alive_task is not None:
                break
            await asyncio.sleep(0.01)
        armed_after_response = protocol.timeout_keep_alive_task is not None
        protocol.data_received(b"G")  # one byte of a next head, nowhere near a request
        armed_after_a_byte = protocol.timeout_keep_alive_task is not None
        protocol.connection_lost(None)
        return [armed_at_start, armed_after_response, armed_after_a_byte]

    assert asyncio.run(main()) == [False, True, False]


def test_a_protocol_subclass_is_taken_as_the_http_class() -> None:
    protocol = portal_protocol()
    config = uvicorn.Config(_Recorder(), http=protocol, lifespan="off")
    config.load()
    assert config.http_protocol_class is protocol
    assert issubclass(protocol, H11Protocol)
    # Each listener has its own table.
    assert protocol.listener.connections is not portal_protocol().listener.connections


SHORT = 0.5


def _closed(sock: socket.socket, within: float) -> bool:
    sock.settimeout(within)
    try:
        while sock.recv(65536):
            pass
    except TimeoutError:
        return False
    except OSError:
        return True
    return True


def _trickle(sock: socket.socket, data: bytes) -> bool:
    """A byte every 20 ms; False if the server closed first."""
    for index in range(len(data)):
        try:
            sock.sendall(data[index : index + 1])
        except OSError:
            return False
        if _closed(sock, 0.02):
            return False
    return True


def test_portal_h11_closes_a_silent_connection_at_the_deadline() -> None:
    with (
        _portal_server(_Recorder(), header_deadline=SHORT) as port,
        socket.create_connection(("127.0.0.1", port)) as sock,
    ):
        assert not _closed(sock, SHORT / 2)
        assert _closed(sock, SHORT + 2)


def test_portal_h11_closes_a_trickled_first_head_at_the_deadline() -> None:
    app = _Recorder()
    with (
        _portal_server(app, header_deadline=SHORT) as port,
        socket.create_connection(("127.0.0.1", port)) as sock,
    ):
        started = time.monotonic()
        assert not _trickle(sock, _head(b"GET / HTTP/1.1", b"X-Pad: " + b"a" * 300))
        assert SHORT - 0.1 <= time.monotonic() - started < SHORT + 2
    assert app.scopes == []


def test_portal_h11_closes_a_second_head_trickled_after_a_response() -> None:
    app = _Recorder()
    with (
        _portal_server(app, header_deadline=SHORT) as port,
        socket.create_connection(("127.0.0.1", port)) as sock,
    ):
        sock.sendall(_head(b"GET / HTTP/1.1", b"Host: localhost"))
        answer = b""
        while not answer.endswith(b"0" + CRLF + CRLF):  # the recorder's answer is chunked
            answer += sock.recv(65536)
        started = time.monotonic()
        assert not _trickle(sock, _head(b"GET / HTTP/1.1", b"X-Pad: " + b"a" * 300))
        # Well before uvicorn's own keep-alive of 5 s, which every byte put off.
        assert time.monotonic() - started < SHORT + 2
    assert len(app.scopes) == 1


def test_portal_h11_evicts_the_longest_idle_and_lets_an_operator_in() -> None:
    with _portal_server(_Recorder(), header_deadline=60) as port:
        idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(ADMIN_CONNECTIONS)]
        try:
            time.sleep(0.2)  # every one accepted, in order
            answer = _exchange(port, _head(b"GET / HTTP/1.1", b"Host: localhost"))
            assert answer.startswith(b"HTTP/1.1 200 OK")
            assert _closed(idle[0], 5)
            assert not _closed(idle[1], 0.2)
            # The operator's connection closed with its answer, so one more fits; the next
            # evicts the longest idle again.
            with (
                socket.create_connection(("127.0.0.1", port)) as refill,
                socket.create_connection(("127.0.0.1", port)) as extra,
            ):
                assert _closed(idle[1], 5)
                assert not _closed(idle[2], 0.2)
                assert not _closed(refill, 0.2)
                assert not _closed(extra, 0.2)
        finally:
            for sock in idle:
                sock.close()


# --- 42 (offline half). The static files ship ---------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = ROOT / "src" / "zoeymcp" / "portal" / "static"


def test_the_wheel_takes_the_whole_package() -> None:
    """hatchling ships every file under the package that git doesn't ignore: no exclude, no
    include list, no artifacts filter can drop the static files."""
    with (ROOT / "pyproject.toml").open("rb") as file:
        build = tomllib.load(file)["tool"]["hatch"]["build"]
    assert build == {"targets": {"wheel": {"packages": ["src/zoeymcp"]}}}


@pytest.mark.parametrize("ignore", [".gitignore", ".dockerignore"])
def test_no_ignore_file_drops_the_static_files(ignore: str) -> None:
    patterns = [
        line.strip()
        for line in (ROOT / ignore).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    for file in STATIC.values():
        relative = (STATIC_DIR / file.name).relative_to(ROOT).as_posix()
        parts = relative.split("/")
        # Every pattern against the whole path, each of its prefixes and each component, so a
        # gitignore pattern (any depth) and a dockerignore one (from the root) are both covered.
        candidates = {relative, *parts, *("/".join(parts[:n]) for n in range(1, len(parts)))}
        matched = [p for p in patterns if any(fnmatch.fnmatch(c, p.strip("/")) for c in candidates)]
        assert matched == [], (relative, matched)


def test_every_static_file_is_in_the_source_tree() -> None:
    assert sorted(path.name for path in STATIC_DIR.iterdir()) == sorted(
        file.name for file in STATIC.values()
    )
