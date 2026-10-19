"""Library contract for the portal: M5 design O.3, items 36 onward.

36 pins what the passkey verifier (design D.3) relies on in ``cryptography`` 50.0.2 beyond what
its documentation promises. ``load_der_public_key`` returns whatever key type an SPKI names, as
readily as ours, so the verifier pins the type to the algorithm and checks RSA sizes itself; a
loaded key serializes back to the same SPKI, which is how a ``getPublicKey()`` key is compared
with the template's. DER is parsed strictly. ECDSA verification takes DER signatures only (as
WebAuthn's are) and accepts a high-S one, which is harmless with single-use challenges. PKCS#1
v1.5 and PSS are distinct schemes, an Ed25519 signature is exactly 64 bytes, and a point off the
curve never becomes a key.
"""

from __future__ import annotations

import warnings
from typing import Any

import pytest
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

from tests.fakes.authenticator import PublicKey, spki

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
