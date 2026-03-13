# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import datetime
import pathlib
import ssl
import subprocess
import typing as t

import pytest

from ansible_collections.microsoft.ad.plugins.plugin_utils._ldap._certificate import (
    get_tls_server_end_point_data,
    load_client_certificate,
    load_trust_certificate,
)

try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import ed25519

except Exception:
    pytest.skip("Cannot run certificate tests without cryptography")


class TlsServer(t.NamedTuple):
    ca: "x509.Certificate"
    ca_key: "rsa.RSAPrivateKey"
    name: str
    context: ssl.SSLContext


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory: pytest.TempPathFactory) -> TlsServer:
    cn = "microsoft.ad.test"
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "microsoft.ad")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_key_usage, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        ca_cert.public_key())  # type: ignore[arg-type]

    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(ca_aki, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    tmpdir = tmp_path_factory.mktemp("cert")
    cert_path = tmpdir / "microsoft.ad.test.pem"
    try:
        with open(cert_path, mode="wb") as fd:
            fd.write(cert_pem)
            fd.write(key_pem)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.VerifyMode.CERT_OPTIONAL
        context.load_cert_chain(str(cert_path))
        context.load_verify_locations(cadata=ca_cert.public_bytes(serialization.Encoding.PEM).decode())

    finally:
        cert_path.unlink(missing_ok=True)

    return TlsServer(ca_cert, ca_key, cn, context)


@pytest.fixture(scope="module")
def client_certificate(tls_server: TlsServer) -> t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"]:
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        tls_server.ca.public_key())  # type: ignore[arg-type]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "client-auth")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(tls_server.ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(
                        x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                        b"\x0c\x0d\x62\x6f\x62\x40\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74",
                    ),
                ]
            ),
            False,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .add_extension(ca_aki, critical=False)
        .sign(tls_server.ca_key, hashes.SHA256())
    )

    return cert, key


def test_get_tls_binding_data_no_data() -> None:
    assert get_tls_server_end_point_data(None) is None


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256", "sha384", "sha512"])
def test_get_tls_binding_data_rsa(
    algorithm: str,
) -> None:
    cert_algo, hash_algo = {
        "md5": (hashes.MD5(), hashes.SHA256()),
        "sha1": (hashes.SHA1(), hashes.SHA256()),
        "sha256": (hashes.SHA256(), hashes.SHA256()),
        "sha384": (hashes.SHA384(), hashes.SHA384()),
        "sha512": (hashes.SHA512(), hashes.SHA512()),
    }[algorithm]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(key, cert_algo)  # type: ignore[arg-type]
        ).public_bytes(encoding=serialization.Encoding.DER)
    except (UnsupportedAlgorithm, ValueError) as e:
        pytest.skip(f"Hash algorithm is unavailable: {e}")

    digest = hashes.Hash(hash_algo)
    digest.update(cert)
    expected = b"tls-server-end-point:" + digest.finalize()

    actual = get_tls_server_end_point_data(cert)
    assert actual == expected


def test_get_tls_binding_data_ed25519() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(key, None)
    ).public_bytes(encoding=serialization.Encoding.DER)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(cert)
    expected = b"tls-server-end-point:" + digest.finalize()

    actual = get_tls_server_end_point_data(cert)
    assert actual == expected


@pytest.mark.parametrize("format", ["pem", "der"])
def test_trust_cert_file(format: str, tls_server: TlsServer, tmp_path: pathlib.Path) -> None:
    context = ssl.create_default_context()

    if format == "pem":
        encoding = serialization.Encoding.PEM
    else:
        encoding = serialization.Encoding.DER

    cert_file = tmp_path / "ca.pem"
    cert_file.write_bytes(tls_server.ca.public_bytes(encoding))

    load_trust_certificate(
        context,
        str(cert_file),
    )
    cert_file.unlink(missing_ok=True)

    perform_handshake(context, tls_server)


def test_trust_cert_dir(tls_server: TlsServer, tmp_path: pathlib.Path) -> None:
    context = ssl.create_default_context()

    cert_dir = tmp_path / "ca"
    cert_dir.mkdir()

    cert_file = cert_dir / "ca.pem"
    cert_file.write_bytes(tls_server.ca.public_bytes(serialization.Encoding.PEM))

    # The c_rehash mechanism is not public and has changed in the past. Use
    # OpenSSL to get the expected hash of the cert for this test.
    cert_hash = (
        subprocess.check_output(
            ["openssl", "x509", "-hash", "-noout", "-in", str(cert_file)],
        )
        .decode()
        .strip()
    )
    cert_file = cert_file.rename(cert_dir / f"{cert_hash}.0")

    load_trust_certificate(context, str(cert_dir))

    perform_handshake(context, tls_server)


def test_trust_cert_str(tls_server: TlsServer) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    perform_handshake(context, tls_server)


@pytest.mark.parametrize(
    "cert_first, password",
    [
        (True, None),
        (False, None),
        (True, b"Password123!\xFF"),
        (False, b"Password123!\xFF"),
    ],
)
def test_client_auth_path_pem_file_combined(
    cert_first: bool,
    password: t.Optional[bytes],
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
    tmp_path: pathlib.Path,
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.PEM)
    key = client_certificate[1].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo,
    )

    cert_file = tmp_path / "client.pem"

    if cert_first:
        cert_file.write_bytes(cert + b"\n" + key)
    else:
        cert_file.write_bytes(key + b"\n" + cert)

    load_client_certificate(
        context,
        str(cert_file),
        password=password.decode("utf-8", errors="surrogateescape") if password else None,
    )

    cert_file.unlink()

    perform_handshake(context, tls_server, client_certificate[0])


@pytest.mark.parametrize("password", [None, b"Password123!\xFF"])
def test_client_auth_path_pem_file_separate_key(
    password: t.Optional[bytes],
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
    tmp_path: pathlib.Path,
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.PEM)
    key = client_certificate[1].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo,
    )

    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert)

    key_file = tmp_path / "key.pem"
    key_file.write_bytes(key)

    load_client_certificate(
        context,
        str(cert_file),
        key=str(key_file),
        password=password.decode("utf-8", errors="surrogateescape") if password else None,
    )

    cert_file.unlink()
    key_file.unlink()

    perform_handshake(context, tls_server, client_certificate[0])


@pytest.mark.parametrize("password", [None, b"Password123!\xFF"])
def test_client_auth_pem_str_combined(
    password: t.Optional[bytes],
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.PEM).decode()
    key = (
        client_certificate[1]
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        )
        .decode()
    )

    cert_data = cert + "\n" + key

    load_client_certificate(
        context,
        cert_data,
        password=password.decode("utf-8", errors="surrogateescape") if password else None,
    )

    perform_handshake(context, tls_server, client_certificate[0])


@pytest.mark.parametrize("password", [None, b"Password123!\xFF"])
def test_client_auth_pem_str_separate_key(
    password: t.Optional[bytes],
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.PEM).decode()
    key = (
        client_certificate[1]
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        )
        .decode()
    )

    load_client_certificate(
        context,
        cert,
        key=key,
        password=password.decode("utf-8", errors="surrogateescape") if password else None,
    )

    perform_handshake(context, tls_server, client_certificate[0])


@pytest.mark.parametrize(
    "cert_is_file, password",
    [
        (True, None),
        (False, None),
        (True, b"Password123!\xFF"),
        (False, b"Password123!\xFF"),
    ],
)
def test_client_auth_pem_mixed(
    cert_is_file: bool,
    password: t.Optional[bytes],
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
    tmp_path: pathlib.Path,
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.PEM).decode()
    key = (
        client_certificate[1]
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        )
        .decode()
    )

    cert_file = tmp_path / "cert.pem"
    cert_file.write_text(cert)

    key_file = tmp_path / "key.pem"
    key_file.write_text(key)

    load_client_certificate(
        context,
        str(cert_file) if cert_is_file else cert,
        key=key if cert_is_file else str(key_file),
        password=password.decode("utf-8", errors="surrogateescape") if password else None,
    )

    cert_file.unlink()
    key_file.unlink()

    perform_handshake(context, tls_server, client_certificate[0])


def test_client_auth_path_der_cert(
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
    tmp_path: pathlib.Path,
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.DER)
    key = client_certificate[1].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_file = tmp_path / "cert.crt"
    cert_file.write_bytes(cert)

    key_file = tmp_path / "key.pem"
    key_file.write_bytes(key)

    load_client_certificate(context, str(cert_file), key=str(key_file))

    cert_file.unlink()
    key_file.unlink()

    perform_handshake(context, tls_server, client_certificate[0])


@pytest.mark.parametrize("password", [None, b"Password123!\xFF"])
def test_client_auth_path_der_key(
    password: t.Optional[bytes],
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
    tmp_path: pathlib.Path,
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.PEM)
    key = client_certificate[1].private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo,
    )
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(cert)

    key_file = tmp_path / "key.crt"
    key_file.write_bytes(key)

    load_client_certificate(
        context,
        str(cert_file),
        key=str(key_file),
        password=password.decode("utf-8", errors="surrogateescape") if password else None,
    )

    cert_file.unlink()
    key_file.unlink()

    perform_handshake(context, tls_server, client_certificate[0])


@pytest.mark.parametrize("password", [None, b"P\xc3\xa4ssword123!"])
def test_client_auth_path_pfx_file(
    password: t.Optional[bytes],
    tls_server: TlsServer,
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
    tmp_path: pathlib.Path,
) -> None:
    context = ssl.create_default_context()
    load_trust_certificate(
        context,
        tls_server.ca.public_bytes(serialization.Encoding.PEM).decode(),
    )

    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    data = serialize_key_and_certificates(b"FriendlyName", client_certificate[1], client_certificate[0], None, enc_algo)

    cert_file = tmp_path / "cert.pfx"
    cert_file.write_bytes(data)

    load_client_certificate(
        context,
        str(cert_file),
        password=password.decode("utf-8", errors="surrogateescape") if password else None,
    )

    cert_file.unlink()

    perform_handshake(context, tls_server, client_certificate[0])


def test_client_auth_incorrect_password(
    client_certificate: t.Tuple["x509.Certificate", "rsa.RSAPrivateKey"],
) -> None:
    context = ssl.create_default_context()

    enc_algo = serialization.BestAvailableEncryption(b"Password01")
    cert = client_certificate[0].public_bytes(encoding=serialization.Encoding.PEM).decode()
    key = (
        client_certificate[1]
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        )
        .decode()
    )

    with pytest.raises(ssl.SSLError):
        load_client_certificate(context, key + cert)


def perform_handshake(
    client: ssl.SSLContext,
    server: TlsServer,
    expected_client: t.Optional["x509.Certificate"] = None,
) -> None:
    client_in = ssl.MemoryBIO()
    client_out = ssl.MemoryBIO()
    client_tls = client.wrap_bio(
        client_in,
        client_out,
        server_side=False,
        server_hostname=server.name,
    )

    server_in = ssl.MemoryBIO()
    server_out = ssl.MemoryBIO()
    server_tls = server.context.wrap_bio(
        server_in,
        server_out,
        server_side=True,
    )

    in_token: t.Optional[bytes] = None
    while True:
        if in_token:
            client_in.write(in_token)

        out_token: t.Optional[bytes] = None
        try:
            client_tls.do_handshake()
        except ssl.SSLWantReadError:
            pass

        out_token = client_out.read()
        if not out_token:
            break

        server_in.write(out_token)
        try:
            server_tls.do_handshake()
        except ssl.SSLWantReadError:
            pass

        in_token = server_out.read()
        if not in_token:
            break

    assert client_tls.version() == server_tls.version()
    assert client_tls.cipher() == server_tls.cipher()

    if expected_client:
        client_cert_bytes = server_tls.getpeercert(True)
        assert client_cert_bytes is not None
        client_cert = x509.load_der_x509_certificate(client_cert_bytes)
        assert str(client_cert.subject) == str(expected_client.subject)
        assert client_cert.public_bytes(serialization.Encoding.PEM) == expected_client.public_bytes(
            serialization.Encoding.PEM
        )
