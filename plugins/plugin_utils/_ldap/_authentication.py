# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import annotations

import ssl
import struct
import typing as t

import sansldap
import spnego

from .client import SyncLDAPClient, MessageEncryptor, Credential


# cryptography is used for TLS channel binding with SPNEGO.
try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes

    HAS_CRYPTOGRAPHY = True
except Exception:
    HAS_CRYPTOGRAPHY = False


class SimpleCredential(Credential):
    def __init__(self, username: t.Optional[str] = None, password: t.Optional[str] = None) -> None:
        self.username = username
        self.password = password

    def authenticate(
        self,
        client: SyncLDAPClient,
        *,
        tls_sock: t.Optional[ssl.SSLSocket] = None,
    ) -> None:
        client.bind(self.username or "", sansldap.SimpleCredential(self.password or ""))


class ClientCertificate(Credential):
    def authenticate(
        self,
        client: SyncLDAPClient,
        *,
        tls_sock: t.Optional[ssl.SSLSocket] = None,
    ) -> None:
        # The certs are provided in the TLS handshake, the SASL EXTERNAL mech
        # just tells the server to check those for the bind.
        client.bind("", sansldap.SaslCredential("EXTERNAL", b""))


class NegotiateCredential(Credential):
    def __init__(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
        protocol: str = "negotiate",
        encrypt: bool = True,
    ) -> None:
        self.username = username
        self.password = password
        self.protocol = protocol
        self.encrypt = encrypt

    def authenticate(
        self,
        client: SyncLDAPClient,
        *,
        tls_sock: t.Optional[ssl.SSLSocket] = None,
    ) -> None:
        context_req = spnego.ContextReq.mutual_auth

        if tls_sock or not self.encrypt:
            # MS AD rejects any authentication that provides integrity or
            # confidentiality if the connection is already protected by TLS.
            # As the GSS-SPNEGO SASL relies on the context attributes to
            # negotiate whether signing/encryption and Kerberos by default
            # always uses the integrity attributes we need to tell it explicity
            # not to. The no_integrity flag does that for us.
            needs_encryptor = False
            context_req |= spnego.ContextReq.no_integrity

        else:
            # When not operating over TLS request integrity and confidentiality
            # so that we can encrypt the traffic.
            needs_encryptor = True
            context_req |= (
                spnego.ContextReq.sequence_detect | spnego.ContextReq.integrity | spnego.ContextReq.confidentiality
            )

        ctx = spnego.client(
            username=self.username,
            password=self.password,
            hostname=client.server,
            service="ldap",
            context_req=context_req,
        )

        cbt = self._get_tls_channel_bindings(tls_sock)
        in_token: t.Optional[bytes] = None
        while not ctx.complete:
            out_token = ctx.step(in_token=in_token, channel_bindings=cbt)
            if not out_token:
                break

            in_token = client.bind(
                "",
                sansldap.SaslCredential("GSS-SPNEGO", out_token),
                success_only=ctx.complete,
            )

        if needs_encryptor:
            client.register_encryptor(SpnegoEncryptor(ctx))

    def _get_tls_channel_bindings(
        self,
        tls_sock: t.Optional[ssl.SSLSocket] = None,
    ) -> t.Optional[spnego.channel_bindings.GssChannelBindings]:
        if not HAS_CRYPTOGRAPHY or not tls_sock:
            return None

        cert_bytes = tls_sock.getpeercert(True)
        if not cert_bytes:
            return None

        backend = default_backend()

        cert = x509.load_der_x509_certificate(cert_bytes, backend)
        try:
            hash_algorithm = cert.signature_hash_algorithm
        except UnsupportedAlgorithm:
            hash_algorithm = None

        # If the cert signature algorithm is unknown, md5, or sha1 then use sha256 otherwise use the signature
        # algorithm of the cert itself.
        if not hash_algorithm or hash_algorithm.name in ["md5", "sha1"]:
            digest = hashes.Hash(hashes.SHA256(), backend)
        else:
            digest = hashes.Hash(hash_algorithm, backend)

        digest.update(cert_bytes)
        cert_hash = digest.finalize()

        return spnego.channel_bindings.GssChannelBindings(
            application_data=b"tls-server-end-point:" + cert_hash,
        )


class SpnegoEncryptor(MessageEncryptor):
    def __init__(self, context: spnego.ContextProxy) -> None:
        self.context = context

    def wrap(
        self,
        data: bytes,
    ) -> bytes:
        wrapped_data = self.context.wrap(data, encrypt=True).data
        return len(wrapped_data).to_bytes(4, byteorder="big") + wrapped_data

    def unwrap(
        self,
        data: bytes,
    ) -> tuple[bytes, int]:
        data_view = memoryview(data)
        data_len = struct.unpack(">I", data_view[:4])[0]
        data_view = data_view[4:]
        if len(data_view) < data_len:
            return b"", 0

        data_view = data_view[:data_len]

        return self.context.unwrap(data_view.tobytes()).data, data_len + 4
