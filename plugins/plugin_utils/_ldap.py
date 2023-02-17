# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""LDAP Helpers.

This contains the code needed to perform LDAP operations for plugins in this
collection. It should only be used by plugins in this collection as the
interface is not final and could be subject to change.
"""

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import annotations

import socket
import ssl
import struct
import threading
import typing as t

import sansldap
import spnego


# cryptography is used for TLS channel binding with SPNEGO.
try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes

    HAS_CRYPTOGRAPHY = True
except Exception:
    HAS_CRYPTOGRAPHY = False

# dnspython is used for dynamic server lookups
try:
    import dns.resolver

    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False


# krb5 is used to retrieve the default realm for dynamic server lookups.
try:
    import krb5

    HAS_KRB5 = True
except Exception:
    HAS_KRB5 = False


MessageType = t.TypeVar("MessageType", bound=sansldap.LDAPMessage)


class Credential:
    def authenticate(
        self,
        client: SyncLDAPClient,
        *,
        tls_sock: t.Optional[ssl.SSLSocket] = None,
    ) -> None:
        raise NotImplementedError()


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
            client.register_encryptor(MessageEncryptor(ctx))

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


class MessageEncryptor:
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


class LDAPResultError(Exception):
    def __init__(
        self,
        msg: str,
        result: sansldap.LDAPResult,
    ) -> None:
        super().__init__(msg)
        self.result = result

    def __str__(self) -> str:
        inner_msg = super().__str__()
        msg = f"Received LDAPResult error {inner_msg} - {self.result.result_code.name}"
        if self.result.matched_dn:
            msg += f" - Matched DN {self.result.matched_dn}"

        if self.result.diagnostics_message:
            msg += f" - {self.result.diagnostics_message}"

        return msg


class ResponseHandler(t.Generic[MessageType]):
    def __init__(
        self,
        message_id: int,
        message_types: t.Tuple[t.Type[MessageType], ...],
    ) -> None:
        self._message_id = message_id
        self._message_types = message_types
        self._condition = threading.Condition()
        self._exp: t.Optional[Exception] = None
        self._results: t.List[MessageType] = []

    def __iter__(self) -> t.Iterator[MessageType]:
        return self._iter_next()

    def append(
        self,
        value: t.Union[Exception, MessageType],
    ) -> None:
        with self._condition:
            if isinstance(value, Exception):
                self._exp = value
            elif isinstance(value, self._message_types) and value.message_id == self._message_id:
                self._results.append(value)
            else:
                return

            self._condition.notify_all()

    def _iter_next(self) -> t.Iterator[MessageType]:
        idx = 0
        while True:
            with self._condition:
                if self._exp:
                    raise Exception(f"Exception from receiving task: {self._exp}") from self._exp

                if idx < len(self._results):
                    value = self._results[idx]
                    idx += 1
                    yield value

                else:
                    self._condition.wait()


class SyncLDAPClient:
    def __init__(
        self,
        server: str,
        sock: t.Union[socket.socket, ssl.SSLSocket],
    ) -> None:
        self.server = server

        self._protocol = sansldap.LDAPClient()
        self._sock = sock
        self._response_handler: t.List[ResponseHandler] = []
        self._encryptor: t.Optional[MessageEncryptor] = None
        self._reader_task = threading.Thread(
            target=self._read_loop,
            name=f"LDAP({server})",
        )
        self._reader_task.start()
        self._wait_tls: t.Optional[threading.Event] = None
        self._default_naming_context: t.Optional[str] = None

    def __enter__(self) -> SyncLDAPClient:
        return self

    def __exit__(self, *args: t.Any, **kwargs: t.Any) -> None:
        self.close()

    def bind(
        self,
        dn: str,
        credential: sansldap.AuthenticationCredential,
        success_only: bool = True,
    ) -> t.Optional[bytes]:
        msg_id = self._protocol.bind(dn, credential)
        response = self._write_and_wait_one(msg_id, sansldap.BindResponse)

        valid_codes = [sansldap.LDAPResultCode.SUCCESS]
        if not success_only:
            valid_codes.append(sansldap.LDAPResultCode.SASL_BIND_IN_PROGRESS)

        if response.result.result_code not in valid_codes:
            raise LDAPResultError("bind failed", response.result)

        return response.server_sasl_creds

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # The socket has already been shutdown for some other reason
            pass
        self._sock.close()
        self._reader_task.join()

    def register_encryptor(
        self,
        encryptor: MessageEncryptor,
    ) -> None:
        self._encryptor = encryptor

    def start_tls(
        self,
        options: ssl.SSLContext,
        *,
        server_hostname: t.Optional[str] = None,
    ) -> ssl.SSLSocket:
        msg_id = self._protocol.extended_request(sansldap.ExtendedOperations.LDAP_START_TLS)
        self._wait_tls = wait_event = threading.Event()
        try:
            response = self._write_and_wait_one(msg_id, sansldap.ExtendedResponse)
            self._valid_result(response.result, "StartTLS failed")

            self._sock = options.wrap_socket(
                self._sock,
                server_hostname=server_hostname or self.server,
            )
            return self._sock
        finally:
            wait_event.set()

    def search(
        self,
        filter: t.Union[str, sansldap.LDAPFilter],
        attributes: t.List[str],
        search_base: t.Optional[str] = None,
    ) -> t.Dict[str, t.Dict[str, t.List[bytes]]]:
        if search_base is None:
            search_base = self._get_default_namining_context()

        res: t.Dict[str, t.Dict[str, t.List[bytes]]] = {}
        for entry in self._search_request(
            base_object=search_base,
            scope=sansldap.SearchScope.SUBTREE,
            filter=filter,
            attributes=attributes,
        ):
            if not isinstance(entry, sansldap.SearchResultEntry):
                continue

            entry_res = res.setdefault(entry.object_name, {})
            for attr in entry.attributes:
                entry_attr = entry_res.setdefault(attr.name, [])
                entry_attr.extend(attr.values)

        return res

    def _get_default_namining_context(self) -> str:
        if self._default_naming_context is None:
            default_naming_context = ""
            for res in self._search_request(
                base_object="",
                scope=sansldap.SearchScope.BASE,
                filter=sansldap.FilterPresent("objectClass"),
                attributes=["defaultNamingContext"],
            ):
                if not isinstance(res, sansldap.SearchResultEntry):
                    continue

                for attr in res.attributes:
                    if attr.name == "defaultNamingContext":
                        default_naming_context = attr.values[0].decode("utf-8")
                        break

            self._default_naming_context = default_naming_context

        return self._default_naming_context

    def _search_request(
        self,
        base_object: t.Optional[str] = None,
        scope: t.Union[int, sansldap.SearchScope] = sansldap.SearchScope.SUBTREE,
        dereferencing_policy: t.Union[int, sansldap.DereferencingPolicy] = sansldap.DereferencingPolicy.NEVER,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: bool = False,
        filter: t.Optional[t.Union[str, sansldap.LDAPFilter]] = None,
        attributes: t.Optional[t.List[str]] = None,
        controls: t.Optional[t.List[sansldap.LDAPControl]] = None,
    ) -> t.Iterator[t.Union[sansldap.SearchResultReference, sansldap.SearchResultEntry]]:
        ldap_filter: t.Optional[sansldap.LDAPFilter] = None
        if isinstance(filter, sansldap.LDAPFilter):
            ldap_filter = filter
        elif filter:
            ldap_filter = sansldap.LDAPFilter.from_string(filter)

        msg_id = self._protocol.search_request(
            base_object=base_object,
            scope=scope,
            dereferencing_policy=dereferencing_policy,
            size_limit=size_limit,
            time_limit=time_limit,
            types_only=types_only,
            filter=ldap_filter,
            attributes=attributes,
            controls=controls,
        )

        handler = self._register_response_handler(
            msg_id,
            sansldap.SearchResultEntry,
            sansldap.SearchResultReference,
            sansldap.SearchResultDone,
        )
        try:
            self._write_msg()
            for res in handler:
                if isinstance(res, sansldap.SearchResultDone):
                    self._valid_result(res.result, "search request failed")
                    break

                else:
                    yield res  # type: ignore[misc]

        finally:
            self._unregister_response_handler(handler)

    def _read_loop(self) -> None:
        data_buffer = bytearray()
        while True:
            try:
                resp = self._sock.recv(4096)
                if not resp:
                    raise Exception("LDAP connection has been shutdown")

                data_buffer.extend(resp)

                while data_buffer:
                    if self._encryptor:
                        dec_data, enc_len = self._encryptor.unwrap(data_buffer)
                        if enc_len == 0:
                            break

                        data_buffer = data_buffer[enc_len:]
                    else:
                        dec_data = bytes(data_buffer)
                        data_buffer = bytearray()

                    for msg in self._protocol.receive(dec_data):
                        for handler in self._response_handler:
                            handler.append(msg)

                        if (
                            isinstance(msg, sansldap.ExtendedResponse)
                            and msg.name == sansldap.ExtendedOperations.LDAP_START_TLS.value
                            and self._wait_tls
                        ):
                            # Need to wait until the sock object has been
                            # updated in start_tls() before issuing another
                            # recv.
                            self._wait_tls.wait()
                            self._wait_tls = None

            except sansldap.ProtocolError as e:
                if e.response:
                    self._sock.sendall(e.response)

                for handler in self._response_handler:
                    handler.append(e)
                break

            except Exception as e:
                for handler in self._response_handler:
                    handler.append(e)
                break

    def _register_response_handler(
        self,
        msg_id: int,
        *message_types: t.Type[MessageType],
    ) -> ResponseHandler[MessageType]:
        handler = ResponseHandler(
            msg_id,
            message_types,
        )
        self._response_handler.append(handler)

        return handler

    def _valid_result(
        self,
        result: sansldap.LDAPResult,
        msg: str,
    ) -> None:
        if result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError(msg, result)

    def _unregister_response_handler(
        self,
        handler: ResponseHandler,
    ) -> None:
        self._response_handler.remove(handler)

    def _write_and_wait_one(
        self,
        msg_id: int,
        message_type: t.Type[MessageType],
    ) -> MessageType:
        handler = self._register_response_handler(msg_id, message_type)
        try:
            self._write_msg()

            return handler.__iter__().__next__()

        finally:
            self._unregister_response_handler(handler)

    def _write_msg(self) -> None:
        data = self._protocol.data_to_send()
        if self._encryptor:
            data = self._encryptor.wrap(data)

        self._sock.sendall(data)


def create_connection(
    auth_protocol: t.Optional[str] = None,
    ca_cert: t.Optional[str] = None,
    cert_verification: t.Optional[str] = None,
    certificate: t.Optional[str] = None,
    certificate_key: t.Optional[str] = None,
    certificate_password: t.Optional[str] = None,
    encrypt: bool = True,
    password: t.Optional[str] = None,
    port: t.Optional[int] = None,
    server: t.Optional[str] = None,
    tls_mode: t.Optional[str] = None,
    username: t.Optional[str] = None,
    **kwargs: t.Any,  # Catches any other module option not needed here
) -> SyncLDAPClient:
    """Creates the LDAP client.

    Creates the LDAP client using the options specified.

    Returns:
        LDAPClient: The LDAP client.
    """
    if not server:
        server, lookup_port = _lookup_server()
        if not port:
            port = lookup_port

    if port is None:
        port = 636 if tls_mode == "ldaps" else 389

    if tls_mode is None and port == 636:
        tls_mode = "ldaps"

    ssl_context: t.Optional[ssl.SSLContext] = None
    if tls_mode:
        ssl_context = ssl.create_default_context()
        if ca_cert:
            # FIXME: Check if file/dir/cert contents
            ssl_context.load_verify_locations(cafile=ca_cert)

        if cert_verification == "ignore":
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE

    if not auth_protocol:
        auth_protocol = "certificate" if certificate and ssl_context else "negotiate"

    credential: Credential
    if auth_protocol == "simple":
        if encrypt and not ssl_context:
            raise Exception("Cannot use simple with encryption.")

        credential = SimpleCredential(username, password)

    elif auth_protocol == "certificate":
        if not ssl_context:
            raise Exception("TLS must be used for certificate authentication")

        if not certificate:
            raise Exception("A certificate must be specified for certificate authentication")

        ssl_context.load_cert_chain(
            certificate,
            keyfile=certificate_key,
            password=certificate_password,
        )
        credential = ClientCertificate()

    else:
        credential = NegotiateCredential(
            username,
            password,
            protocol=auth_protocol,
            encrypt=encrypt,
        )

    tls_sock: t.Optional[ssl.SSLSocket] = None
    sock = socket.create_connection((server, port))

    if ssl_context and tls_mode == "ldaps":
        tls_sock = sock = ssl_context.wrap_socket(sock, server_hostname=server)

    client = SyncLDAPClient(server, sock)
    try:
        if ssl_context and tls_mode == "start_tls":
            tls_sock = client.start_tls(ssl_context)

        credential.authenticate(client, tls_sock=tls_sock)

        return client
    except:
        client.close()
        raise


def _lookup_server() -> tuple[str, int]:
    if not HAS_DNSPYTHON:
        raise Exception("Cannot lookup server without dnspython being installed")

    default_realm: t.Optional[str] = None
    if HAS_KRB5:
        ctx = krb5.init_context()
        try:
            default_realm = krb5.get_default_realm(ctx).decode("utf-8")
        except krb5.Krb5Error:
            # Will raise if not configured and the krb5 library cannot
            # determine the default.
            pass

    if not default_realm:
        raise Exception("Failed to find default domain realm, cannot lookup server")

    srv_record = f"_ldap._tcp.dc._msdcs.{default_realm}"

    answer = next(dns.resolver.resolve(srv_record, "SRV").__iter__())
    return str(answer.target), answer.port
