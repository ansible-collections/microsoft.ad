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
import typing as t

from .client import SyncLDAPClient, Credential
from ._lookup import lookup_ldap_server
from ._authentication import SimpleCredential, NegotiateCredential, ClientCertificate


def create_ldap_connection(
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

    Creates the LDAP client using the options specified. The options here
    correspond to the options defined in the ldap_connection doc fragment.

    Args:
        auth_protocol: The authentication protocol to use, can be simple,
            certificate, negotiate, keberos, or ntlm.
        ca_cert: The CA PEM path to use for certificate verification.
        cert_verification: Controls the certificate verification behaviour, can
            be always or ignore.
        certificate: The client certificate PEM file (optionally key) to use for
            certificate authentication.
        certificate_key: The client certificate PEM key to use for certificate
            authentication.
        certificate_password: The password used to decrypt the client
            certificate key if it is encrypted.
        encrypt: The connection should be encrypted, whether through TLS or
            with authentication encryption.
        password: The password to authenticate with.
        port: The LDAP port to use.
        server: The LDAP server to connect to.
        tls_mode: The TLS mode, can be ldaps or start_tls.
        username: The username to authenticate with.

    Returns:
        LDAPClient: The LDAP client.
    """
    if not server:
        server, lookup_port = lookup_ldap_server()
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
