# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment:

    # associated with plugin_utils._ldap.create_connection
    DOCUMENTATION = """
options:
  auth_protocol:
    description:
    - The authentication protocol to use when connecting to the LDAP host.
    - Defaults to C(certificate) if LDAPS/StartTLS is used and I(certificate)
      has been specified. Otherwise it defaults to C(negotiate).
    - C(simple) is simple authentication where the user and password are sent
      in plaintext. It does not support any encryption so either must be used
      with LDAPS, or StartTLS. If using over a plaintext LDAP connection
      without TLS, C(encrypt=False) must be specified to explicitly opt into no
      encryption.
    - C(certificate) is TLS client certificate authentication. It can only be
      used with LDAPS or StartTLS. See I(certificate) for more
      information on how to specify the client certificate used for
      authentication.
    - C(negotiate) will attempt to negotiate Kerberos authentication wtih a
      fallback to NTLM. If Kerberos is available the Kerberos credential cache
      can be used if no username or password is specified.
    - C(kerberos) will use Kerberos authentication with no NTLM fallback.
    - C(ntlm) will use NTLM authentication with no Kerberos attempt.
    - Both C(simple) and C(certificate) work without any optional dependencies.
    - C(negotiate), C(kerberos), and C(ntlm) support encryption over LDAP.
    - C(negotiate), C(kerberos), and C(ntlm) require the C(pyspnego) Python
      library to be installed. For C(kerberos), and for C(negotiate) to try
      Kerberos, the C(pyspnego[kerberos]) extras is also required.
    - See R(LDAP authentication,ansible_collections.microsoft.ad.docsite.guide_ldap_connection.authentication)
      for more information.
    choices:
    - simple
    - certificate
    - negotiate
    - kerberos
    - ntlm
    type: str
  ca_cert:
    description:
    - The path to a CA certificate PEM file to use for certificate
      verification.
    - If omitted, the default CA store used for verification is dependent on
      the current Python settings.
    type: str
  cert_verification:
    description:
    - The certificate verification behaviour when using a TLS connection.
    - This can be set to C(always), or C(ignore).
    - C(always) will perform certificate hostname and CA verification.
    - C(ignore) will ignore any certificate errors.
    - See R(Certificate verification,ansible_collections.microsoft.ad.docsite.guid_ldap.cert_verification)
      for more information.
    choices:
    - always
    - ignore
    default: always
    type: str
  certificate:
    description:
    - The path to the certificate bundle to use for certificate authentication.
    - This file can contain the certificate and key or just the certificate
      itself. Use I(certificate_key) if a separate file is used to contain the
      certificate key.
    type: str
  certificate_key:
    description:
    - The path to the certificate key to use for certificate authentication.
    - If set, the certificate key is sourced from this file and I(certificate)
      should be the path to a file with just the certificate PEM.
    - If the key is encrypted, use I(certificate_password) to specify the
      password used to decrypt the key.
    type: str
  certificate_password:
    description:
    - The password used to decrypt the certificate key specified by
      I(certificate) or I(certificate_key).
    type: str
  encrypt:
    description:
    - Whether encryption is required for the connection.
    - Encryption can either be performed using the authentication protocol or
      through TLS.
    - The I(auth_protocol) C(negotiate), C(kerberos), and C(ntlm) all support
      encryption over LDAP whereas C(simple) does not.
    - If using C(auth_protocol=simple) over LDAP without TLS then this must be
      set to C(False). As no encryption is used, all traffic will be in
      plaintext and should be avoided.
    default: true
    type: bool
  password:
    description:
    - The password to authenticate with.
    - If I(auth_protocol) is C(simple) and no password is specified, the
      bind will be performed as an unauthenticated bind.
    - If I(auth_protocol) is C(negotiate), C(kerberos), or C(ntlm) and no
      password is specified, it will attempt to use the local cached credential
      specified by I(username) if available.
  port:
    description:
    - The LDAP port to use for the connection.
    - Port 389 is used for LDAP and port 686 is used for LDAPS.
    - Defaults to port C(636) if C(tls_mode=ldaps) otherwise C(389).
    type: int
  server:
    description:
    - The domain controller/server to connect to.
    - If not specified the server will be derived from the current krb5.conf
      C(default_realm) setting and with an SRV DNS lookup.
    - See R(Server lookup,ansible_collections.microsoft.ad.docsite.guid_ldap.server_lookup)
      for more information.
    type: str
  tls_mode:
    description:
    - The TLS operation to use.
    - If an explicit I(port) is set to C(636) then this defaults to C(ldaps).
    - C(ldaps) will connect over LDAPS (port 636).
    - C(start_tls) will connect over LDAP (port 389) and perform the StartTLS
      operation before the bind.
    - It is recommended to use C(ldaps) over C(start_tls) if TLS is going to be
      used.
    choices:
    - ldaps
    - start_tls
    type: str
  username:
    description:
    - The username to authenticate with.
    - If I(auth_protocol) is C(simple) and no username is specified, anonymous
      authentication is used.
    - If I(auth_protocol) is C(negotiate), C(kerberos), or C(ntlm) and no
      username is specified, it will attempt to use the local cached credential
      if available, for example one retrieved by C(kinit).
    type: str
notes:
- See R(LDAP connection help,ansible_collections.microsoft.ad.docsite.guide_ldap)
  for more information about LDAP connections.
requirements:
- dnspython - For option server lookup support
- pyspnego >= 0.8.0
- pyspnego[kerberos] - For Kerberos and server lookup support
- sansldap
"""
