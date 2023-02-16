# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = """
name: laps_password
author: Jordan Borean (@jborean93)
short_description: Retrieves the LAPS password for a server.
description:
- This lookup returns the LAPS password set for a server from the Active Directory database.
options:
  _terms:
    description:
    - The host name to retrieve the LAPS password for.
    - This corresponds to the C(sAMAccountName) of the computer to lookup.
    - If the value does not end with C($), it is automatically added during the
      lookup.
    required: True
    type: str
  auth_protocol:
    description:
    - The authentication protocol to use when connecting to the LDAP host.
    - FIXME determine and document defaults
    - C(simple) is simple authentication where the user and password are sent
      in plaintext. It does not support any encryption so either must be used
      with LDAPS, or StartTLS. If using over a plaintext LDAP connection
      without TLS, C(encrypt=False) must be specified to explicitly opt into no
      encryption.
    - C(certificate) is TLS client certificate authentication. It can only be
      used with LDAPS or StartTLS. See I(certificate) for more
      information.
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
      should contain just the certificate.
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
  search_base:
    description:
    - Changes the search based used when searching for the computer object.
    - Defaults to the C(defaultNamingContext) of the Active Directory server
      if not specified.
    - If searching a larger Active Directory database, it is recommended to
      narrow the search base to speed up the queries.
    type: str
  server:
    description:
    - The domain controller/server to connect to.
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
requirements:
- dnspython - For option server lookup support
- pyspnego
- pyspnego[kerberos] - For Kerberos and server lookup support
- sansldap
"""

EXAMPLES = """
"""

RETURN = """
_raw:
  description:
  - The LAPS password(s) for the host(s) requested.
  type: str
"""

from ansible.errors import AnsibleLookupError
from ansible.module_utils.basic import missing_required_lib
from ansible.plugins.lookup import LookupBase

try:
    import sansldap
    from ..plugin_utils import _ldap as ldap

    HAS_LDAP = True
    LDAP_IMP_ERR = None
except Exception as e:
    HAS_LDAP = False
    LDAP_IMP_ERR = e


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if not HAS_LDAP:
            msg = missing_required_lib(
                "sansldap",
                url="https://pypi.org/project/sansldap/",
                reason="for ldap lookups",
            )
            raise AnsibleLookupError(f"{msg}: {LDAP_IMP_ERR}") from LDAP_IMP_ERR

        self.set_options(var_options=variables, direct=kwargs)

        with ldap.create_connection(**self.get_options()) as client:

            host_filter = sansldap.FilterOr(filters=[])

            hosts = []
            for t in terms:
                host = str(t)
                if not host.endswith("$"):
                    host = f"{host}$"

                hosts.append(host)
                host_filter.filters.append(sansldap.FilterEquality("sAMAccountName", host.encode("utf-8")))

            ldap_filter = sansldap.FilterAnd(filters=[sansldap.FilterEquality("objectClass", b"computer"), host_filter])

            result = client.search(
                ldap_filter,
                ["sAMAccountName", "ms-Mcs-AdmPwd"],
                search_base=self.get_option("search_base"),
            )
            sam_results = {
                r["sAMAccountName"][0].decode("utf-8").upper(): r.get("ms-Mcs-AdmPwd", None) for r in result.values()
            }

            laps_passwords = []
            for host in hosts:
                upper_host = host.upper()
                if upper_host not in sam_results:
                    raise AnsibleLookupError(f"Failed to find the server '{host}'")

                password = sam_results[upper_host]
                if not password:
                    raise AnsibleLookupError(f"The server '{host}' did not have the LAPS attribute 'ms-Mcs-AdmPwd'")

                laps_passwords.append(password[0].decode("utf-8"))

            return laps_passwords
