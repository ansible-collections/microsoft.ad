.. _ansible_collections.microsoft.ad.docsite.guide_ldap_connection:

*********************
LDAP Connection guide
*********************

This guide covers information about communicating with an LDAP server, like Microsoft Active Directory, from the Ansible host. Unlike Windows hosts, there are no builtin mechanisms to communicate and authenticate with an LDAP server, so the plugins that run on the Ansible host require some extra configuration to get working.

.. note::
  This guide covers LDAP communication from the Ansible host. This does not apply to the modules that run on the remote Windows hosts. See :ref:`AD Authentication in Modules <ansible_collections.microsoft.ad.docsite.guide_ad_module_authentication>` for information on how modules authentication can be configured.

.. contents::
  :local:
  :depth: 1

.. _ansible_collections.microsoft.ad.docsite.guide_ldap_connection.requirements:

Requirements
============

The LDAP connection code requires the `sansldap <https://pypi.org/project/sansldap/>`_ and `pyspnego <https://pypi.org/project/pyspnego/>`_ libraries. They can be installed using ``pip`` with:

.. code-block:: shell-session

    $ python3 -m pip install --user \
        'pyspnego >= 0.8.0'
        sansldap

.. note::
  This guide assumes ``python3`` is the same Python that Ansible uses, see ``ansible --version`` for details on the Python version/location.

There are also optional dependencies to provide extra features

+-------------------------+-----------------------------+
| Feature                 | Package                     |
+=========================+=============================+
| Kerberos Authentication | pyspnego[kerberos] >= 0.8.0 |
+-------------------------+-----------------------------+
| Server Lookups          | dnspython                   |
+-------------------------+-----------------------------+
| LAPS Decryption         | dpapi-ng                    |
+-------------------------+-----------------------------+

To install all the optional features run:

.. code-block:: shell-session

    $ python3 -m pip install --user \
        dnspython \
        dpapi-ng \
        'pyspnego[kerberos] >= 0.8.0'

The Kerberos authentication components require the Kerberos system libraries to be present. For RPM based systems, these are:

.. code-block:: shell-session

    $ dnf install gcc python3-devel krb5-libs krb5-devel

Other Linux distributions require the same packages listed above but they are likely listed under different names than what ``dnf`` uses.

The :ref:`microsoft.ad.debug_ldap_client <ansible_collections.microsoft.ad.debug_ldap_client_module>`. action plugin can be used to debug the Ansible host setup and its LDAP capabilities. It includes details such as:

* The Python packages related to LDAP that are installed, or import failure messages if not installed
* The Kerberos host and credential cache information if the Kerberos extras are installed
* The SRV lookup information if ``dnspython`` and Kerberos extras are installed

To use this module simply run

.. code-block:: shell-session

    $ ansible localhost -m microsoft.ad.debug_ldap_client


.. _ansible_collections.microsoft.ad.docsite.guide_ldap_connection.connection_options:

Connection options
==================

Connecting to a Microsoft Active Directory or LDAP server requires information like the domain controller hostname, port, whether to use LDAPS or StartTLS, and authentication information. Some of this information can be retrieved based on the Ansible host environment but can also be manually specified through the plugin options. These options include:

+---------------+--------------------------------+---------------------------------------------+
| Option        | Default                        | Purpose                                     |
+===============+================================+=============================================+
| server        | Server lookup through Kerberos | The LDAP server hostname                    |
+---------------+--------------------------------+---------------------------------------------+
| port          | 389 or 686 if tls_mode=ldaps   | The LDAP port                               |
+---------------+--------------------------------+---------------------------------------------+
| tls_mode      | LDAPS if port=686 else None    | TLS details - LDAP, LDAP + StartTLS, LDAPS  |
+---------------+--------------------------------+---------------------------------------------+
| auth_protocol | Negotiate                      | Authentication protocol                     |
+---------------+--------------------------------+---------------------------------------------+
| username      | None                           | Attempts to use Kerberos cache if available |
+---------------+--------------------------------+---------------------------------------------+
| password      | None                           | Attempts to use Kerberos cache if available |
+---------------+--------------------------------+---------------------------------------------+

The server lookup details are described below. The port defaults to ``389`` unless ``tls_mode: ldaps`` is specified. The TLS mode defaults to ``ldaps`` if the port is explicitly set to ``686`` otherwise it defaults to ``389``. The authentication protocol defaults to ``negotiate`` while attempting to use the implicit credential if it's available.


.. _ansible_collections.microsoft.ad.docsite.guide_ldap_connection.server_lookup:

Server lookup
-------------

If no server option was explicitly set, the plugin will attempt to lookup the LDAP server based on the current environment configuration. This is only possible if:

* The ``dnspython`` Python package is installed
* The ``pyspnego[kerberos]`` Python package for Kerberos is installed
* The underlying Kerberos library has a ``default_realm`` set in the `MIT krb5.conf <https://web.mit.edu/kerberos/krb5-latest/doc/admin/host_config.html#default-realm>`_

If none of the above are true, the connection will fail and an explicit server must be supplied. If all the requirements are satisfied this is the server lookup workflow:

* The ``default_realm`` of the local Kerberos configuration is retrieved
* A DNS SRV lookup is done for the record ``_ldap._tcp.dc._msdcs.{{ default_realm }}``
* The DNS records are sorted by priority and weight and the first is selected
* The hostname and port on the selected SRV record are used for the lookup

.. note::
  If an explicit port is specified, it will take priority over the port returned by the SRV record.


.. _ansible_collections.microsoft.ad.docsite.guide_ldap_connection.authentication:

Authentication
==============

A critical component of LDAP connections is how the user authenticates itself to the server. The following authentication mechanisms are supported:

+----------------+---------------------+----------------------------+
| Authentication | Supports Encryption | Implicit Credential        |
+================+=====================+============================+
| simple         | No - TLS needed     | Yes - Appears as Anonymous |
+----------------+---------------------+----------------------------+
| certificate    | Yes                 | No                         |
+----------------+---------------------+----------------------------+
| negotiate      | Yes                 | Yes - With Kerberos        |
+----------------+---------------------+----------------------------+
| kerberos       | Yes                 | Yes                        |
+----------------+---------------------+----------------------------+
| ntlm           | Yes                 | No                         |
+----------------+---------------------+----------------------------+

Unless otherwise specified, the default authentication protocol used is ``negotiate`` which relies on the ``pyspnego`` library. See :ref:`requirements <ansible_collections.microsoft.ad.docsite.guide_ldap_connection.requirements>` for more information on how to install this requirement.

Any protocol that does not support encryption must either be used with LDAPS, StartTLS, or they must explicitly disable the encryption checks with the ``encrypt: false`` option. Disabling encryption is not recommended as it will send the credentials without any protection and any of the data exchanged can be seen by anyone. It also requires the target server to allow unencrypted connections as they can reject such connections.

Implicit credential support documents whether the authentication protocol can authenticate without an explicit ``username`` and ``password`` specified. Currently only ``simple`` and ``negotiate/kerberos`` supports implicit credentials. See each protocol section for more details.

Simple
------

Simple authentication is the most basic authentication protocol supported. It works by sending the username and password in plaintext to the server, similar to HTTP Basic authentication. Microsoft AD requires the username to be the ``sAMAccountName`` or ``userPrincipalName`` of the account but other LDAP implementations require the LDAP ``distinguishedName``. While it is possible to do an anonymous bind when no username or password is specified, it is likely the server will reject any search operations unless it is authenticated with an actual users credentials. Simple authentication is not allowed over a connection that is not protected by TLS. It is possible to allow simple authentication over such connections by disabling the encryption check but this is not recommended.

.. warning::
    Simple authentication should be avoided unless TLS is used, either through LDAPS or StartTLS. Failure to use use LDAPS will expose the credentials used during the authentication and the subsequent data unprotected from eavesdropping or tampering.


Certificate
-----------

Certificate authentication uses TLS client authentication as part of the TLS handshake to authenticate the user to the host. As it is part of the TLS handshake, it can only be used over an LDAPS connection or with StartTLS. It uses a certificate and certificate key of the user to authenticate as. There are three options that can be used to specify a client certificate and key to use for authentication:

* ``certificate`` - The certificate, and optionally bundled key
* ``certificate_key`` - The certificate key if not bundled in ``certificate``
* ``certificate_password`` - The password used to decrypt the certificate key

The ``certificate`` and ``certificate_key`` can either be a file path to the certificate and key or they can be a string of the PEM encoded certificate/key. The ``certificate`` file path can be a PEM, DER, or PKCS12/PFX encoded certificate with optional key bundle whereas the ``certificate_key`` file path can be a PEM or DER encoded key. If the key inside the PEM, DER, or PKCS12/PFX content is encrypted, the ``certificate_password`` can be used to specify the password used to decrypt the key.

.. note::
    Setting these options are dependent on the plugin itself, the keys here reflect the option name and not necessarily Ansible variables that can be set and read automatically by a plugin.


Negotiate
---------

Negotiate authentication is the default authentication protocol used by LDAP connections. It is a combination of both ``kerberos`` and ``ntlm`` with the client negotiating which one to use. It will favor ``kerberos`` if it is available and fallback to ``ntlm`` if not. The ``pyspnego`` Python package provides ``negotiate`` with just ``ntlm`` support, ``kerberos`` support is provided by the ``pyspnego[kerberos]`` extras option. See :ref:`requirements <ansible_collections.microsoft.ad.docsite.guide_ldap_connection.requirements>` for more information on how to install this requirement.

Kerberos
--------

Kerberos authentication is a modern authentication protocol supported by Microsoft AD servers and is the preferred protocol for authentication. It is only available if the ``pyspnego[kerberos]`` extras package is installed and the host has been configured properly. Typically this configuration is done through the `/etc/krb5.conf <https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html>`_ file on the system. This guide will not go into configuring the host's Kerberos settings as it is environment specific.

A good way to ensure the host has been configured to use Kerberos correctly is to ensure the following commands work:

.. code-block:: shell-session

    $ python -c "import krb5"
    $ kinit username@DOMAIN.REALM
    $ kvno ldap/dc.domain.realm

.. note::
    The ``kvno`` command is an MIT krb5 specific command, it is not available on hosts that use Heimdal krb5 like macOS.

The ``python`` command ensures the required Python libraries have been installed. The ``kinit`` command will retrieve a Kerberos ticket for the user specified and the ``kvno`` command will attempt to retrieve a service ticket for the service principal name (SPN) requested. If both commands work then there is a good chance Kerberos authentication will work with the LDAP connection.

Using the ``kinit`` command it is possible to set up a credential cache for Ansible to use for authentication. By having a credential retrieved using ``kinit``, it is possible to authenticate with the LDAP server without any explicit username and password set in Ansible. It is still possible to use Kerberos with explicit credentials.

NTLM
----

NTLM authentication is a simple authentication protocol that can be used by itself or as part of the ``negotiate`` fallback if ``kerberos`` is unavailable. Unlike ``kerberos`` support, it does not normally support implicit credentials so typically needs an explicit username and password specified to be used. It requires no extra host configuration and should work once ``pyspnego`` has been installed.

.. warning::
  While NTLM does support encryption it is considered weak by modern standards. It is recommended to only use NTLM with an LDAPS or StartTLS connection where the stronger encryption and server checks provided by TLS mitigate the weaknesses in NTLM.


.. _ansible_collections.microsoft.ad.docsite.guide_ldap_connection.cert_validation:

Certificate validation
======================

Using LDAPS or LDAP over StartTLS will perform a TLS handshake which by default has the client attempting to validate the certificate presented by the server. If the certificate chain cannot be trusted, or the hostname does not match the one being requested the connection will fail with an error indicating why. The default trust store location is dependent on the Python configuration and what SSL library it has been linked to. Typically it would be the OS' default trust store but when in doubt the following Python code can be used to verify the LDAPS certificate. Make sure to change ``hostname`` to the hostname of the LDAP server that should be tested.

.. code-block:: python

    import socket
    import ssl

    hostname = 'dc.domain.com'
    port = 636
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print(ssock.version())

The ``ca_cert`` connection option can be used to set an explicit CA bundle to use for verification. This is useful if the CA bundle is not part of the OS store but located somewhere else on the filesystem. The value can be in the form of:

* a file path to a PEM or DER encoded bundle of certificates
* A directory path that contains several CA certificates in the PEM format following an OpenSSL specific layout as document by `CApath <https://www.openssl.org/docs/manmaster/man3/SSL_CTX_load_verify_locations.html>`_
* A string containing PEM encoded certificates

It is also possible to disable certificate verification using the ``cert_validation`` connection option. The default is ``always`` but can be set to ``ignore`` to disable all checks or ``ignore_hostname`` to disable just the hostname check. This can be useful for test environments that use self signed certificates but it should not be used in a production environment.

.. warning::
    Disabling certificate validation removes a lot of the benefits that TLS offers. There is no way to verify the target server is who it says that it is.
