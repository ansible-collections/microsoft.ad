.. _ansible_collections.microsoft.ad.docsite.guide_ad_module_authentication:

****************************
AD Authentication in Modules
****************************

A key requirement of the modules used inside this collection is being able to authenticate a user to the domain controller when managing a resource. This guide will cover the different options available for this scenario.

.. note::
  This guide covers authentication to a domain controller when using a module on a Windows host. See :ref:`LDAP Authentication <ansible_collections.microsoft.ad.docsite.guide_ldap_connection.authentication>` for information on how authentication is done when using plugins running on Linux.

.. contents::
  :local:
  :depth: 1

.. _ansible_collections.microsoft.ad.docsite.guide_ad_module_authentication.implicit_auth:

Implicit Authentication
=======================

The first and simplest option is to use the connection user's existing credentials during authentication. This avoids having to specify a username and password in the module's parameters, but it does require that the connection method used by Ansible supports credential delegation. For example using CredSSP authentication with the ``winrm`` and ``psrp`` connection plugin, or using Kerberos delegation. Other authentication options, like NTLM, do not support credential delegation and will not work with implicit authentication.

The only way to test out if implicit authentication is available is to run the module and see if it works. If it does not work then the error will most likely contain the message ``Failed to contact the AD server``.

.. _ansible_collections.microsoft.ad.docsite.guide_ad_module_authentication.become:

Become
======

If implicit authentication is not available, the module can be run with ``become`` that specifies the username and password to use for authentication.

.. code-block:: yaml

    - name: Use become with connection credentials
      microsoft.ad.user:
        name: MyUser
        state: present
      become: true
      become_method: runas
      become_flags: logon_type=new_credentials logon_flags=netcredentials_only
      vars:
        ansible_become_user: '{{ ansible_user }}'
        ansible_become_pass: '{{ ansible_password }}'

The ``runas`` method is used on Windows and the ``become_flags`` will specify that the credentials should be used for network authentication only. The ``ansible_become_user`` and ``ansible_become_pass`` variables specify the username and password to use for authentication. It is important that both of these variables are set to a valid username and password or else the authentication will fail.

It is also possible to use the ``SYSTEM`` account for become. This will have the module use the AD computer account for that host when authenticating with the target DC rather than an explicit username and password. The AD computer account must still have the required rights to perform the operation requested.

.. code-block:: yaml

    - name: Use machine account for authentication
      microsoft.ad.user:
        name: MyUser
        state: present
      become: true
      become_method: runas
      become_user: SYSTEM

.. _ansible_collections.microsoft.ad.docsite.guide_ad_module_authentication.explicit_creds:

Explicit Credentials
====================

The final option is to specify the username and password as module options. This can be done in two ways; with the ``domain_username`` and ``domain_password`` options, or with the ``domain_credentials`` option. An example of both methods is shown below.

.. code-block:: yaml

    - name: Use domain_username and domain_password
      microsoft.ad.user:
        name: MyUser
        state: present
        domain_username: '{{ ansible_user }}'
        domain_password: '{{ ansible_password }}'

    - name: Use domain_credentials
        name: MyUser
        state: present
        domain_credentials:
        - username: '{{ ansible_user }}'
          password: '{{ ansible_password }}'

.. note::
    The ``domain_credentials`` option was added in version 1.6.0 of this collection.

The ``domain_credentials`` option without the ``name`` key, like in the above example, will be the credentials used for authentication with the default domain controller just like ``domain_username`` and ``domain_password``. Using both options together is not supported and will result in an error.

The ``domain_credentials`` option can also be used to specify server specific credentials. For example when attempting to lookup the identity of an AD object:

.. code-block:: yaml

    - name: Set member with lookup on different server
      microsoft.ad.group:
        name: MyGroup
        state: present
        members:
          add:
          - GroupOnDefaultDC
          - name: GroupOnDefaultDC2
          - name: GroupOnOtherDC
            server: OtherDC
          - name: GroupOnThirdDC
            server: ThirdDC
        domain_credentials:
        - username: UserForDefaultDC
          password: PasswordForDefaultDC
        - name: OtherDC
          username: UserForOtherDC
          password: PasswordForOtherDC

In the case above there are three members being added to the group:

* ``GroupOnDefaultDC`` - Will be looked up on the default domain controller using ``UserForDefaultDC`` and ``PasswordForDefaultDC``
* ``GroupOnDefaultDC2`` - Same as the above just specified as a dictionary
* ``GroupOnOtherDC`` - Will be looked up on ``OtherDC`` using ``UserForOtherDC`` and ``PasswordForOtherDC``
* ``GroupOnThirdDC`` - Will be looked up on ``ThirdDC`` using the implicit user authentication context

The value for ``server`` must correspond to a ``name`` entry in ``domain_credentials``. If the server is not specified in ``domain_credentials``, the module will default to using the ``domain_username/domain_password`` or implicit user authentication.

.. note::
    The default (no ``name`` key) entry in ``domain_credentials`` is only used for lookups without an explicit server set. The ``domain_username`` and ``domain_password`` credential will be used for all connections unless there is an explicit server entry in ``domain_credentials``.
