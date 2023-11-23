================================================
Ansible Microsoft Active Directory Release Notes
================================================

.. contents:: Topics


v1.4.1
======

Release Summary
---------------

Release summary for v1.4.1

Bugfixes
--------

- debug_ldap_client - handle failures when attempting to get the krb5 context and default CCache rather than fail with a traceback

v1.4.0
======

Release Summary
---------------

Prepare for v1.4.0 release

Minor Changes
-------------

- Make ``name`` an optional parameter for the AD modules. Either ``name`` or ``identity`` needs to be set with their respective behaviours. If creating a new AD user and only ``identity`` is set, that will be the value used for the name of the object.
- Set minimum supported Ansible version to 2.14 to align with the versions still supported by Ansible.
- object_info - Add ActiveDirectory module import

v1.3.0
======

Release Summary
---------------

release summary for v1.3.0

Minor Changes
-------------

- AD objects will no longer be moved to the default AD path for their type if no ``path`` was specified. Use the value ``microsoft.ad.default_path`` to explicitly set the path to the default path if that behaviour is desired.
- microsoft.ad.ldap - Added the option ``filter_without_computer`` to not add the AND clause ``objectClass=computer`` to the final filter used - https://github.com/ansible-collections/microsoft.ad/issues/55

Bugfixes
--------

- Added the missing dependency ``dpapi-ng`` to Ansible Execution Environments requirements file for LAPS decryption support
- Ensure renaming and moving an object will be done with the ``domain_server`` and ``domain_username`` credentials specified - https://github.com/ansible-collections/microsoft.ad/issues/54
- Fix up ``protect_from_deletion`` when creating new AD objects - https://github.com/ansible-collections/microsoft.ad/issues/47
- Fix up date_time attribute comparisons to be idempotent - https://github.com/ansible-collections/microsoft.ad/issues/57
- microsoft.ad.user - Ensure the ``spn`` diff after key is ``spn`` and not ``kerberos_encryption_types``
- microsoft.ad.user - treat an expired account as a password that needs to be changed

v1.2.0
======

Release Summary
---------------

Release summary for v1.2.0

Minor Changes
-------------

- microsoft.ad.debug_ldap_client - Add ``dpapi_ng`` to list of packages checked
- microsoft.ad.ldap - Add support for decrypting LAPS encrypted password
- microsoft.ad.ldap - Allow setting LDAP connection and authentication options through environment variables - https://github.com/ansible-collections/microsoft.ad/issues/34

Deprecated Features
-------------------

- Deprecating support for Server 2012 and Server 2012 R2. These OS versions are reaching End of Life status from Microsoft and support for using them in Ansible are nearing its end.

Bugfixes
--------

- group - Fix idempotency check when ``scope: domainlocal`` is set - https://github.com/ansible-collections/microsoft.ad/issues/31
- microsoft.ad.group - ensure the ``scope`` and ``category`` values are checked as case insensitive to avoid changes when not needed - https://github.com/ansible-collections/microsoft.ad/issues/31

v1.1.0
======

Release Summary
---------------

This release includes the new ``microsoft.ad.ldap`` inventory plugin which can be used to generate an Ansible
inventory from an LDAP/AD source.


Bugfixes
--------

- microsoft.ad.user - Fix setting ``password_expired`` when creating a new user - https://github.com/ansible-collections/microsoft.ad/issues/25

New Plugins
-----------

Filter
~~~~~~

- as_datetime - Converts an LDAP value to a datetime string
- as_guid - Converts an LDAP value to a GUID string
- as_sid - Converts an LDAP value to a Security Identifier string

Inventory
~~~~~~~~~

- ldap - Inventory plugin for Active Directory

New Modules
-----------

- debug_ldap_client - Get host information for debugging LDAP connections

v1.0.0
======

Release Summary
---------------

This is the first release of the ``microsoft.ad`` Ansible collection which contains modules that can be used to managed a Microsoft Active Directory environment.
