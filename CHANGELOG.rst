================================================
Ansible Microsoft Active Directory Release Notes
================================================

.. contents:: Topics


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
