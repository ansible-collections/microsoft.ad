.. _ansible_collections.microsoft.ad.docsite.guide_migration:

***************
Migration guide
***************

Some of the modules in this collection have come from the `ansible.windows collection <https://galaxy.ansible.com/ansible/windows>`_ or the `community.windows collection <https://galaxy.ansible.com/community/windows>`_. This document will go through some of the changes made to help ease the transition from the older modules to the ones in this collection.

.. contents::
  :local:
  :depth: 1

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules:

Migrated Modules
================

The following modules have been migrated in some shape or form into this collection

* ``ansible.windows.win_domain`` -> ``microsoft.ad.domain`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain>`
* ``ansible.windows.win_domain_controller`` -> ``microsoft.ad.domain_controller`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_controller>`
* ``ansible.windows.win_domain_membership`` -> ``microsoft.ad.membership`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_membership>`
* ``community.windows.win_domain_computer`` -> ``microsoft.ad.computer`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_computer>`
* ``community.windows.win_domain_group`` -> ``microsoft.ad.group`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_group>`
* ``community.windows.win_domain_group_membership`` -> ``microsoft.ad.group`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_group_membership>`
* ``community.windows.win_domain_object_info`` -> ``microsoft.ad.object_info`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_object_info>`
* ``community.windows.win_domain_ou`` -> ``microsoft.ad.ou`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_ou>`
* ``community.windows.win_domain_user`` -> ``microsoft.ad.user`` - :ref:`details <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_user>`

While these modules are mostly drop in place compatible there are some breaking changes that need to be considered. See each module entry for more information.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain:

Module ``win_domain``
---------------------

Migrated to :ref:`microsoft.ad.domain <ansible_collections.microsoft.ad.domain_module>`.

There are no known breaking changes and should work as a drop in replacement. The ``reboot`` option has been added to have the module handle any reboots that are needed instead of a separate ``ansible.windows.win_reboot`` task. Due to the operations involved with promoting a domain controller, it is highly recommended to use this option.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_controller:

Module ``win_domain_controller``
--------------------------------

Migrated to :ref:`microsoft.ad.domain_controller <ansible_collections.microsoft.ad.domain_controller_module>`.

The following options have been removed:

* ``log_path`` - Creating a debug log of module actions is not supported

The ``reboot`` option has been added to have the module handle any reboots instead of a separate ``ansible.windows.win_reboot`` task. Due to the operations involved with promoting a domain controller, it is highly recommended to use this option.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_membership:

Module ``win_domain_membership``
--------------------------------

Migrated to :ref:`microsoft.ad.membership <ansible_collections.microsoft.ad.membership_module>`.

The following options have been removed:

* ``log_path`` - Creating a debug log of module actions is not supported

The ``reboot`` option has been added to have the module handle any reboots instead of a separate ``ansible.windows.win_reboot`` task.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_computer:

Module ``win_domain_computer``
------------------------------

Migrated to :ref:`microsoft.ad.computer <ansible_collections.microsoft.ad.computer_module>`.

The option ``dns_host_name`` is not required when ``state: present``, the computer object is created without the ``dnsHostName`` LDAP attribute set if it is not defined.

The default for ``enabled`` is nothing, the group will still be enabled when created but it will use the existing status if the option is omitted.

The option ``ou`` is now named ``path`` to match the standard set by other modules.

The options ``offline_domain_join`` and ``odj_blob_path`` has been removed. Use the new module ``microsoft.ad.offline_join`` to generate the offline join blob. For example:

.. code-block:: yaml

  - name: create computer object
    microsoft.ad.computer:
      name: MyComputer
      state: present
    register: computer_obj

  - name: create offline blob
    microsoft.ad.offline_join:
      identity: '{{ computer_obj.object_guid }}'
    when: computer_obj is changed
    register: offline_blob

  - name: display offline blob
    debug:
      var: offline_blob.blob
    when: computer_obj is changed

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_group:

Module ``win_domain_group``
---------------------------

Migrated to :ref:`microsoft.ad.group <ansible_collections.microsoft.ad.group_module>`.

The following options have changed:

* ``attributes`` - changed format as outlined in :ref:`Attributes guid <ansible_collections.microsoft.ad.docsite.guide_attributes>`
* ``ignore_protection`` - Has been removed and ``state: absent`` will also remove objects regardless of the protection status
* ``organizational_unit`` and ``ou`` - Have been removed, use ``path`` instead
* ``protect`` - Has been renamed to ``protect_from_deletion`` and is now not needed to be unset for ``state: absent`` to remove the group

The return values for ``win_domain_group`` have also been simplified to only return:

* ``distinguished_name`` - The Distinguished Name (``DN``) of the managed OU
* ``object_guid`` - The Object GUID of the managed OU
* ``sid`` - The Security Identifier of the managed user

All other return values have been removed, use ``microsoft.ad.object_info`` to get extra values if needed.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_group_membership:

Module ``win_domain_group_membership``
--------------------------------------

Migrated to :ref:`microsoft.ad.group <ansible_collections.microsoft.ad.group_module>`.

The functionality of this module has been merged with ``microsoft.ad.group``. Use the ``members`` option to ``add``, ``remove``, or ``set`` to add, remove, or set group members respectively.

One change is ``win_domain_group_membership`` could specify the server to lookup the member using the ``SERVER\member-name`` format. This member format is not supported in ``microsoft.ad.group`` but since v1.6.0 of this collection the same can be achieved by using a dictionary as the member value. For example:

.. code-block:: yaml

  - name: Add a domain user/group from another Domain in the multi-domain forest to a domain group
    community.windows.win_domain_group_membership:
      name: GroupinDomainAAA
      domain_server: DomainAAA.cloud
      members:
        - DomainBBB.cloud\UserInDomainBBB
      state: present

  - name: Add a domain user/group from another Domain in the multi-domain forest to a domain group
    microsoft.ad.group:
      name: GroupinDomainAAA
      domain_server: DomainAAA.cloud
      members:
        add:
          - name: UserInDomainBBB
            server: DomainBBB.cloud
      state: present

See :ref:`DN Lookup Attributes <ansible_collections.microsoft.ad.docsite.guide_attributes.dn_lookup_attributes>` for more information.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_object_info:

Module ``win_domain_object_info``
---------------------------------

Migrated to :ref:`microsoft.ad.object_info <ansible_collections.microsoft.ad.object_info_module>`.

There are no known breaking changes and should work as a drop in replacement.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_ou:

Module ``win_domain_ou``
------------------------

Migrated to :ref:`microsoft.ad.ou <ansible_collections.microsoft.ad.ou_module>`.

The following options have changed:

* ``protected`` - Has been renamed to ``protect_from_deletion`` and is now not needed to be unset for ``state: absent`` to remove the OU
* ``recursive`` - Has been removed and ``state: absent`` will also remove objects recursively
* ``filter`` - Has been removed, the ``name`` object refers to the OU name and ``identity`` can be used to select the OU by ``DistinguishedName`` or ``ObjectGUID`` if a rename or move is needed
* ``properties`` - Has been removed, use the new ``attributes`` option

The return values for ``win_domain_ou`` have also been simplified to only return:

* ``distinguished_name`` - The Distinguished Name (``DN``) of the managed OU
* ``object_guid`` - The Object GUID of the managed OU

All other return values have been removed, use ``microsoft.ad.object_info`` to get extra values if needed.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_user:

Module ``win_domain_user``
--------------------------

Migrated to :ref:`microsoft.ad.user <ansible_collections.microsoft.ad.user_module>`.

The following options have changed:

* ``attributes`` - changed format as outlined in :ref:`Attributes guid <ansible_collections.microsoft.ad.docsite.guide_attributes>`
* ``delegates`` - changed format as outlined in :ref:`Setting list values <ansible_collections.microsoft.ad.docsite.guide_list_values>`
* ``groups`` - changed format as outlined in :ref:`Setting list values <ansible_collections.microsoft.ad.docsite.guide_list_values>`
* ``groups_action`` - has been removed in favour of the new ``groups`` format
* ``groups_missing_behaviour`` - has been moved into the ``group`` dictionary value as ``missing_behaviour``
* ``spn``- changed format as outlined in :ref:`Setting list values <ansible_collections.microsoft.ad.docsite.guide_list_values>`
* ``spn_action`` - has been removed in favour of the new ``spn`` format
* ``state`` - No query option - use ``microsoft.ad.object_info`` instead
* ``enabled`` - Does not default to ``true``. Creating a new user without a password will use ``enabled=false`` but setting a password will use ``enabled=true``

The ``groups_action`` and ``spn_action`` ``set`` value was renamed to align with common practice. The ``state=query`` functionality has been removed to simplify the module and favour ``microsoft.ad.object_info`` which is designed to return information about AD objects. The ``enabled`` default was removed to allow setting other attributes on an existing AD object without always having to specify ``enabled``.

The return values for ``win_domain_user`` have also been simplified to only return:

* ``distinguished_name`` - The Distinguished Name (``DN``) of the managed user
* ``object_guid`` - The Object GUID of the managed user
* ``sid`` - The Security Identifier of the managed user

All other return values have been removed, use ``microsoft.ad.object_info`` to get extra values if needed.
