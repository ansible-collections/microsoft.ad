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

* ``ansible.windows.win_domain`` -> ``microsoft.ad.domain`` - :ref:`see here <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain>`
* ``ansible.windows.win_domain_controller`` -> ``microsoft.ad.domain_controller`` - :ref:`see here <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_controller>`
* ``ansible.windows.win_domain_membership`` -> ``microsoft.ad.membership`` - :ref:`see here <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_membership>`
* ``community.windows.win_domain_computer`` -> ``microsoft.ad.computer`` - :ref:`see here <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_computer>`
* ``community.windows.win_domain_object_info`` -> ``microsoft.ad.object_info`` - :ref:`see here <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_object_info>`
* ``community.windows.win_domain_ou`` -> ``microsoft.ad.ou`` - :ref:`see here <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_ou>`
* ``community.windows.win_domain_user`` -> ``microsoft.ad.user`` - :ref:`see here <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_user>`

While these modules are mostly drop in place compatible there are some breaking changes that need to be considered. See each module entry for more information.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain:

Module ``win_domain``
---------------------

There are no known breaking changes and should work as a drop in replacement. The ``reboot`` option has been added to have the module handle any reboots that are needed instead of a separate ``ansible.windows.win_reboot`` task. Due to the operations involved with promoting a domain controller, it is highly recommended to use this option.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_controller:

Module ``win_domain_controller``
--------------------------------

The following options have been removed:

* ``log_path`` - Creating a debug log of module actions is not supported

The ``reboot`` option has been added to have the module handle any reboots instead of a separate ``ansible.windows.win_reboot`` task. Due to the operations involved with promoting a domain controller, it is highly recommended to use this option.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_membership:

Module ``win_domain_membership``
--------------------------------

The following options have been removed:

* ``log_path`` - Creating a debug log of module actions is not supported

The ``reboot`` option has been added to have the module handle any reboots instead of a separate ``ansible.windows.win_reboot`` task.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_computer:

Module ``win_domain_computer``
------------------------------

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

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_object_info:

Module ``win_domain_object_info``
---------------------------------

There are no known breaking changes and should work as a drop in replacement.

.. _ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_ou:

Module ``win_domain_ou``
------------------------

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

The following options have changed:

* ``attributes`` - changed format as outlined in :ref:`Attributes guid <ansible_collections.microsoft.ad.docsite.guide_attributes>`
* ``groups_action`` - ``replace`` has been renamed to ``set``
* ``spn_action`` - ``replace`` has been renamed to ``set``
* ``state`` - No query option - use ``microsoft.ad.object_info`` instead
* ``enabled`` - Does not default to ``true``. Creating a new user without a password will use ``enable=false`` but setting a password will use ``enable=true``

The ``groups_action`` and ``spn_action`` ``set`` value was renamed to align with common practice. The ``state=query`` functionality has been removed to simplify the module and favour ``microsoft.ad.object_info`` which is designed to return information about AD objects. The ``enabled`` default was removed to allow setting other attributes on an existing AD object without always having to specify ``enabled``.

The return values for ``win_domain_user`` have also been simplified to only return:

* ``distinguished_name`` - The Distinguished Name (``DN``) of the managed user
* ``object_guid`` - The Object GUID of the managed user
* ``sid`` - The Security Identifier of the managed user

All other return values have been removed, use ``microsoft.ad.object_info`` to get extra values if needed.
