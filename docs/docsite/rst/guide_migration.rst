.. _ansible_collections.ansible.active_directory.docsite.guide_migration:

***************
Migration guide
***************

Some of the modules in this collection have come from the `ansible.windows collection <https://galaxy.ansible.com/ansible/windows>`_ or the `community.windows collection <https://galaxy.ansible.com/community/windows>`_. This document will go through some of the changes made to help ease the transition from the older modules to the ones in this collection.

.. contents::
  :local:
  :depth: 1

.. _ansible_collections.active_directory.docsite.guide_migration.migrated_modules:

Migrated Modules
================

The following modules have been migrated in some shape or form into this collection

* ``ansible.windows.win_domain`` -> ``ansible.active_directory.domain`` - :ref:`see here <ansible_collections.ansible.active_directory.docsite.guide_migration.migrated_modules.win_domain>`_
* ``ansible.windows.win_domain_controller`` -> ``ansible.active_directory.domain_controller`` - :ref:`see here <ansible_collections.ansible.active_directory.docsite.guide_migration.migrated_modules.win_domain_controller>`_
* ``ansible.windows.win_domain_membership`` -> ``ansible.active_directory.membership`` - :ref:`see here <ansible_collections.ansible.active_directory.docsite.guide_migration.migrated_modules.win_domain_membership>`_
* ``community.windows.win_domain_object_info`` -> ``ansible.active_directory.object_info`` - :ref:`see here <ansible_collections.ansible.active_directory.docsite.guide_migration.migrated_modules.win_domain_object_info>`_
* ``community.windows.win_domain_ou`` -> ``ansible.active_directory.ou`` - :ref:`see here <ansible_collections.ansible.active_directory.docsite.guide_migration.migrated_modules.win_domain_ou>`_
* ``community.windows.win_domain_user`` -> ``ansible.active_directory.user`` - :ref:`see here <ansible_collections.ansible.active_directory.docsite.guide_migration.migrated_modules.win_domain_user>`_

While these modules are mostly drop in place compatible there are some breaking changes that need to be considered. See each module entry for more information.

.. _ansible_collections.active_directory.docsite.guide_migration.migrated_modules.win_domain:

Module win_domain
-----------------

There are no known breaking changes and should work as a drop in replacement. The ``reboot`` option has been added to have the module handle any reboots that are needed instead of a separate ``ansible.windows.win_reboot`` task. Due to the operations involved with promoting a domain controller, it is highly recommended to use this option.

.. _ansible_collections.active_directory.docsite.guide_migration.migrated_modules.win_domain_controller:

Module win_domain_controller
----------------------------

The following options have been removed:

* ``log_path`` - Creating a debug log of module actions is not supported

The ``reboot`` option has been added to have the module handle any reboots instead of a separate ``ansible.windows.win_reboot`` task. Due to the operations involved with promoting a domain controller, it is highly recommended to use this option.

.. _ansible_collections.active_directory.docsite.guide_migration.migrated_modules.win_domain_membership:

Module win_domain_membership
----------------------------

The following options have been removed:

* ``log_path`` - Creating a debug log of module actions is not supported

The ``reboot`` option has been added to have the module handle any reboots instead of a separate ``ansible.windows.win_reboot`` task. Due to the operations involved with promoting a domain controller, it is highly recommended to use this option.

.. _ansible_collections.active_directory.docsite.guide_migration.migrated_modules.win_domain_object_info:

Module win_domain_object_info
-----------------------------

There are no known breaking changes and should work as a drop in replacement.

.. _ansible_collections.active_directory.docsite.guide_migration.migrated_modules.win_domain_ou:

Module win_domain_ou
----------------------

The following options have changed:

* ``protected`` - Has been renamed to ``protect_from_deletion`` and is now not needed to be unset for ``state: absent`` to remove the OU
* ``recursive`` - Has been removed and ``state: absent`` will also remove objects recursively
* ``filter`` - Has been removed, the ``name`` object refers to the OU name and ``identity`` can be used to select the OU by DistinguishedName or ObjectGUID if a rename or move is needed
* ``properties`` - Has been removed, use the new ``attributes`` option

The return values for ``win_domain_ou`` have also been simplified to only return:

* ``distinguished_name`` - The Distinguished Name (``DN``) of the managed OU
* ``object_guid`` - The Object GUID of the managed OU

All other return values have been removed, use ``ansible.active_directory.object_info`` to get extra values if needed.

.. _ansible_collections.active_directory.docsite.guide_migration.migrated_modules.win_domain_user:

Module win_domain_user
----------------------

The following options have changed:

* ``attributes`` - changed format as outlined in :ref:`Attributes guid <ansible_collections.ansible.active_directory.docsite.guide_attributes>`_
* ``groups_action`` - ``replace`` has been renamed to ``set``
* ``spn_action`` - ``replace`` has been renamed to ``set``
* ``state`` - No query option - use ``ansible.active_directory.object_info`` instead
* ``enabled`` - Does not default to ``true``. Creating a new user without a password will use ``enable=false`` but setting a password will use ``enable=true``

The ``groups_action`` and ``spn_action`` ``set`` value was renamed to align with common practice. The ``state=query`` functionality has been removed to simplify the module and favour ``ansible.active_directory.object_info`` which is designed to return information about AD objects. The ``enabled`` default was removed to allow setting other attributes on an existing AD object without always having to specify ``enabled``.

The return values for ``win_domain_user`` have also been simplified to only return:

* ``distinguished_name`` - The Distinguished Name (``DN``) of the managed user
* ``object_guid`` - The Object GUID of the managed user
* ``sid`` - The Security Identifier of the managed user

All other return values have been removed, use ``ansible.active_directory.object_info`` to get extra values if needed.
