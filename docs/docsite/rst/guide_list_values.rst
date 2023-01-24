.. _ansible_collections.microsoft.ad.docsite.guide_list_values:

********************************
Setting list option values guide
********************************

Some AD options accept multiple values which require special rules when it comes to checking for idempotency in Ansible. This collection has been designed so that each of the modules which manage AD objects follow the same style when it comes to their options. In particular, they should all follow the style documented in this guide when it comes to options that contain multiple values like ``spn``, ``delegates``, etc.

.. contents::
  :local:
  :depth: 1

.. _ansible_collections.microsoft.ad.docsite.guide_list_values.something:

Add, remove, and set
====================

For each module option that manage a multi valued LDAP attribute there exists three actions:

* ``add``
* ``remove``
* ``set``

The ``add`` and ``remove`` option will add or remove the specified value(s) from the existing value. The ``set`` option will replace the existing values with what was specified in the task.
Using an example of an AD object with the following ``servicePrincipalNames`` values:

* ``HTTP/host1``
* ``HTTP/host1.domain.com``
* ``HTTP/host1.domain.com:443``

Doing ``add: ['HTTP/host1','HTTP/host2']`` will add ``HTTP/host2`` to the existing values bringing it to:

* ``HTTP/host1``
* ``HTTP/host1.domain.com``
* ``HTTP/host1.domain.com:443``
* ``HTTP/host2``

Doing ``remove: ['HTTP/host1','HTTP/host3']`` will remove ``HTTP/host1`` from the existing values bringing it to:

* ``HTTP/host1.domain.com``
* ``HTTP/host1.domain.com:443``

Doing ``set: ['HTTP/host1', 'HTTP/host2']`` will remove any values not in that list and add values in that list but not set bringing it to:

* ``HTTP/host1``
* ``HTTP/host2``

It is possible to use ``add`` and ``remove`` together but setting ``set`` will always take precedence over the others.
It is also possible to clear all the existing values by setting the ``set`` value to an empty list, for example ``set: []``.

Examples
========

The ``add``, ``remove``, and ``set`` options are subkeys of the module option it controls. For example the :ref:`microsoft.ad.user <ansible_collections.microsoft.ad.user_module>` has an option called ``groups`` which control the list of groups the user is a member of. To add a group to the user, simply use the ``add`` key like so:

.. code-block:: yaml

  - name: add a user to a group
    microsoft.ad.user:
      name: MyUser
      groups:
        add:
        - Group 1
        - Group 2

This will ensure the user is added to the groups ``Group 1`` and ``Group 2`` while also preserving the existing membership. To remove a user from a user, simple use the ``remove`` key like so:

.. code-block:: yaml

  - name: remove a user from a group
    microsoft.ad.user:
      name: MyUser
      groups:
        remove:
        - Group 1
        - Group 2

This does the opposite to add and will remove the user from ``Group 1`` and ``Group 2`` but it will still preserve any existing group memberships of that user. It is also possible to combine ``add`` and ``remove`` together:

.. code-block:: yaml

  - name: add and remove user groups
    microsoft.ad.user:
      name: MyUser
      groups:
        add:
        - Group 1
        remove:
        - Group 2

This will ensure the user is a member of ``Group 1`` and is not a member of ``Group 2``. Like before it will not touch the existing group membership if they are not specified.

The set option following the same format like so:

.. code-block:: yaml

  - name: set user groups
    microsoft.ad.user:
      name: MyUser
      groups:
        set:
        - Group 1
        - Group 2

This will ensure the user is only members of ``Group 1`` and ``Group 2``, removing any other group not in that list. While it is possible to combine ``set`` with either ``add`` or ``remove``, the module will completely ignore the values in ``add`` or ``remove``.

Finally to remove a user from all groups, use an empty list for the ``set`` option like so:

.. code-block:: yaml

  - name: remove user groups
    microsoft.ad.user:
      name: MyUser
      groups:
        set: []

.. note::
  This is not actually possible for user groups as it will always be a member of its primary group, it is just used for demonstration purposes.
