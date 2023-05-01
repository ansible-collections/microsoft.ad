.. _ansible_collections.microsoft.ad.docsite.guide_ldap_inventory:

********************
LDAP Inventory guide
********************

This guide covers information about the LDAP inventory plugin included in this collection. This inventory plugin can be used to build an inventory from an LDAP server source, like Microsoft Active Directory.

.. contents::
  :local:
  :depth: 1

.. _ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.connection_info:

Connection info
===============

Details on how to configure an LDAP connection can be found under :ref:`the LDAP connection guide <ansible_collections.microsoft.ad.docsite.guide_ldap_connection>`. Each of the connection options described by the plugin documentation are specified in the inventory yml configuration file like the below.

.. code-block:: yaml

    plugin: microsoft.ad.ldap

    # LDAP connection options can be defined in the yaml config.
    auth_protocol: simple
    username: UserName
    password: MyPassword123
    tls_mode: ldaps


.. _ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.attributes:

Attributes
==========

The LDAP inventory plugin can be used to set custom facts for each host it retrieves based on the computer object's LDAP attributes. Retrieving custom attributes is done through the ``attributes`` option in the inventory plugin definition. The value is set to one of the three following types:

* Empty string or null
* A template string
* A dictionary

.. note::
    While an individual attribute can only be set to one of these types, it is possible to use the different value types for different attributes.

It is also possible to use the ``compose`` inventory option to use the builtin compose templating provided by inventory plugins but the LDAP attributes must first be requested through the ``attributes`` option and referenced in the ``compose`` template through the host fact the ``attributes`` set it on.

Empty string or null
--------------------

.. code-block:: yaml

    attributes:
      comment:
      objectSid: ''
      ms-Mcs-AdmPwd:

In this case each of the attribute values will be set as a host fact as they are coerced by the LDAP schema, see :ref:`value types and templating <ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.value_types>`. The name of each fact will be based on the attribute name with ``-`` being replaced by ``_``. In the above example the host facts ``comment``, ``objectSid``, and ``ms_Mcs_AdmPwd`` will be set to the coerced values.

.. code-block:: yaml

    # ansible-inventory -i microsoft.ad.ldap.yml --host MYHOST --vars --yaml

    ansible_host: MYHOST.domain.com
    comment: test comment
    ms_Mcs_AdmPwd: Password123!
    objectSid: S-1-5-21-1234-1108
    microsoft_ad_distinguished_name: CN=MYHOST,CN=Computers,DC=domain,DC=com


Template string
---------------

.. code-block:: yaml

    attributes:
      comment: this
      objectSid: raw | microsoft.ad.as_sid
      ms-Mcs-AdmPwd: raw | first

This format will set the host fact based on the template value specified. Each template is implicitly wrapped with ``{{ ... }}`` and processed through Jinja2 to produce a result. This means the template string can contain filters provided by Ansible and other collections to convert the raw LDAP value into something more useful. The ``this`` variable refers to the coerced LDAP attribute value and ``raw`` refers to a list of base64 encoded byte strings of the raw LDAP attribute value. See :ref:`value types and templating <ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.value_types>` for more information around what can be done inside the templates. Each host fact will be named after the attribute name with ``-`` being replaced by ``_``. In the above example the host facts ``command``, ``objectSid``, and ``ms_Mcs_AdmPwd`` will be set to the template results.

.. code-block:: yaml

    # ansible-inventory -i microsoft.ad.ldap.yml --host MYHOST --vars --yaml

    ansible_host: MYHOST.domain.com
    comment: test comment
    ms_Mcs_AdmPwd: UGFzc3dvcmQxMjMh
    objectSid:
    - S-1-5-21-1234-1108
    microsoft_ad_distinguished_name: CN=MYHOST,CN=Computers,DC=domain,DC=com


Dictionary
----------

.. code-block:: yaml

    attributes:
      comment:
        # Jinja2 native types will automatically convert this to a dict as
        # the value is a json string.
        my_comment:
        other_var: this | from_json
      objectSid:
        sid: raw | microsoft.ad.as_sid | first
      ms-Mcs-AdmPwd:
        ansible_password: this

The final value that can be set on each attribute values is a dictionary where the keys are the host facts to set and the value is the template used to dervice the final value. It can be null or an empty string to refer to the LDAP coerced value of that attribute (``this``) or a template string to template a new value based on the requirements at hand. See the above two formats for more info on null/empty string vs a string template value. In the above example there are 4 host facts set:

* ``my_command`` - the coerced value for the ``comment`` attribute
* ``other_var`` - a dictionary created from the coerced value of ``comment`` if it was a json string
* ``sid`` - the computer SID value as a string derived from ``objectSid``
* ``ansible_password`` - the LAPS password coerced value derived from ``ms-Mcs-AdmPwd``

.. code-block:: yaml

    # ansible-inventory -i microsoft.ad.ldap.yml --host MYHOST --vars --yaml

    ansible_host: MYHOST.domain.com
    ansible_password: Password123!
    my_comment:
      foo: bar
    other_var:
      foo: bar
    sid: S-1-5-21-1234-1108
    microsoft_ad_distinguished_name: CN=MYHOST,CN=Computers,DC=domain,DC=com

.. note::
    The host fact names are used literally, there are no conversions from ``-`` to ``_`` when using this format.


.. _ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.inventory_hostname:

Inventory hostname
==================

By default the ``inventory_hostname`` for a found host will be based on the ``name`` LDAP attribute value. If the ``dNSHostName`` attribute is set for the computer account found, it will be set as the ``ansible_host`` fact. To define a custom ``inventory_hostname`` or ``ansible_host`` either set it in the ``attributes`` or ``compose`` plugin option under that key. For example this will set the ``inventory_hostname`` to the value of ``sAMAccountName`` without the ending ``$`` rather than the computer account LDAP ``name`` attribute.

.. code-block:: yaml

    attributes:
      sAMAccountName:
      inventory_hostname: sAMAccountName[:-1]

.. code-block:: yaml

    # ansible-inventory -i microsoft.ad.ldap.yml --host MYHOST --vars --yaml

    ansible_host: MYHOST.domain.com
    microsoft_ad_distinguished_name: CN=OtherName,CN=Computers,DC=domain,DC=com
    sAMAccountName: MYHOST$


It is also possible to set ``inventory_hostname`` under the ``compose`` key. The following will produce the same output as the above.

.. code-block:: yaml

    attributes:
      sAMAccountName:

    compose:
      inventory_hostname: sAMAccountName[:-1]


An example of setting a custom ``ansible_host`` fact that is used as the connection host but leaving the default ``inventory_hostname`` of the computer account name is:

.. code-block:: yaml

    attributes:
      sAMAccountName:
      ansible_host: sAMAccountName[:-1]


.. _ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.value_types:

Value types and templating
==========================

Each LDAP attribute value is stored as a list of bytes but the schema supplied in the LDAP database can describe how those raw list of bytes are represented as a proper type, like a string, integer, boolean, etc. Currently only these four types are used when coercing LDAP attribute values

* Booleans
* Integers
* Bytes
* Strings

Booleans, integers, and strings are coerced into those specific Python types but bytes are coerced into a base64 string encoding of those bytes.

.. note::
    The ``objectGuid`` and ``objectSid`` attributes are always coerced into strings representing the security identifier and guid respectively. These are the only attributes that have special coercion rules outside of the LDAP schema syntax.

LDAP attribute values may also be marked as a a single or multi valued attribute. A single value contains just the coerced value, or ``None/null`` if it has not been set while a multi valued attribute will be set as a list of coerced values. For example the ``comment`` is a single valued string while ``servicePrincipalName`` is a multi valued string. Using this inventory configuration that requests ``comment``, and ``servicePrincipalName`` we get the following inventory host definition:

.. code-block:: yaml

    plugin: microsoft.ad.ldap

    attributes:
      comment:
      servicePrincipalName:


.. code-block:: yaml

    # ansible-inventory -i microsoft.ad.ldap.yml --host MYHOST --vars --yaml

    ansible_host: MYHOST.domain.com
    comment: test comment
    servicePrincipalName:
    - WSMAN/MYHOST
    - WSMAN/MYHOST.domain.com
    - TERMSRV/MYHOST
    - TERMSRV/MYHOST.domain.com
    - RestrictedKrbHost/MYHOST
    - HOST/MYHOST
    - RestrictedKrbHost/MYHOST.domain.com
    - HOST/MYHOST.domain.com
    microsoft_ad_distinguished_name: CN=MYHOST,CN=Computers,DC=domain,DC=com

Some attributes like ``pwdLastSet`` are typically represented as a datetime value but internally are stored as integers. As there is no metadata in the LDAP schema to denote these integer values as datetime objects they will only be coerced into integer values by default.

The following filters can be used as an easy way to further convert the coerced values into something more readable:

* :ref:`microsoft.ad.as_datetime <ansible_collections.microsoft.ad.as_datetime_filter>`
* :ref:`microsoft.ad.as_guid <ansible_collections.microsoft.ad.as_guid_filter>`
* :ref:`microsoft.ad.as_sid <ansible_collections.microsoft.ad.as_sid_filter>`

An example of these filters being used in the ``attributes`` option can be seen below:

.. code-block:: yaml

    plugin: microsoft.ad.ldap

    attributes:
      pwdLastSet:
        password_last_set_int: this
        password_last_set_datetime: this | microsoft.ad.as_datetime

.. code-block:: yaml

    # ansible-inventory -i microsoft.ad.ldap.yml --host MYHOST --vars --yaml

    ansible_host: MYHOST.domain.com
    password_last_set_datetime: 2023-02-06T07:39:09.195321+0000
    password_last_set_int: 133201427491953218
    microsoft_ad_distinguished_name: CN=MYHOST,CN=Computers,DC=domain,DC=com

The templates can also reference other filters that exist outside the collection, like the Ansible builtin ``from_json`` and more. The value is simply what would be placed inside ``{{ ... }}`` during a normal template operation.

.. note::
    Lookups cannot be used in the attribute value templates, only filters.

Each template used in the ``attributes`` inventory option can reference the following variables:

* ``this``
* ``raw``
* Any previously defined attributes

The ``this`` variable refers to the coerced LDAP attribute value while ``raw`` refers to the list of base64 encoded strings representing the raw LDAP value that hasn't been coerced. As each attribute host fact is processed, it is also available in the subsequent templates under that host fact name. Here is an example of a more complex set of attributes:

.. code-block:: yaml

    plugin: microsoft.ad.ldap

    attributes:
      objectSid:
        sid: this
        sid_raw: raw
        sid_raw_filtered: raw | microsoft.ad.as_sid | first
      objectGuid:
      sAMAccountName:
        computer_name:
      comment:
        comment: this
        # Can refer to previously set attributes above
        description: computer_name ~ " - " ~ sid ~ " - " ~ objectGuid ~ " - " ~ this

    # Can also be used as a template and refer to the vars retrieved above
    compose:
      comment2: comment

.. code-block:: yaml

    # ansible-inventory -i microsoft.ad.ldap.yml --host MYHOST --vars --yaml

    ansible_host: MYHOST.domain.com
    comment: test comment
    comment2: test comment
    computer_name: MYHOST$
    description: MYHOST$ - S-1-5-21-1234-1108 - 51cc490f-1de0-41ae-98ad-dc065d5b33e2 - test comment
    objectGuid: 51cc490f-1de0-41ae-98ad-dc065d5b33e2
    sid: S-1-5-21-1234-1108
    sid_raw:
    - AQMAAAAAAAUVAAAA0gQAAFQEAAA=
    sid_raw_filtered: S-1-5-21-1234-1108
    microsoft_ad_distinguished_name: CN=MYHOST,CN=Computers,DC=domain,DC=com
