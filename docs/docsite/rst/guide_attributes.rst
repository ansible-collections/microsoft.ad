.. _ansible_collections.microsoft.ad.docsite.guide_attributes:

****************
Attributes guide
****************

A common use case for modules in this collection is to manage various Active Directory objects, such as users, groups, computers, and more. Some of these options are exposed as direct module options but other attributes might need to be set through the ``attributes`` option common to most modules in this collection.

.. contents::
  :local:
  :depth: 1

.. _ansible_collections.microsoft.ad.docsite.guide_attributes.ldap_attributes:

LDAP Attributes
===============

One core component of Microsoft's Active Directory (``AD``) is a Lightweight Directory Access Protocol (``LDAP``) database. This database contains all the information relevant to an AD environment such as users, computers, organizational units, and more. Each object contains a dynamic set of attributes to describe the object and conform to a schema. For example users contain attributes like ``firstName``, ``country``, ``sAMAccountName`` to describe the object itself. Microsoft document all the builtin attributes in AD in their `AD Attribute Schema <https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all>`_. For example the `SAM-Account-Name attribute <https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccountname>`_ contains the metadata around this attribute. It includes fields like:

* ``Ldap-Display-Name`` - The LDAP display name
* ``Syntax`` - The underlying value type that the attribute stores
* ``System-Only`` - Whether the attribute is set by the system, effectively making it read only
* ``Is-Single-Value`` - Whether the attribute value is a single value or an array/list of values

The ``Ldap-Display-Name`` is the attribute name/key that is referenced by the Ansible module. For example to manage the ``SAM-Account-Name`` attribute, it would be referenced by the key ``sAMAccountName``. Each attribute has at least 1 value associated with it, but some attributes can have multiple values. For example ``sAMAccountName`` is a ``Is-Single-Value`` attribute so only has one value but ``userCert`` can contain multiple values. The ``Active Directory Users and Computers`` snap-in (or ``dsa.msc``) can be used to view these LDAP attributes in the advanced mode. This is useful for seeing existing values as well as what attributes can be set on an object.

The LDAP schema in AD can also be extended to add custom attributes for an organization. These custom attributes are also supported in the modules in this collection. To get the LDAP schema information for attributes, the following can be run in PowerShell:

.. code-block:: PowerShell

    Function Get-AttributeMetadata {
        [CmdletBinding()]
        param ([Parameter(ValueFromPipeline)][string[]]$Name)

        begin {
            $schema = (Get-ADRootDSE -Properties subschemaSubentry).subschemaSubentry
            $getParams = @{
                SearchBase = $schema
                LDAPFilter = '(objectClass=*)'
                Properties = 'attributeTypes'
            }
            $attributes = (Get-ADObject @getParams).attributeTypes
            $queried = $false
        }

        process {
            foreach ($n in $Name) {
                $queried = $true
                $attributes | Where-Object {
                    $_ -like "*Name '$n'*"
                }
            }
        }

        end {
            if (-not $queried) {
                $attributes
            }
        }
    }

    # Display all attributes
    Get-AttributeMetadata

    # Get specific attributes
    Get-AttributeMetadata -Name sAMAccountName, o, objectGuid

The output is in the format::

    ( $ATTRIBUTE_OID NAME '$ATTRIBUTE_NAME' SYNTAX '$TYPE_OID' [SINGLE-VALUE|NO-USER-MODIFICATION] )

The ``$TYPE_OID`` specifies the value type that can be used for this attribute. search the OID online for more information. The ``SINGLE-VALUE`` specifies if the attribute can only store 1 value. The ``NO-USER-MODIFICATION`` specifies if the attribute is read only and cannot be set.

The last example outputs::

    ( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )
    ( 2.5.4.10 NAME 'o' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
    ( 1.2.840.113556.1.4.2 NAME 'objectGUID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE NO-USER-MODIFICATION )

This shows the ``sAMAccountName`` is a string that can only have 1 value. The ``o`` attribute is also a string but can store multiple values. The ``objectGUID`` is a byte array value that can only have 1 value and is also read only.

.. _ansible_collections.microsoft.ad.docsite.guide_attributes.setting_attributes:

Setting Attributes
==================

Each module that manages an Active Directory object will have an ``attributes`` option which is used to configure LDAP attributes directly. The dictionary accepts three keys:

* ``add`` - Adds the attribute values if not present
* ``remove`` - Removes the attribute values if present
* ``set`` - Replaces the existing attribute values with the ones specified.

Each of these keys contain a dictionary value where the keys are the LDAP attribute names by ``ldapDisplayName`` and their values to set. As an LDAP attribute can contain multiple values, the values specified can either be a single value or a list of values, for example:

.. code-block:: yaml

    - microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          set:
            comment: My Comment
            extensionName:
            - Extension Value 1
            - Extension Value 2
            - Extension Value 3

The above example will set the ``comment`` LDAP attribute of the ``MyUser`` object to the value specified. It will also ensure the ``extensionName`` attribute is set to those three values, removing any other value if present.

The ``add`` key can be used to ensure the LDAP attribute values specified are added to the Attribute value list. The opposite is true for attributes under the ``remove`` key. Any attributes there will have the values specified removed if they are present on the attribute in question. For example:

.. code-block:: yaml

    - microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          add:
            extensionName:
            - Extension Value 1
            - Extension Value 3
          remove:
            extensionName:
            - Extension Value 2

The above example will ensure the ``extensionName`` has the values ``Extension Value 1``, ``Extension Value 3`` and remove ``Extension Value 2`` if it is set. Because ``set`` was not used, any existing values will not be touched unless they are in the ``remove`` entry.

.. note::
    Only use LDAP attributes that can contain multiple values with ``add`` or ``remove``. Using a ``Is-Single-Value`` attribute will result in undefined behaviour.

To clear an attribute value, define the attribute under ``set`` and set the value to either null (``~``) or an empty list. For example

.. code-block:: yaml

    - microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          set:
            # Null can either be represented by no value
            # or with tilde (~)
            comment: ~
            company:
            extensionName: []

This task will ensure the ``comment``, ``company``, and ``extensionName`` attributes are cleared of any value.

.. _ansible_collections.microsoft.ad.docsite.guide_attributes.attribute_types:

Attribute Types
===============

There are a few different value types that can be stored in an attribute.
The common types are:

* Strings
* Integers
* Booleans
* Byte Arrays
* Dates
* Security Descriptors

Setting a string, integer, or boolean value through an Ansible task is simply done through the YAML syntax, for example:

.. code-block:: yaml

    string: This is a string
    integer: 1
    boolean: true

.. note::
    Strings are compared in a case sensitive operation, that is ``"String" != "string"``.

These simple types can also be represented by a dictionary with the keys ``type`` and ``value``. The type key can be set to one of the following:

* ``bool`` - Value is casted to a boolean
* ``bytes`` - Value is decoded as a base64 string
* ``date_time`` - Value is decoded as an ISO 8601 datetime string
* ``int`` - Value is decoded as an integer
* ``security_descriptor`` - Value is decoded as a SDDL string
* ``string`` - Value is casted to a string
* ``raw`` - Value is used as is - this is the default type used

This looks like the following:

.. code-block:: yaml

    - microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          set:
            # comment: A raw value that is a string
            comment:
              type: raw
              value: A string

            # userAccountControl: 1234
            userAccountControl:
              type: int
              value: 1234

            # extensionName: ['Value 1', 'Value 2']
            extensionName:
            - type: raw
              value: Value 1
            - type: raw
              value: Value 2

The complex dictionary value with the ``type`` and ``value`` structure is only really needed for the more complex types listed below. If omitted the value is treated as ``type: raw``.

Byte Arrays
-----------

As raw bytes cannot be expressed in YAML, to set an attribute with a byte array value the following format is used:

.. code-block:: yaml

    - microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          set:
            # Attribute with single value
            dsaSignature:
              type: bytes
              value: YmluYXJ5
            # Attribute with multiple values
            userCertificate:
            - type: bytes
              value: Zm9vYmFy
            - type: bytes
              value: YmFyZm9v

The value specified here is the bytes encoded as a base64 string.

The :ref:`ansible.builtin.b64encode filter <ansible_collections.ansible.builtin.b64encode_filter>` can be used to encode strings on the fly, and the :ref:`ansible.builtin.file lookup <ansible_collections.ansible.builtin.file_lookup>` could be used to read data from a file.


.. code-block:: yaml

    - vars:
        sig_data: "{{ lookup('ansible.builtin.file', '/path/to/my/sig') }}"
      microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          set:
            # Attribute with single value
            dsaSignature:
              type: bytes
              value: "{{ sig_data | ansible.builtin.b64encode }}"


Dates
-----

Attributes with datetime values are technically integer values but represent a point in time. For ease of use, these entries can be represented as an ISO 8601 extended format datetime and will be internally represented by the integer value. To specify an attribute value in the datetime format, use the same dictionary value structure as above but set the ``type`` to ``date_time``. For example:

.. code-block:: yaml

    - microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          set:
            dateAttributeSingleValue:
              type: date_time
              value: '2019-09-07T15:50:00+00:00'
            dateAttributeMultipleValue:
            - type: date_time
              value: '2019-09-07T15:50:00Z'
            - type: date_time
              value: '2019-09-07T11:50:00-04:00'

Internally the datetime is converted to the UTC time and converted to the number of 100 nanosecond increments since 1601-01-01. This PowerShell snippet shows what is happening internally to get the integer value:

.. code-block:: PowerShell

    $dt = '2019-09-07T15:50:00Z'
    $dtVal = [DateTimeOffset]::ParseExact(
        $dt,
        [string[]]@("yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"),
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal)
    $dtVal.UtcDateTime.ToFileTimeUtc()

.. note:: If no timezone is specified, it is assumed to be in UTC.

Security Descriptors
--------------------

A security descriptor is stored as a byte array in the attribute but the ``security_descriptor`` type can be used to more conveniently represent this value in a playbook. The value specified is the `Security Descriptor Definition Language <https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language>`_ (``SDDL``). This string is internally converted to the byte array needed to set the SDDL. An example of setting an attribute of this type is:

.. code-block:: yaml

    - microsoft.ad.user:
        name: MyUser
        state: present
        attributes:
          set:
            nTSecurityDescriptor:
              type: security_descriptor
              value: O:DAG:DAD:PAI(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)

SDDL strings can be quite complex so building them manually is ill-advised. It is recommended to build a test object in the ``Active Directory Users and Computers`` snap-in (or ``dsa.msc``) and set the security as needed in the ``Security`` tab. From there the SDDL string can be retrieved by doing the following:

.. code-block:: PowerShell

    $dn = 'CN=ObjectName,DC=domain,DC=test'
    $obj = Get-ADObject -Identity $dn -Properties nTSecurityDescriptor
    $obj.nTSecurityDescriptor.GetSecurityDescriptorSddlForm('All')

.. _ansible_collections.microsoft.ad.docsite.guide_attributes.dn_lookup_attributes:

DN Lookup Attributes
====================

Some attributes in Active Directory are stored as a Distinguished Name (``DN``) value that references another AD object. Some modules expose a way to lookup the DN using a more human friendly value, such as ``managed_by``. These option values must either be a string or a dictionary with the key ``name`` and optional key ``server``. The string value or the value of ``name`` is the identity to lookup while ``server`` is the domain server to lookup the identity on. The lookup identity value can be specified as a ``distinguishedName``, ``objectGUID``, ``objectSid``, ``sAMAccountName``, or ``userPrincipalName``. The below is an example of how to lookup a DN using the ``sAMAccountName`` using a string value or in the dictionary form:

.. code-block:: yaml

    - name: Find managed_by using string value
      microsoft.ad.group:
        name: My Group
        scope: global
        managed_by: Domain Admins

    - name: Find managed_by using dictionary value with a server
      microsoft.ad.group:
        name: My Group
        scope: global
        managed_by:
          name: Domain Admins
          server: OtherDC

There are also module options that can set a list of DN values for an attribute. The list values for these options are the same as the single value attributes where each DN lookup is set as a string or a dictionary with the ``name`` and optional ``server`` key.

.. code-block:: yaml

    - name: Specify a list of DNs to set
      microsoft.ad.computer:
        identity: TheComputer
        delegates:
          set:
          - FileShare
          - name: ServerA
            server: OtherDC

For list attributes with the ``add/remove/set`` subkey options, the ``lookup_failure_action`` option can also be set to ``fail`` (default), ``ignore``, or ``warn``. The ``fail`` option will fail the task if any of the lookups fail, ``ignore`` will ignore any invalid lookups, and ``warn`` will emit a warning but still continue on a lookup failure.

.. code-block:: yaml

    - name: Specify a list of DNs to set - ignoring lookup failures
      microsoft.ad.computer:
        identity: TheComputer
        delegates:
          lookup_failure_action: ignore
          set:
          - FileShare
          - MissingUser

When a ``server`` key is provided, the lookup will be done using the server value specified. It is possible to also provide explicit credentials just for that server using the ``domain_credentials`` option.

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
        domain_credentials:
        - username: UserForDefaultDC
          password: PasswordForDefaultDC
        - name: OtherDC
          username: UserForOtherDC
          password: PasswordForOtherDC

In the above, the ``GroupOnOtherDC`` will be done with ``OtherDC`` with the username ``UserForOtherDC``.

The documentation for the module option will identify if the option supports the lookup behaviour or whether a DN value must be explicitly provided.
