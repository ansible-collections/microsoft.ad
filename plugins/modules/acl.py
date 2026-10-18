#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: acl
short_description: Used to set ACL's on objects in an Active Directory.
description:
  - Used to set ACL's on objects in an Active Directory.
options:
  object:
    description: The Distinguished Name of object to modify.
    type: str
    required: yes
    aliases: [ path ]
  principal:
    description: User or Group to add specified rights on the object.
    type: str
    required: yes
    aliases: [ user ]
  rights:
    description:
    - The rights/permissions that are to be allowed/denied for the object.
    - The rights can be any right under Microsoft Learn ActiveDirectoryRights
      U(https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights).
    type: str
    required: yes
  object_type:
    description:
    - The attribute or object type that the rights are to be allowd/denied for.
    - This can be any LDAP attribute or object type.
    type: str
    aliases: [ rights_attr ]
  type:
    description: Specify whether to allow or deny the rights specified.
    type: str
    choices: [ allow, deny ]
    required: yes
  inherit:
    description:
    - Inherit flags on the ACL rules.
    - For more information on the choices see Microsoft Learn ActiveDirectorySecurityInheritance
      U(https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance).
    type: str
    default: None
  inherited_object_type:
    description: The inherited attribute or object type the access rule applies on
    type: str
  state:
    description: Specify whether to add C(present) or remove C(absent) the specified access rule.
    type: str
    choices: [ absent, present ]
    default: present
author:
  - Mikael Olofsson (@quiphius)
'''

EXAMPLES = r'''
- name: Let System Adminstrators create/delete users in the MyAdmins OU
  microsoft.ad.acl:
    path: "OU=MyAdmins,DC=domain,DC=test"
    user: System Administrators
    rights: CreateChild,DeleteChild
    rights_attr: user
    type: allow

- name: Let System Adminstrators manage users in the MyAdmins OU
  microsoft.ad.acl:
    path: "CN=System Administrators,OU=MyAdmins,DC=domain,DC=test"
    user: System Administrators
    rights: GenericAll
    inherited_object_type: user
    inherit: Children
    type: allow

- name: Set the C(Manager can update membership list) in the C(Managed By) tab
  microsoft.ad.acl:
    object: "CN=System Administrators,OU=MyAdmins,DC=domain,DC=test"
    principal: System Administrators
    rights: WriteProperty
    rights_attr: member
    type: allow
'''
