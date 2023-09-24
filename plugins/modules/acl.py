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
    description: The rights/permissions that are to be allowed/denied for the object.
    type: str
    required: yes
  rights_attr:
    description: The attribute that the rights are to be allowd/denied for.
    type: str
  type:
    description: Specify whether to allow or deny the rights specified.
    type: str
    choices: [ allow, deny ]
    required: yes
  inherit:
    description: Inherit flags on the ACL rules.
    type: str
    default: None
  state:
    description: Specify whether to add C(present) or remove C(absent) the specified access rule.
    type: str
    choices: [ absent, present ]
    default: present
author:
  - Mikael Olofsson (@quiphius)
'''

EXAMPLES = r'''
- name: Set the C(Manager can update membership list) in the C(Managed By) tab
  win_domain_acl:
    object: "CN=System Administrators,OU=MyDomain,DC=domain,DC=test"
    principal: System Administrators
    rights: WriteProperty
    rights_attr: member
    type: allow
'''
