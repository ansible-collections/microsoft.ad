# -*- coding: utf-8 -*-

# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment:

    # Common options for ansible_collections.ansible.active_directory.plugins.module_utils.ADAttribute
    DOCUMENTATION = r"""
options:
  attributes:
    description:
    - The attributes to either add, remove, or set on the AD object.
    - The value of each attribute option should be a dictionary where the key
      is the LDAP attribute, e.g. C(firstName), C(comment) and the value is the
      value, or list of values, to set for that attribute.
    - The attribute value(s) can either be the raw string, integer, or bool
      value to add, remove, or set on the attribute in question.
    - The value can also be a dictionary with the I(type) key set to C(bytes),
      C(date_time), C(security_descriptor), or C(raw) and the value for this
      entry under the I(value) key.
    - The C(bytes) type has a value that is a base64 encoded string of the raw
      bytes to set.
    - The C(date_time) type has a value that is the ISO 8601 DateTime string of
      the DateTime to set. The DateTime will be set as the Microsoft FILETIME
      integer value which is the number of 100 nanoseconds since 1601-01-01 in
      UTC.
    - The C(security_descriptor) type has a value that is the Security
      Descriptor SDDL string used for the C(nTSecurityDescriptor) attribute.
    - The C(raw) type is the int, string, or boolean value to set.
    - String attribute values are compared using a case sensitive match on the
      AD object being managed.
    default: {}
    type: dict
    suboptions:
      add:
        description:
        - A dictionary of all the attributes and their value(s) to add to the
          AD object being managed if they are not already present.
        - This is used for attributes that can contain multiple values, if the
          attribute only allows a single value, use I(set) instead.
        default: {}
        type: dict
      remove:
        description:
        - A dictionary of all the attributes and their value(s) to remove from
          the AD object being managed if they are present.
        - This is used for attributes that can contain multiple values, if the
          attribute only allows a single value, use I(set) instead.
        default: {}
        type: dict
      set:
        description:
        - A dictionary of all attributes and their value(s) to set on the AD
          object being managed.
        - This will replace any existing values if they do not match the ones
          being requested.
        - The order of attribute values are not checked only, only that the
          values requested are the only values on the object attribute.
        - Set this to null or an empty list to clear any values for the
          attribute.
        default: {}
        type: dict
"""
