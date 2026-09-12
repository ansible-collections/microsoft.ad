# -*- coding: utf-8 -*-
# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Contract tests for the indirect-node audit query file.

The query file in ``extensions/audit/`` is executable code that runs inside the
Automation Platform controller, and its output feeds subscription node counting.
Nothing else in this repository executes it, so a change to it ships with a green
CI run no matter what it does.

These tests assert the contract that ``awx/main/tasks/host_indirect.py`` actually
imposes -- not the output the query happens to produce today. That distinction is
the whole point: an assertion captured from real output agrees with that output
by construction, so it can only detect drift, never wrongness.

The contract, read off the consumer:

* ``name``            must be present and must never be null.
                      ``if name is None: continue``
* ``canonical_facts`` must be present and truthy.
                      ``if not data.get('canonical_facts'): continue``
* ``canonical_facts`` must contain no null at any depth. ``get_hashable_form()``
                      accepts int/float/str/bool/dict/list/tuple and raises
                      ``UnhashableFacts`` on anything else, including ``None``;
                      the caller catches it and skips the record. One null in one
                      field silently discards the whole node.
* ``canonical_facts`` is the *sole* dedup key -- ``results[hashable_facts]``. It
                      must therefore hold identity and nothing else. A mutable
                      field in it re-counts the same node every time it changes.
* ``facts``           must carry ``infra_type``, ``infra_bucket`` and
                      ``device_type``, normalised ``lowercase_with_underscores``.
                      A node without them is counted but cannot be bucketed, so
                      it is invisible in every rollup.

These are static checks over the query source. They need no credentials, no live
endpoint and no recorded fixture, so they run in ``ansible-test units`` on every
change and cannot be skipped by path filtering.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import re

import pytest
import yaml

# --------------------------------------------------------------------------
# Locate the query file
# --------------------------------------------------------------------------

COLLECTION_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
AUDIT_DIR = os.path.join(COLLECTION_ROOT, "extensions", "audit")
QUERY_FILE = os.path.join(AUDIT_DIR, "event_query.yml")

NORMALIZED = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*$")
TAXONOMY_KEYS = ("infra_type", "infra_bucket", "device_type")

# Field names that change over the life of a node. Anything here inside
# canonical_facts is an overcount: the same node is re-counted as a new one
# every time the value changes. These belong in `facts`, which is not hashed.
VOLATILE_KEYS = frozenset([
    "status", "state", "tags", "hostname", "ip", "ipv4", "ipv6", "lanip",
    "lan_ip", "mac", "management_ip", "managementip", "interface_ip",
    "interfaceip", "address", "power_state", "powerstate", "role", "version",
    "firmware",
])

# Stable identifiers. A display `name` alongside one of these is redundant and
# mutable -- renaming the object produces a second audit row for one node.
IDENTITY_KEYS = frozenset([
    "id", "moid", "serial", "serial_number", "object_guid", "guid", "uuid",
    "ansible_product_serial", "instance_id", "arn",
])


def load_queries():
    with open(QUERY_FILE) as handle:
        document = yaml.safe_load(handle) or {}
    return {
        key: (value["query"] if isinstance(value, dict) else value)
        for key, value in document.items()
    }


QUERIES = load_queries()
MODULES = sorted(QUERIES)


# --------------------------------------------------------------------------
# Minimal jq source handling -- brace matching, not a parser. Enough to find
# two object literals and enumerate their value expressions.
# --------------------------------------------------------------------------

def strip_comments(source):
    lines = []
    for line in source.splitlines():
        in_string = False
        for index, char in enumerate(line):
            if char == '"':
                in_string = not in_string
            elif char == "#" and not in_string:
                line = line[:index]
                break
        lines.append(line)
    return "\n".join(lines)


def balanced_block(source, start=0):
    """Return the ``{...}`` block beginning at the first brace at or after start."""
    open_at = source.find("{", start)
    if open_at < 0:
        return None, -1
    depth = 0
    in_string = False
    index = open_at
    while index < len(source):
        char = source[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_at:index + 1], index
        index += 1
    return source[open_at:], len(source)


def split_pairs(block):
    """Split a jq object literal into ``(key, value-expression)`` pairs."""
    body = block[1:-1]
    parts = []
    depth = 0
    in_string = False
    buffer_ = []
    for char in body:
        if in_string:
            buffer_.append(char)
            if char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[(":
            depth += 1
        elif char in "}])":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append("".join(buffer_))
            buffer_ = []
            continue
        buffer_.append(char)
    parts.append("".join(buffer_))

    pairs = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        depth = 0
        in_string = False
        cut = -1
        for index, char in enumerate(part):
            if in_string:
                if char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char in "{[(":
                depth += 1
            elif char in "}])":
                depth -= 1
            elif char == ":" and depth == 0:
                cut = index
                break
        if cut < 0:
            pairs.append((part.strip('"'), None))
        else:
            pairs.append((part[:cut].strip().strip('"'), part[cut + 1:].strip()))
    return pairs


def emitted_record(query):
    """The object the query emits: the last balanced block mentioning canonical_facts."""
    source = strip_comments(query)
    position = 0
    found = None
    while True:
        block, end = balanced_block(source, position)
        if block is None:
            break
        if "canonical_facts" in block:
            found = block
        position = end + 1
    return found


def sub_object(expression):
    block, _ = balanced_block(expression or "", 0)
    return dict(split_pairs(block)) if block else {}


def emitted_literals(expression):
    """String literals the expression can emit.

    Excludes arguments to test()/match()/split() and friends -- those are
    patterns being read, not taxonomy values being written.
    """
    readers = (r"\b(test|match|contains|split|startswith|endswith|ltrimstr"
               r"|rtrimstr|sub|gsub|inside)\s*\([^()]*\)")
    return re.findall(r'"([^"\\]*)"', re.sub(readers, " ", expression or ""))


PATH = re.compile(
    r"(?:\$[A-Za-z_]\w*|(?<![\w)\]\"])\.)"
    r"(?:[A-Za-z_]\w*|\[[^\]]*\])(?:\.[A-Za-z_]\w*|\[[^\]]*\])*"
)


def proven_non_null(query):
    """Paths and variables the query proves non-null before building the record."""
    source = strip_comments(query)
    proven = set()
    for match in re.finditer(r"select\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)", source):
        condition = match.group(1)
        for inner in re.finditer(
            r"\(?\s*(\$?[\w.\[\]]+)\s*(?://\s*null\s*)?\)?\s*!=\s*null", condition
        ):
            proven.add(inner.group(1))
        if re.search(r"\.\s*!=\s*null", condition):
            proven.add(".")
    for match in re.finditer(r"\(\s*(\$?[\w.\[\]]+)\s*//\s*[^)]*?\)\s*!=\s*null", source):
        proven.add(match.group(1))
    # `(.kind // "missing") as $kind` -- the variable cannot be null.
    for match in re.finditer(
        r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s+as\s+(\$[A-Za-z_]\w*)", source
    ):
        expression, variable = match.group(1), match.group(2)
        if re.search(r'//\s*("[^"]*"|\{\}|\[\]|-?\d+|true|false)\s*$', expression.strip()):
            proven.add(variable)
    for match in re.finditer(r"(\$?[\w.\[\]]+)\s+as\s+(\$[A-Za-z_]\w*)", source):
        if match.group(1) in proven:
            proven.add(match.group(2))
    return proven


def can_be_null(expression, proven):
    """True if this canonical_facts value expression can evaluate to null."""
    if expression is None:
        return True
    collapsed = " ".join(expression.split())
    if re.search(r"//\s*null\s*\)?\s*$", collapsed):
        return True                       # explicit `// null`
    if re.fullmatch(r'"[^"]*"', collapsed):
        return False                      # literal
    if re.search(r'//\s*("[^"]*"|\{\}|\[\]|-?\d+|true|false)', collapsed):
        return False                      # non-null default
    if "tostring" in collapsed or "tojson" in collapsed:
        return False                      # coerced to a string
    references = PATH.findall(collapsed)
    if not references:
        return False
    return any(reference not in proven for reference in references)


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_query_file_exists_and_parses():
    assert os.path.isfile(QUERY_FILE), "%s is missing" % QUERY_FILE
    assert QUERIES, "%s declares no queries" % QUERY_FILE


@pytest.mark.parametrize("module", MODULES)
def test_module_key_is_fully_qualified(module):
    parts = module.split(".")
    assert len(parts) == 3, (
        "'%s' is not of the form namespace.collection.module. host_indirect.py "
        "skips any key that does not split into exactly three parts, so this "
        "query would never run." % module
    )


@pytest.mark.parametrize("module", MODULES)
def test_emits_a_name_that_cannot_be_null(module):
    record = emitted_record(QUERIES[module])
    assert record is not None, "%s: could not find the emitted record object" % module
    pairs = dict(split_pairs(record))

    assert "name" in pairs, (
        "%s emits no top-level `name`. host_indirect.py does `if name is None: "
        "continue`, so every node this module reports is discarded." % module
    )
    assert not can_be_null(pairs["name"], proven_non_null(QUERIES[module])), (
        "%s: `name` can evaluate to null (%s). Give it a non-null fallback or "
        "guard the record with select()." % (module, pairs["name"])
    )


@pytest.mark.parametrize("module", MODULES)
def test_canonical_facts_is_present_and_non_empty(module):
    pairs = dict(split_pairs(emitted_record(QUERIES[module])))
    assert "canonical_facts" in pairs, (
        "%s emits no `canonical_facts`. host_indirect.py does "
        "`if not data.get('canonical_facts'): continue`." % module
    )
    assert sub_object(pairs["canonical_facts"]), (
        "%s emits an empty `canonical_facts`. An empty dict is falsy, so the "
        "record is discarded." % module
    )


@pytest.mark.parametrize("module", MODULES)
def test_no_field_in_canonical_facts_can_be_null(module):
    """The defect class that has no name in any documentation.

    ``get_hashable_form()`` raises ``UnhashableFacts`` on ``None``. The caller
    catches it and skips the record -- silently, logged once per job at INFO,
    with the job still green. A single optional field referenced without a
    fallback discards the entire node.

    Note that ``// null`` does not make a field optional. It guarantees the
    drop. If a field may be absent, either omit the key or move it to ``facts``.
    """
    query = QUERIES[module]
    pairs = dict(split_pairs(emitted_record(query)))
    proven = proven_non_null(query)
    nullable = [
        "canonical_facts.%s = %s" % (key, value)
        for key, value in sub_object(pairs.get("canonical_facts", "")).items()
        if can_be_null(value, proven)
    ]
    assert not nullable, (
        "%s: these canonical_facts fields can evaluate to null, which discards "
        "the whole record:\n    %s\nGuard the source with select(... != null), "
        "give a non-null fallback, or move the field to `facts` (not hashed)."
        % (module, "\n    ".join(nullable))
    )


@pytest.mark.parametrize("module", MODULES)
def test_canonical_facts_holds_identity_only(module):
    """canonical_facts is the sole dedup key, so anything mutable in it overcounts."""
    pairs = dict(split_pairs(emitted_record(QUERIES[module])))
    fields = sub_object(pairs.get("canonical_facts", ""))
    lowered = set(key.lower() for key in fields)

    volatile = sorted(lowered & VOLATILE_KEYS)
    assert not volatile, (
        "%s: canonical_facts contains mutable field(s) %s. canonical_facts is "
        "the only dedup key (results[hashable_facts]), so the same node is "
        "counted again every time one of these changes. Move them to `facts`, "
        "which is not hashed." % (module, ", ".join(volatile))
    )

    identifiers = sorted(lowered & IDENTITY_KEYS)
    assert not ("name" in lowered and identifiers), (
        "%s: canonical_facts contains both `name` and the stable identifier(s) "
        "%s. `name` is mutable, so renaming the object counts it as a second "
        "node. Keep the identifier, move `name` to `facts`."
        % (module, ", ".join(identifiers))
    )

    module_name = module.split(".")[-1]
    discriminators = sorted(
        key for key, value in fields.items()
        if re.fullmatch(r'"%s"' % re.escape(module_name), (value or "").strip())
    )
    assert not discriminators, (
        "%s: canonical_facts.%s is the module's own name. One physical node "
        "touched by two modules in this collection then produces two audit "
        "rows. Move it to `facts`."
        % (module, ", ".join(discriminators))
    )


@pytest.mark.parametrize("module", MODULES)
def test_facts_carry_the_full_taxonomy(module):
    pairs = dict(split_pairs(emitted_record(QUERIES[module])))
    assert "facts" in pairs, (
        "%s emits no `facts`. The node is counted but cannot be bucketed, so it "
        "is invisible in every rollup." % module
    )
    facts = sub_object(pairs["facts"])
    missing = [key for key in TAXONOMY_KEYS if key not in facts]
    assert not missing, "%s: facts is missing %s" % (module, ", ".join(missing))


@pytest.mark.parametrize("module", MODULES)
def test_taxonomy_values_are_normalized(module):
    """Assert the shape, not the value.

    An equality assertion against a captured literal cannot catch a value that
    only appears for a resource type nobody wrote a fixture for -- which is
    exactly where ``mapping[$x] // $x`` fallbacks leak raw API strings.
    """
    facts = sub_object(dict(split_pairs(emitted_record(QUERIES[module]))).get("facts", ""))
    bad = [
        "facts.%s = %r" % (key, literal)
        for key in TAXONOMY_KEYS
        for literal in emitted_literals(facts.get(key))
        if literal and not NORMALIZED.match(literal)
    ]
    assert not bad, (
        "%s: taxonomy values must match %s (lowercase_with_underscores). "
        "Unnormalised values become separate buckets downstream:\n    %s"
        % (module, NORMALIZED.pattern, "\n    ".join(bad))
    )
