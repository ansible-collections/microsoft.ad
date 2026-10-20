# -*- coding: utf-8 -*-
# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Behavioural tests for ``extensions/audit/event_query.yml``.

Nothing in this collection executes that file. It is read by the Automation
Platform controller (``awx/main/tasks/host_indirect.py``), which compiles the
jq and feeds it each module's result, so a defect in it is invisible from
inside this repository and silent in production -- the job stays green.

These tests therefore do the one thing a reader here can do without a
controller: run the real ``jq`` against the module's **own documented RETURN
samples**, read out of ``plugins/modules/<module>.yml``, and assert on what
comes out. Nothing here inspects the text of the query or hard-codes what AD
returns; if the module's documented return values change, these tests follow
them.
"""

from __future__ import annotations

import os

import pytest

yaml = pytest.importorskip("yaml")

COLLECTION_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..")
QUERY_FILE = os.path.join(COLLECTION_ROOT, "extensions", "audit", "event_query.yml")
MODULE_DIR = os.path.join(COLLECTION_ROOT, "plugins", "modules")


def load_queries():
    if not os.path.isfile(QUERY_FILE):
        return {}
    with open(QUERY_FILE, "rb") as handle:
        return yaml.safe_load(handle) or {}


ENTRIES = load_queries()
MODULES = sorted(ENTRIES)


def expression(module):
    """The jq text the controller compiles for ``module``."""
    entry = ENTRIES[module]
    return entry["query"] if isinstance(entry, dict) else entry


def documented_return_sample(module):
    """A result payload built from the module's own documented RETURN samples."""
    short_name = module.split(".")[-1]
    doc_file = os.path.join(MODULE_DIR, "%s.yml" % short_name)
    with open(doc_file, "rb") as handle:
        documentation = yaml.safe_load(handle) or {}
    returns = documentation.get("RETURN") or {}
    sample = {
        field: spec.get("sample")
        for field, spec in returns.items()
        if isinstance(spec, dict) and spec.get("sample") is not None
    }
    # Every module result carries this; it is also the whole payload for a
    # task that changed nothing.
    sample["changed"] = True
    return sample


def run(module, payload):
    """Compile and run the query exactly as the controller does."""
    jq = pytest.importorskip("jq", reason="jq is required to run the audit query")
    return jq.compile(expression(module)).input(payload).all()


# -- the file itself --------------------------------------------------------


def test_query_file_exists_and_declares_queries():
    assert os.path.isfile(QUERY_FILE), "%s is missing" % QUERY_FILE
    assert ENTRIES, "%s declares no queries" % QUERY_FILE


@pytest.mark.parametrize("module", MODULES)
def test_entry_is_shaped_as_the_controller_expects(module):
    """Keyed by FQCN, with a single string ``query``."""
    assert module.count(".") == 2, (
        "%r must be a fully qualified module name; the controller matches the "
        "key against the module the task ran" % module
    )
    entry = ENTRIES[module]
    assert isinstance(entry, dict), "%s: entry must be a mapping" % module
    assert set(entry) == {"query"}, "%s: expected exactly one key, 'query', got %s" % (
        module,
        sorted(entry),
    )
    assert isinstance(entry["query"], str) and entry["query"].strip(), (
        "%s: 'query' must be a non-empty string" % module
    )


@pytest.mark.parametrize("module", MODULES)
def test_query_names_a_module_in_this_collection(module):
    short_name = module.split(".")[-1]
    assert os.path.isfile(os.path.join(MODULE_DIR, "%s.yml" % short_name)), (
        "%s: no such module in this collection, so the query is dead weight "
        "the controller will never match" % module
    )


@pytest.mark.parametrize("module", MODULES)
def test_query_compiles(module):
    """The controller compiles outside its own error handling.

    ``jq.compile()`` is called in ``build_indirect_host_data`` *outside* the
    ``try/except`` that guards evaluation, so a compile error propagates into
    the caller's ``except Exception``, which sits outside the transaction
    wrapping the ``bulk_create``. One uncompilable query therefore discards
    every audit record for the whole job -- including records produced by
    every *other* collection in that job -- and reverts
    ``event_queries_processed`` with it, so the fallback task re-picks the job
    and fails the same way until it ages out.

    The shipped 1.11.0 query failed exactly this check: it read ``$data``
    without ever binding it.
    """
    jq = pytest.importorskip("jq", reason="jq is required to validate the query")
    try:
        jq.compile(expression(module))
    except Exception as exc:  # noqa: BLE001 - jq raises a bare ValueError
        raise AssertionError(
            "%s: the jq expression does not compile, so this collection "
            "reports no nodes at all and discards the audit records of every "
            "other collection in the same job.\n    %s"
            % (module, str(exc).splitlines()[0])
        )


# -- what it emits, driven by the module's documented RETURN ----------------


@pytest.mark.parametrize("module", MODULES)
def test_documented_result_emits_one_usable_record(module):
    records = run(module, documented_return_sample(module))

    assert len(records) == 1, (
        "%s: the documented return sample should count as exactly one node, "
        "got %d records" % (module, len(records))
    )
    record = records[0]

    assert isinstance(record, dict), (
        "%s: the controller iterates records and calls .get() on each; a list "
        "or scalar raises and loses the whole job's records" % module
    )
    assert record.get("name"), "%s: a record with no name cannot be saved" % module
    canonical_facts = record.get("canonical_facts")
    assert canonical_facts, (
        "%s: the controller skips any record whose canonical_facts is falsy" % module
    )
    assert all(value is not None for value in canonical_facts.values()), (
        "%s: canonical_facts is hashed to build the dedup key and "
        "get_hashable_form() raises on None, which silently discards the "
        "node: %r" % (module, canonical_facts)
    )


@pytest.mark.parametrize("module", MODULES)
def test_name_is_the_stable_identifier(module):
    """``unique_together = [('name', 'job')]``, enforced across one transaction.

    Two records that differ in ``canonical_facts`` but share a ``name`` raise
    IntegrityError, which rolls back every audit record for the job. So the
    name has to be the identifier that cannot repeat -- not a label that can.
    """
    sample = documented_return_sample(module)
    record = run(module, sample)[0]
    assert record["name"] == sample["object_guid"], (
        "%s: name should be the object GUID, which AD assigns at creation and "
        "never reuses. Got %r" % (module, record["name"])
    )


def test_an_object_recreated_at_the_same_dn_is_two_distinct_names():
    """The collision the distinguished name would have caused.

    A DN is unique in the directory at any one instant, but an object deleted
    and recreated at the same DN within a single job produces two GUIDs
    sharing one DN. Keyed on the DN that is one name for two records, and the
    job loses everything.
    """
    module = "microsoft.ad.computer"
    sample = documented_return_sample(module)
    first = run(module, sample)[0]
    recreated = dict(sample, object_guid="7b2f1c54-0000-4aaa-9bbb-ccddeeff0011")
    second = run(module, recreated)[0]

    assert first["name"] != second["name"], (
        "both incarnations emitted the name %r; one job touching both loses "
        "every audit record it produced" % first["name"]
    )


def test_a_computer_object_without_a_sid_is_still_counted():
    """The defect this query file was changed to fix.

    ``sid`` used to sit in ``canonical_facts`` behind ``// null``. Any object
    AD returns without one -- and non-security-principals have none -- hashed
    to None and was dropped on the floor, job still green. It belongs in
    ``facts``, which is not hashed.
    """
    module = "microsoft.ad.computer"
    sample = documented_return_sample(module)
    sample.pop("sid")

    records = run(module, sample)

    assert len(records) == 1, (
        "a computer object with no SID was discarded; it is a managed node "
        "and must still be counted"
    )
    assert (
        "sid" not in records[0]["canonical_facts"]
    ), "sid is back in canonical_facts, where a null discards the node"


@pytest.mark.parametrize("missing", ["object_guid", "distinguished_name"])
def test_an_incomplete_result_emits_nothing(missing):
    """No committed AD object means nothing to count.

    Emitting a partial record here would be worse than emitting none: the
    identity would be wrong, and a wrong identity is counted.
    """
    module = "microsoft.ad.computer"
    sample = documented_return_sample(module)
    sample.pop(missing)

    assert run(module, sample) == [], (
        "a result with no %s is not a committed object and must not be counted"
        % missing
    )


def test_a_task_that_returned_nothing_emits_nothing():
    """``state: absent`` and no-op tasks return little more than ``changed``."""
    assert run("microsoft.ad.computer", {"changed": True}) == []
