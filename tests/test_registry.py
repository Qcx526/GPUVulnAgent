# -*- coding: utf-8 -*-
"""Registry: real parameter types, validation before dispatch, honest failures."""

from __future__ import annotations

import pytest

from gpuvulnagent.registry import ParamSpec, ToolRegistry, ToolSpec, coerce_arguments


def _spec(**overrides) -> ToolSpec:
    defaults = dict(name="probe", description="d", handler=lambda **kwargs: {"ok": True},
                    parameters=[ParamSpec("count", "integer", "how many", required=True,
                                          minimum=1, maximum=10),
                                ParamSpec("label", "string", "a label", required=False,
                                          default="x"),
                                ParamSpec("tags", "array", "tags", required=False),
                                ParamSpec("mode", "string", "mode", required=False,
                                          default="basic", enum=("basic", "advanced"))])
    defaults.update(overrides)
    return ToolSpec(**defaults)


def test_parameters_are_typed_not_all_strings():
    schema = _spec().json_schema()
    assert schema["properties"]["count"]["type"] == "integer"
    assert schema["properties"]["tags"]["type"] == "array"
    assert schema["properties"]["tags"]["items"]["type"] == "string"
    assert schema["properties"]["mode"]["enum"] == ["basic", "advanced"]
    assert schema["required"] == ["count"]
    openai = _spec().openai_schema()
    assert openai["function"]["parameters"]["properties"]["count"]["type"] == "integer"


def test_unambiguous_strings_are_coerced_and_recorded():
    values, errors, coercions = coerce_arguments(_spec(), {"count": "5"})
    assert errors == []
    assert values["count"] == 5
    assert values["label"] == "x"
    assert coercions and "count" in coercions[0]


def test_wrong_type_is_an_error_not_a_guess():
    _, errors, _ = coerce_arguments(_spec(), {"count": "many"})
    assert errors and "count" in errors[0]


def test_out_of_range_and_bad_enum_are_refused():
    _, errors, _ = coerce_arguments(_spec(), {"count": 99})
    assert errors
    _, errors, _ = coerce_arguments(_spec(), {"count": 2, "mode": "turbo"})
    assert errors and "mode" in errors[0]


def test_unknown_argument_lists_what_is_accepted():
    _, errors, _ = coerce_arguments(_spec(), {"count": 2, "nonsense": 1})
    assert errors and "nonsense" in errors[0] and "count" in errors[0]


def test_registry_dispatches_with_validated_arguments():
    seen = {}

    def handler(count: int, label: str, mode: str = "basic", tags=None):
        seen.update({"count": count, "label": label, "mode": mode, "tags": tags})
        return {"ok": True, "summary": {"count": count}}

    spec = _spec(handler=handler)
    registry = ToolRegistry()
    registry.register(spec)
    outcome = registry.call("probe", {"count": "3"})
    assert outcome["dispatched"] and outcome["ok"]
    assert seen["count"] == 3
    assert outcome["coercions"]


def test_dispatch_failure_is_distinguishable_from_operation_failure():
    registry = ToolRegistry()
    registry.register(_spec(parameters=[ParamSpec("count", "integer", required=True)],
                           handler=lambda count: {"ok": count > 5}))
    bad_args = registry.call("probe", {"count": "not-a-number"})
    assert bad_args["dispatched"] is False and bad_args["status"] == "dispatch_error"

    failed_op = registry.call("probe", {"count": 1})
    assert failed_op["dispatched"] is True and failed_op["ok"] is False


def test_internal_type_error_is_a_tool_fault():
    registry = ToolRegistry()

    def broken(**kwargs):
        return "x" + 1  # noqa: B008 - deliberate fault inside the tool body

    registry.register(ToolSpec(name="broken", description="d", handler=broken))
    outcome = registry.call("broken", {})
    assert outcome["dispatched"] is True
    assert outcome["ok"] is False
    assert "internal fault" in outcome["error"]


def test_unknown_tool_and_duplicate_registration():
    registry = ToolRegistry()
    registry.register(_spec())
    with pytest.raises(ValueError):
        registry.register(_spec())
    outcome = registry.call("no-such-tool", {})
    assert outcome["dispatched"] is False and "unknown tool" in outcome["error"]


def test_missing_dependency_prevents_dispatch():
    registry = ToolRegistry()
    registry.register(ToolSpec(name="needs_ghost", description="d",
                               handler=lambda: {"ok": True},
                               requires=["ghost-binary-that-does-not-exist"]))
    outcome = registry.call("needs_ghost", {})
    assert outcome["dispatched"] is False
    assert "ghost-binary-that-does-not-exist" in outcome["error"]
