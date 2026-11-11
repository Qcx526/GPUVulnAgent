# -*- coding: utf-8 -*-
"""Tool specification with real parameter types.

The P17/P18 registry described every parameter as the string ``"str"`` and turned that
into ``{"type": "string"}`` for the provider. A model that wanted ``max_results: 5`` was
told to send a string, and integer-only tool bodies then had to guess. Here a parameter
carries a JSON-Schema type, so the provider sees the same contract the tool enforces.

Validation happens before dispatch and can coerce unambiguous cases (``"5"`` for an
integer) while recording that it did so. Ambiguous input is an error, not a guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

SCALAR_TYPES = ("string", "integer", "number", "boolean", "array", "object")
TYPE_ALIASES = {"str": "string", "int": "integer", "float": "number", "double": "number",
                "bool": "boolean", "list": "array", "dict": "object", "text": "string"}


@dataclass
class ParamSpec:
    name: str
    type: str = "string"
    description: str = ""
    required: bool = True
    enum: Sequence[Any] = ()
    items_type: str = "string"
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    default: Any = None

    def __post_init__(self) -> None:
        self.type = TYPE_ALIASES.get(self.type.lower(), self.type.lower())
        if self.type not in SCALAR_TYPES:
            raise ValueError("parameter %r has unsupported type %r (allowed: %s)"
                             % (self.name, self.type, ", ".join(SCALAR_TYPES)))

    def json_schema(self) -> dict:
        schema: Dict[str, Any] = {"type": self.type}
        if self.description:
            schema["description"] = self.description
        if self.enum:
            schema["enum"] = list(self.enum)
        if self.type == "array":
            schema["items"] = {"type": TYPE_ALIASES.get(self.items_type, self.items_type)}
        if self.minimum is not None:
            schema["minimum"] = self.minimum
        if self.maximum is not None:
            schema["maximum"] = self.maximum
        if self.default is not None:
            schema["default"] = self.default
        return schema


@dataclass
class ToolSpec:
    name: str
    description: str
    handler: Callable
    parameters: List[ParamSpec] = field(default_factory=list)
    category: str = "general"
    requires: List[str] = field(default_factory=list)
    source: str = "builtin"
    location: str = ""
    usage: str = ""
    formats: Sequence[str] = ()
    side_effects: Sequence[str] = ()
    tags: Sequence[str] = ()

    def parameter(self, name: str) -> Optional[ParamSpec]:
        for item in self.parameters:
            if item.name == name:
                return item
        return None

    def json_schema(self) -> dict:
        properties = {item.name: item.json_schema() for item in self.parameters}
        required = [item.name for item in self.parameters if item.required]
        schema: Dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return schema

    def openai_schema(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name,
            "description": _clip(self.description, 1000),
            "parameters": self.json_schema(),
        }}

    def signature(self) -> str:
        parts = []
        for item in self.parameters:
            marker = "" if item.required else "?"
            parts.append("%s%s:%s" % (item.name, marker, item.type))
        return "%s(%s)" % (self.name, ", ".join(parts))


def _clip(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def coerce_arguments(spec: ToolSpec, arguments: Dict[str, Any]) -> Tuple[Dict, List[str], List[str]]:
    """Return ``(values, errors, coercions)``. Never raises on user input."""
    errors: List[str] = []
    coercions: List[str] = []
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return {}, ["arguments must be an object, got %s" % type(arguments).__name__], []

    known = {item.name for item in spec.parameters}
    unknown = sorted(set(arguments) - known)
    if unknown:
        errors.append("unknown argument(s) %s; accepted: %s"
                      % (", ".join(unknown),
                         ", ".join(sorted(known)) or "(none)"))

    values: Dict[str, Any] = {}
    for item in spec.parameters:
        if item.name not in arguments or arguments[item.name] is None:
            if item.required:
                errors.append("missing required argument %r (%s)" % (item.name, item.type))
            elif item.default is not None:
                values[item.name] = item.default
            continue
        value, error, coerced = _coerce(item, arguments[item.name])
        if error:
            errors.append(error)
            continue
        if coerced:
            coercions.append("%s: %s -> %s" % (item.name, type(arguments[item.name]).__name__,
                                               item.type))
        values[item.name] = value
    return values, errors, coercions


def _coerce(item: ParamSpec, value: Any) -> Tuple[Any, str, bool]:
    kind = item.type
    if kind == "string":
        if isinstance(value, str):
            return _check_enum(item, value)
        if isinstance(value, (int, float, bool)):
            return _check_enum(item, str(value))
        return None, "%r must be a string, got %s" % (item.name, type(value).__name__), False

    if kind == "integer":
        if isinstance(value, bool):
            return None, "%r must be an integer, got boolean" % item.name, False
        if isinstance(value, int):
            return _check_range(item, value, False)
        if isinstance(value, str):
            try:
                return _check_range(item, int(value.strip()), True)
            except ValueError:
                return None, "%r must be an integer, got %r" % (item.name, value), False
        if isinstance(value, float) and value.is_integer():
            return _check_range(item, int(value), True)
        return None, "%r must be an integer, got %s" % (item.name, type(value).__name__), False

    if kind == "number":
        if isinstance(value, bool):
            return None, "%r must be a number, got boolean" % item.name, False
        if isinstance(value, (int, float)):
            return _check_range(item, float(value), False)
        if isinstance(value, str):
            try:
                return _check_range(item, float(value.strip()), True)
            except ValueError:
                return None, "%r must be a number, got %r" % (item.name, value), False
        return None, "%r must be a number, got %s" % (item.name, type(value).__name__), False

    if kind == "boolean":
        if isinstance(value, bool):
            return value, "", False
        if isinstance(value, int) and value in (0, 1):
            return bool(value), "", True
        if isinstance(value, str) and value.strip().lower() in ("true", "false", "1", "0"):
            return value.strip().lower() in ("true", "1"), "", True
        return None, "%r must be a boolean, got %r" % (item.name, value), False

    if kind == "array":
        if isinstance(value, list):
            return value, "", False
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                try:
                    parsed = json.loads(text)
                except ValueError:
                    return None, "%r looks like JSON but does not parse" % item.name, False
                if isinstance(parsed, list):
                    return parsed, "", True
            # A single scalar is a one-element list, which is what callers mean.
            return [value], "", True
        return None, "%r must be an array, got %s" % (item.name, type(value).__name__), False

    if kind == "object":
        if isinstance(value, dict):
            return value, "", False
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except ValueError:
                return None, "%r must be a JSON object string" % item.name, False
            if isinstance(parsed, dict):
                return parsed, "", True
        return None, "%r must be an object, got %s" % (item.name, type(value).__name__), False

    return None, "%r has unsupported type %r" % (item.name, kind), False


def _check_enum(item: ParamSpec, value: Any) -> Tuple[Any, str, bool]:
    if item.enum and value not in item.enum:
        return None, "%r must be one of %s, got %r" % (item.name, list(item.enum), value), False
    return value, "", False


def _check_range(item: ParamSpec, value: Any, coerced: bool) -> Tuple[Any, str, bool]:
    if item.minimum is not None and value < item.minimum:
        return None, "%r must be >= %s, got %s" % (item.name, item.minimum, value), False
    if item.maximum is not None and value > item.maximum:
        return None, "%r must be <= %s, got %s" % (item.name, item.maximum, value), False
    return value, "", coerced
