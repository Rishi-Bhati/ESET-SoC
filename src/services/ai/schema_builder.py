"""
Builds provider-specific structured-output schemas from the AIOutput Pydantic model.

Two dialects:

* OpenAI / Azure OpenAI strict mode (`build_strict_json_schema`): standard JSON
  Schema, but strict mode requires every object to list ALL its properties in
  `required` and to set `additionalProperties: false`. In exchange the API
  guarantees the response matches the schema exactly.

* Gemini (`build_gemini_schema`): an OpenAPI subset that supports `required` but
  not `$ref`/`$defs`/`additionalProperties`. Passing the Pydantic class to the
  (now EOL) google.generativeai SDK directly looks like it works, but its
  converter silently drops every `required` array, letting Gemini return a
  near-empty object — so the schema is built by hand here.

Both accept `pin`: a map of top-level property -> the only allowed values. The
pipeline pins `risk_level` to the level the rule engine computed, so the model
is structurally unable to return a different one.
"""
import copy
from typing import Any
from pydantic import BaseModel

# Keys Gemini's Schema type understands; everything else (title, default,
# additionalProperties, $defs, ...) is dropped.
_GEMINI_KEYS = {"type", "description", "enum", "items", "properties", "required", "nullable", "format"}
# Keys kept for OpenAI strict mode. `title`/`default` are dropped: they carry
# nothing the model needs and `default` is not permitted in strict mode.
_STRICT_KEYS = {"type", "description", "enum", "items", "properties", "required", "additionalProperties"}


def _resolve(node: Any, defs: dict[str, Any], allowed: set[str]) -> Any:
    """Recursively inline $ref nodes and strip keys the target dialect does not accept."""
    if isinstance(node, list):
        return [_resolve(item, defs, allowed) for item in node]
    if not isinstance(node, dict):
        return node

    # Inline a $ref by substituting the referenced definition
    ref = node.get("$ref")
    if ref:
        name = ref.rsplit("/", 1)[-1]
        target = dict(defs.get(name, {}))
        # Merge any sibling keys (e.g. description) over the referenced schema
        for key, value in node.items():
            if key != "$ref":
                target[key] = value
        return _resolve(target, defs, allowed)

    cleaned: dict[str, Any] = {}
    for key, value in node.items():
        if key not in allowed:
            continue
        if key == "properties":
            cleaned[key] = {k: _resolve(v, defs, allowed) for k, v in value.items()}
        elif key == "items":
            cleaned[key] = _resolve(value, defs, allowed)
        else:
            cleaned[key] = value

    return cleaned


def _pin(schema: dict[str, Any], pin: dict[str, list[str]] | None) -> dict[str, Any]:
    for prop, values in (pin or {}).items():
        target = schema.get("properties", {}).get(prop)
        if target is None:
            raise KeyError(f"Cannot pin unknown property {prop!r}")
        target["enum"] = list(values)
        target["type"] = "string"
    return schema


def _make_strict(node: Any) -> Any:
    if isinstance(node, dict):
        if node.get("type") == "object" or "properties" in node:
            node["type"] = "object"
            node["additionalProperties"] = False
            node["required"] = list(node.get("properties", {}).keys())
        for key in ("properties",):
            if key in node:
                for child in node[key].values():
                    _make_strict(child)
        if "items" in node:
            _make_strict(node["items"])
    return node


def build_strict_json_schema(model: type[BaseModel], pin: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """JSON Schema for OpenAI structured outputs with `strict: true`."""
    raw = model.model_json_schema()
    schema = _resolve(copy.deepcopy(raw), raw.get("$defs", {}), _STRICT_KEYS)
    return _pin(_make_strict(schema), pin)


def build_gemini_schema(model: type[BaseModel], pin: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """
    Converts a Pydantic model into a Gemini-compatible schema dict that
    preserves `required` at every nesting level.
    """
    raw = model.model_json_schema()
    return _pin(_resolve(raw, raw.get("$defs", {}), _GEMINI_KEYS), pin)
