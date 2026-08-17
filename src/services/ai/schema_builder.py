"""
Builds Gemini-compatible response schemas from Pydantic models.

Why this exists: passing a Pydantic model class directly as `response_schema`
looks like it works, but the (now EOL) google.generativeai SDK's internal
converter silently drops every `required` array. Gemini then treats all fields
as optional and is free to return a near-empty object like {"risk_level": "HIGH"},
which fails Pydantic validation and sends the whole alert down the PARTIAL path.

Gemini accepts an OpenAPI-subset schema which supports `required`, but does NOT
support JSON-Schema `$ref`/`$defs`, so nested models must be inlined.
"""
from typing import Any
from pydantic import BaseModel

# Keys Gemini's Schema type understands; everything else (title, default,
# additionalProperties, $defs, ...) is dropped.
_ALLOWED_KEYS = {"type", "description", "enum", "items", "properties", "required", "nullable", "format"}


def _resolve(node: Any, defs: dict[str, Any]) -> Any:
    """Recursively inline $ref nodes and strip keys Gemini does not accept."""
    if isinstance(node, list):
        return [_resolve(item, defs) for item in node]
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
        return _resolve(target, defs)

    cleaned: dict[str, Any] = {}
    for key, value in node.items():
        if key not in _ALLOWED_KEYS:
            continue
        if key in ("properties",):
            cleaned[key] = {k: _resolve(v, defs) for k, v in value.items()}
        elif key in ("items",):
            cleaned[key] = _resolve(value, defs)
        else:
            cleaned[key] = value

    return cleaned


def build_gemini_schema(model: type[BaseModel]) -> dict[str, Any]:
    """
    Converts a Pydantic model into a Gemini-compatible schema dict that
    preserves `required` at every nesting level.
    """
    raw = model.model_json_schema()
    defs = raw.get("$defs", {})
    return _resolve(raw, defs)
