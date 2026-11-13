import re
from typing import Any, Dict, List, Optional, Set, Union

ISO_DATETIME_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)
UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def infer_payload_schema(payload: Any, max_depth: int = 10, current_depth: int = 0) -> Dict[str, Any]:
    """
    Infers a JSON schema representation from a single payload observation.
    Captures primitive types, formats, array items, and nested object properties.
    """
    if current_depth > max_depth:
        return {"type": "object", "truncated": True}

    if payload is None:
        return {"type": "null"}

    if isinstance(payload, bool):
        return {"type": "boolean"}

    if isinstance(payload, int):
        return {"type": "integer"}

    if isinstance(payload, float):
        return {"type": "number"}

    if isinstance(payload, str):
        schema = {"type": "string"}
        if ISO_DATETIME_REGEX.match(payload):
            schema["format"] = "date-time"
        elif UUID_REGEX.match(payload):
            schema["format"] = "uuid"
        return schema

    if isinstance(payload, list):
        if not payload:
            return {"type": "array", "items": {"type": "unknown"}}
        # Sample elements and merge item schemas
        item_schemas = [
            infer_payload_schema(elem, max_depth, current_depth + 1)
            for elem in payload[:20]
        ]
        merged_items = item_schemas[0]
        for s in item_schemas[1:]:
            merged_items = merge_structural_schemas(merged_items, s)
        return {"type": "array", "items": merged_items}

    if isinstance(payload, dict):
        properties = {}
        required = []
        for key, val in payload.items():
            key_str = str(key)
            properties[key_str] = infer_payload_schema(val, max_depth, current_depth + 1)
            required.append(key_str)
        return {
            "type": "object",
            "properties": properties,
            "required": sorted(required),
        }

    return {"type": "string"}


def merge_structural_schemas(
    schema_a: Optional[Dict[str, Any]],
    schema_b: Optional[Dict[str, Any]],
    depth: int = 0
) -> Dict[str, Any]:
    """
    Incrementally merges two structural schemas into a unified profile.
    Handles:
    - Optional fields (fields not present in all observations lose 'required' status).
    - Type inconsistencies / unions (e.g. int vs string, or nullable fields).
    - Nested object properties and array item types.
    """
    if not schema_a:
        return schema_b or {}
    if not schema_b:
        return schema_a or {}

    type_a = schema_a.get("type")
    type_b = schema_b.get("type")

    # If types differ or one is a union
    if type_a != type_b:
        types_a = set(type_a if isinstance(type_a, list) else [type_a])
        types_b = set(type_b if isinstance(type_b, list) else [type_b])
        combined_types = sorted(list(types_a.union(types_b) - {"unknown"}))
        if not combined_types:
            combined_types = ["unknown"]

        return {
            "type": combined_types if len(combined_types) > 1 else combined_types[0],
            "nullable": "null" in combined_types,
            "inconsistent_types": True,
        }

    # Same type: Object
    if type_a == "object":
        props_a = schema_a.get("properties", {})
        props_b = schema_b.get("properties", {})
        all_keys = set(props_a.keys()).union(set(props_b.keys()))

        merged_props = {}
        merged_required = []

        req_a = set(schema_a.get("required", []))
        req_b = set(schema_b.get("required", []))

        for k in all_keys:
            if k in props_a and k in props_b:
                merged_props[k] = merge_structural_schemas(props_a[k], props_b[k], depth + 1)
                # If key was required in both A and B, it remains required
                if k in req_a and k in req_b:
                    merged_required.append(k)
            elif k in props_a:
                # Key absent in B -> becomes optional
                merged_props[k] = props_a[k]
            else:
                # Key absent in A -> becomes optional
                merged_props[k] = props_b[k]

        return {
            "type": "object",
            "properties": merged_props,
            "required": sorted(merged_required),
        }

    # Same type: Array
    if type_a == "array":
        items_a = schema_a.get("items")
        items_b = schema_b.get("items")
        merged_items = merge_structural_schemas(items_a, items_b, depth + 1)
        return {"type": "array", "items": merged_items}

    # Same primitive type
    res = {"type": type_a}
    if schema_a.get("format") and schema_a.get("format") == schema_b.get("format"):
        res["format"] = schema_a["format"]

    return res
