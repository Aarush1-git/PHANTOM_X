import json
from typing import Dict, Any, List
from pydantic import BaseModel


class ParsedHarEntry(BaseModel):
    method: str
    url: str
    status: int
    request_headers: Dict[str, str]
    response_headers: Dict[str, str]
    request_body: str
    response_body: str
    time_ms: float


class HarTrafficParser:
    """Parses HTTP Archive (.har) files to discover endpoints, parameters, and payloads."""

    @staticmethod
    def parse_har_content(har_json_str: str) -> List[ParsedHarEntry]:
        try:
            data = json.loads(har_json_str)
            entries = data.get("log", {}).get("entries", [])
            parsed = []
            for e in entries:
                req = e.get("request", {})
                resp = e.get("response", {})
                parsed.append(ParsedHarEntry(
                    method=req.get("method", "GET"),
                    url=req.get("url", ""),
                    status=resp.get("status", 0),
                    request_headers={h["name"].lower(): h["value"] for h in req.get("headers", [])},
                    response_headers={h["name"].lower(): h["value"] for h in resp.get("headers", [])},
                    request_body=req.get("postData", {}).get("text", ""),
                    response_body=resp.get("content", {}).get("text", ""),
                    time_ms=e.get("time", 0.0)
                ))
            return parsed
        except Exception:
            return []

