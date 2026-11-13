import re
from urllib.parse import urlparse
from typing import Tuple

UUID_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
NUMERIC_ID_REGEX = re.compile(r"^\d+$")


def normalize_url_path(url_or_path: str) -> str:
    """
    Extract and normalize the HTTP path from a URL or raw path string.
    Strips protocol, host, port, query parameters, and trailing slashes.
    Ensures path begins with leading slash.
    """
    if not url_or_path or not url_or_path.strip():
        return "/"

    clean = url_or_path.strip()
    # If full URL with scheme, extract path
    if "://" in clean or clean.startswith("//"):
        parsed = urlparse(clean)
        path = parsed.path
    else:
        # Strip query string or fragments if present in relative path
        path = clean.split("?")[0].split("#")[0]

    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path

    # Collapse multiple consecutive slashes
    path = re.sub(r"/{2,}", "/", path)

    # Strip trailing slash unless root path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    return path


def parameterize_path(path: str) -> str:
    """
    Convert dynamic URL segments (UUIDs, integer IDs) into parameterized placeholders:
    e.g. /api/v1/users/5a91b.../orders/123 -> /api/v1/users/{id}/orders/{id}
    """
    normalized = normalize_url_path(path)
    segments = normalized.split("/")
    parameterized = []

    for seg in segments:
        if not seg:
            continue
        if UUID_REGEX.fullmatch(seg):
            parameterized.append("{id}")
        elif NUMERIC_ID_REGEX.fullmatch(seg):
            parameterized.append("{id}")
        else:
            parameterized.append(seg)

    return "/" + "/".join(parameterized)


def normalize_endpoint_identity(method: str, url_or_path: str) -> Tuple[str, str, str]:
    """
    Returns (normalized_method, normalized_path, parameterized_path).
    Example: ('GET', 'https://api.local/users/123?q=test') -> ('GET', '/users/123', '/users/{id}')
    """
    clean_method = method.strip().upper()
    norm_path = normalize_url_path(url_or_path)
    param_path = parameterize_path(norm_path)
    return clean_method, norm_path, param_path
