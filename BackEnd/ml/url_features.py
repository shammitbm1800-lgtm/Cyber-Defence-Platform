from urllib.parse import urlparse

URL_FEATURES = [
    "dot_count",
    "url_len",
    "digit_count",
    "special_count",
    "hyphen_count",
    "double_slash",
    "single_slash",
    "at_the_rate",
    "protocol",
    "protocol_count",
]

# These are the lexical special characters used by the dataset's feature
# definition. Dots, slashes, hyphens and @ are tracked separately.
SPECIAL_CHARACTERS = set(":;#!%~+_?=&,][)")


def extract_url_features(url: str) -> dict:
    """Extract the exact lexical feature definitions used by the URL model.

    Important: do not add or remove URL characters just because they look
    suspicious. The live extractor must match the training feature semantics.
    """
    value = (url or "").strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    scheme = (parsed.scheme or "").lower()

    # The source dataset is primarily lexical URL text without the scheme.
    # Remove the transport prefix before calculating character-count features;
    # keep HTTPS separately in the protocol feature. This prevents every normal
    # https:// URL from looking suspicious merely because it contains // and : .
    lexical = parsed.netloc + parsed.path
    if parsed.query:
        lexical += "?" + parsed.query
    if parsed.fragment:
        lexical += "#" + parsed.fragment

    return {
        "dot_count": float(lexical.count(".")),
        "url_len": float(len(lexical)),
        "digit_count": float(sum(c.isdigit() for c in lexical)),
        "special_count": float(sum(1 for c in lexical if c in SPECIAL_CHARACTERS)),
        "hyphen_count": float(lexical.count("-")),
        "double_slash": float(lexical.count("//")),
        "single_slash": float(lexical.count("/")),
        "at_the_rate": float(lexical.count("@")),
        "protocol": float(1 if scheme == "https" else 0),
        "protocol_count": float(value.lower().count("http")),
    }
