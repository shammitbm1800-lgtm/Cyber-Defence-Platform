import re

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"()]+",
    re.IGNORECASE
)


def extract_urls(message):
    if not message:
        return []

    return URL_PATTERN.findall(message)