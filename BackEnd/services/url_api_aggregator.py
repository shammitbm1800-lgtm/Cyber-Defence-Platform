from services.url_api_service import (
    check_urlscan,
    check_urlhaus,
    check_privacytestlab,
    check_phishstats
)


def scan_url_with_apis(url):
    """
    Run all configured URL threat-intelligence APIs.
    """

    results = []

    results.append(check_urlscan(url))
    results.append(check_urlhaus(url))
    results.append(check_privacytestlab(url))
    results.append(check_phishstats(url))

    return results


# Keep compatibility with existing code
check_all_url_apis = scan_url_with_apis