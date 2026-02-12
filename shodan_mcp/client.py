"""Shodan API HTTP client for safe request execution and response parsing."""

import httpx
import ipaddress
import re
from contextlib import asynccontextmanager
from loguru import logger
from shodan_mcp.consts import (
    DEFAULT_REQUEST_TIMEOUT,
    FORBIDDEN_QUERY_CHARS,
    SHODAN_API_KEY,
    SHODAN_BASE_URL,
    SHODAN_CVEDB_URL,
    SHODAN_INTERNETDB_URL,
)


def _sanitize_error(error: Exception) -> Exception:
    """Strip the API key from error messages to prevent leaking secrets.

    Returns a new exception of the same type with the sanitized message.
    For complex exception types that require extra constructor args (e.g.,
    httpx.HTTPStatusError), falls back to a generic Exception.
    """
    msg = str(error)
    if SHODAN_API_KEY:
        msg = msg.replace(SHODAN_API_KEY, '***')
    try:
        return type(error)(msg)
    except TypeError:
        return Exception(msg)


@asynccontextmanager
async def _safe_httpx_client(timeout: int = DEFAULT_REQUEST_TIMEOUT):
    """Wrap httpx.AsyncClient to strip API keys from any error messages."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            yield client
    except Exception as e:
        raise _sanitize_error(e) from None


def validate_ip(ip: str) -> str:
    """Validate and sanitize an IP address to prevent injection.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        The validated IP address string.

    Raises:
        ValueError: If the IP address is invalid or contains forbidden characters.
    """
    ip = ip.strip()

    if not ip:
        raise ValueError('IP address cannot be empty')

    # Check for injection characters
    if any(c in ip for c in FORBIDDEN_QUERY_CHARS):
        raise ValueError(f'IP address contains forbidden characters: {ip}')

    # Validate as IPv4 or IPv6
    try:
        parsed = ipaddress.ip_address(ip)
        return str(parsed)
    except ValueError:
        raise ValueError(f'Invalid IP address: {ip}')


def validate_query(query: str) -> str:
    """Validate and sanitize a Shodan search query.

    Args:
        query: Shodan search query string (e.g., 'apache port:8080 country:US').

    Returns:
        The validated query string.

    Raises:
        ValueError: If the query is empty or contains forbidden characters.
    """
    query = query.strip()

    if not query:
        raise ValueError('Search query cannot be empty')

    # Check for shell injection characters
    if any(c in query for c in FORBIDDEN_QUERY_CHARS):
        raise ValueError(f'Query contains forbidden characters: {query}')

    return query


def validate_cve_id(cve_id: str) -> str:
    """Validate a CVE identifier format.

    Args:
        cve_id: CVE identifier string (e.g., 'CVE-2021-44228').

    Returns:
        The validated CVE ID string (uppercased).

    Raises:
        ValueError: If the CVE ID format is invalid.
    """
    cve_id = cve_id.strip().upper()

    if not cve_id:
        raise ValueError('CVE ID cannot be empty')

    # CVE format: CVE-YYYY-NNNNN (at least 4 digits in the sequence number)
    cve_re = re.compile(r'^CVE-\d{4}-\d{4,}$')
    if not cve_re.match(cve_id):
        raise ValueError(
            f'Invalid CVE ID format: {cve_id}. '
            'Expected format: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)'
        )

    return cve_id


async def shodan_host_lookup(
    ip: str,
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Look up detailed host information from Shodan.

    Args:
        ip: Validated IP address to look up.
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Raw JSON response as a dictionary.

    Raises:
        httpx.HTTPStatusError: If the API returns an error status.
        httpx.TimeoutException: If the request times out.
    """
    url = f'{SHODAN_BASE_URL}/shodan/host/{ip}'
    params = {'key': api_key}

    logger.info(f'Shodan host lookup: {ip}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_search(
    query: str,
    api_key: str,
    page: int = 1,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Search Shodan's database with a query.

    Args:
        query: Validated Shodan search query.
        api_key: Shodan API key.
        page: Results page number (1-indexed).
        timeout: HTTP request timeout in seconds.

    Returns:
        Raw JSON response as a dictionary.

    Raises:
        httpx.HTTPStatusError: If the API returns an error status.
        httpx.TimeoutException: If the request times out.
    """
    url = f'{SHODAN_BASE_URL}/shodan/host/search'
    params = {
        'key': api_key,
        'query': query,
        'page': page,
    }

    logger.info(f'Shodan search: query="{query}", page={page}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_cve_lookup(
    cve_id: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Look up CVE details from Shodan's CVE database.

    This endpoint is FREE and does not require an API key.

    Args:
        cve_id: Validated CVE identifier (e.g., 'CVE-2021-44228').
        timeout: HTTP request timeout in seconds.

    Returns:
        Raw JSON response as a dictionary.

    Raises:
        httpx.HTTPStatusError: If the API returns an error status.
        httpx.TimeoutException: If the request times out.
    """
    url = f'{SHODAN_CVEDB_URL}/cve/{cve_id}'

    logger.info(f'Shodan CVE lookup: {cve_id}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


def validate_hostnames(hostnames: str) -> str:
    """Validate a comma-separated list of hostnames.

    Args:
        hostnames: Comma-separated hostnames (e.g., 'google.com,bing.com').

    Returns:
        The validated hostnames string.

    Raises:
        ValueError: If the hostnames are invalid or contain forbidden characters.
    """
    hostnames = hostnames.strip()

    if not hostnames:
        raise ValueError('Hostnames cannot be empty')

    if any(c in hostnames for c in FORBIDDEN_QUERY_CHARS):
        raise ValueError(f'Hostnames contain forbidden characters: {hostnames}')

    hostname_re = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
    )
    parts = [h.strip() for h in hostnames.split(',')]
    for h in parts:
        if not h or not hostname_re.match(h):
            raise ValueError(f'Invalid hostname: {h}')

    return ','.join(parts)


def validate_domain(domain: str) -> str:
    """Validate a domain name.

    Args:
        domain: Domain name (e.g., 'example.com').

    Returns:
        The validated domain string.

    Raises:
        ValueError: If the domain is invalid.
    """
    domain = domain.strip().lower()

    if not domain:
        raise ValueError('Domain cannot be empty')

    if any(c in domain for c in FORBIDDEN_QUERY_CHARS):
        raise ValueError(f'Domain contains forbidden characters: {domain}')

    domain_re = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'
    )
    if not domain_re.match(domain):
        raise ValueError(f'Invalid domain: {domain}')

    return domain


async def shodan_dns_resolve(
    hostnames: str,
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Resolve hostnames to IP addresses via Shodan.

    Args:
        hostnames: Comma-separated hostnames (e.g., 'google.com,bing.com').
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary mapping hostnames to IP addresses.
    """
    url = f'{SHODAN_BASE_URL}/dns/resolve'
    params = {'key': api_key, 'hostnames': hostnames}

    logger.info(f'Shodan DNS resolve: {hostnames}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_dns_reverse(
    ips: str,
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Reverse DNS lookup for IP addresses via Shodan.

    Args:
        ips: Comma-separated IP addresses (e.g., '8.8.8.8,1.1.1.1').
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary mapping IPs to lists of hostnames.
    """
    url = f'{SHODAN_BASE_URL}/dns/reverse'
    params = {'key': api_key, 'ips': ips}

    logger.info(f'Shodan DNS reverse: {ips}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_search_count(
    query: str,
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Count Shodan search results without consuming query credits.

    Args:
        query: Shodan search query.
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with 'total' count and optional facets.
    """
    url = f'{SHODAN_BASE_URL}/shodan/host/count'
    params = {'key': api_key, 'query': query}

    logger.info(f'Shodan search count: query="{query}"')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_domain_info(
    domain: str,
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Get DNS information about a domain from Shodan.

    Args:
        domain: Domain name (e.g., 'example.com').
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with subdomains, DNS records, and tags.
    """
    url = f'{SHODAN_BASE_URL}/dns/domain/{domain}'
    params = {'key': api_key}

    logger.info(f'Shodan domain info: {domain}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_internetdb_lookup(
    ip: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Quick IP lookup from Shodan InternetDB (free, no API key).

    Args:
        ip: IP address to look up.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with ports, hostnames, CPEs, vulns, and tags.
    """
    url = f'{SHODAN_INTERNETDB_URL}/{ip}'

    logger.info(f'InternetDB lookup: {ip}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def shodan_honeyscore(
    ip: str,
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> float:
    """Get honeypot probability score for an IP address.

    Args:
        ip: IP address to score.
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Honeypot probability score (0.0 to 1.0).
    """
    url = f'{SHODAN_BASE_URL}/labs/honeyscore/{ip}'
    params = {'key': api_key}

    logger.info(f'Shodan honeyscore: {ip}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return float(response.text)


async def shodan_api_info(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Get API key information and usage stats.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with plan info, credits, and usage limits.
    """
    url = f'{SHODAN_BASE_URL}/api-info'
    params = {'key': api_key}

    logger.info('Shodan API info lookup')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_my_ip(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> str:
    """Get your current external IP address as seen by Shodan.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        IP address as a string.
    """
    url = f'{SHODAN_BASE_URL}/tools/myip'
    params = {'key': api_key}

    logger.info('Shodan my-ip lookup')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_cve_search(
    is_kev: bool = False,
    sort_by_epss: bool = False,
    skip: int = 0,
    limit: int = 20,
    start_date: str | None = None,
    end_date: str | None = None,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Search CVEs in Shodan's CVEDB (free, no API key).

    Args:
        is_kev: Only return CVEs in CISA's Known Exploited Vulnerabilities catalog.
        sort_by_epss: Sort results by EPSS score (highest first).
        skip: Number of results to skip.
        limit: Maximum number of results (max 100).
        start_date: Filter CVEs published after this date (YYYY-MM-DD).
        end_date: Filter CVEs published before this date (YYYY-MM-DD).
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with CVE list and total count.
    """
    url = f'{SHODAN_CVEDB_URL}/cves'
    params: dict = {'skip': skip, 'limit': min(limit, 100)}

    if is_kev:
        params['is_kev'] = 'true'
    if sort_by_epss:
        params['sort_by_epss'] = 'true'
    if start_date:
        params['start_date'] = start_date
    if end_date:
        params['end_date'] = end_date

    logger.info(f'Shodan CVE search: kev={is_kev}, epss_sort={sort_by_epss}')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_cpe_search(
    product: str,
    count: bool = True,
    skip: int = 0,
    limit: int = 100,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Search CPEs in Shodan's CVEDB (free, no API key).

    Args:
        product: Product name to search for (e.g., 'apache', 'nginx').
        count: Whether to include total count.
        skip: Number of results to skip.
        limit: Maximum number of results.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with CPE list and total count.
    """
    url = f'{SHODAN_CVEDB_URL}/cpes'
    params: dict = {
        'product': product,
        'skip': skip,
        'limit': limit,
    }
    if count:
        params['count'] = 'true'

    logger.info(f'Shodan CPE search: product="{product}"')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_search_facets(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> list:
    """List available search facets.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of available facet names.
    """
    url = f'{SHODAN_BASE_URL}/shodan/host/search/facets'
    params = {'key': api_key}

    logger.info('Shodan search facets listing')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_search_filters(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> list:
    """List available search filters.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of available filter names.
    """
    url = f'{SHODAN_BASE_URL}/shodan/host/search/filters'
    params = {'key': api_key}

    logger.info('Shodan search filters listing')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_search_tokens(
    query: str,
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Parse a search query into tokens.

    Args:
        query: Shodan search query to analyze.
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with attributes, errors, filters, and string.
    """
    url = f'{SHODAN_BASE_URL}/shodan/host/search/tokens'
    params = {'key': api_key, 'query': query}

    logger.info(f'Shodan search tokens: query="{query}"')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_ports(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> list:
    """List port numbers that Shodan crawlers are looking for.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of port numbers.
    """
    url = f'{SHODAN_BASE_URL}/shodan/ports'
    params = {'key': api_key}

    logger.info('Shodan ports listing')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_protocols(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """List protocols available for on-demand scanning.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary mapping protocol names to descriptions.
    """
    url = f'{SHODAN_BASE_URL}/shodan/protocols'
    params = {'key': api_key}

    logger.info('Shodan protocols listing')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_account_profile(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Get Shodan account profile information.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary with account profile details.
    """
    url = f'{SHODAN_BASE_URL}/account/profile'
    params = {'key': api_key}

    logger.info('Shodan account profile lookup')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def shodan_http_headers(
    api_key: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT,
) -> dict:
    """Get the HTTP headers that your client sends when connecting to a webserver.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dictionary of HTTP header name-value pairs.
    """
    url = f'{SHODAN_BASE_URL}/tools/httpheaders'
    params = {'key': api_key}

    logger.info('Shodan HTTP headers lookup')

    async with _safe_httpx_client(timeout=timeout) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()


