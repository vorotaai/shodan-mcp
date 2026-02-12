"""Shodan MCP Server implementation.

This server provides internet intelligence tools via the Model Context Protocol,
wrapping the Shodan API for authorized security research and reconnaissance.
"""

import sys
from loguru import logger
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field
from shodan_mcp.client import (
    _sanitize_error,
    shodan_account_profile,
    shodan_api_info,
    shodan_cpe_search,
    shodan_cve_lookup,
    shodan_cve_search,
    shodan_dns_resolve,
    shodan_dns_reverse,
    shodan_domain_info,
    shodan_honeyscore,
    shodan_host_lookup,
    shodan_http_headers,
    shodan_internetdb_lookup,
    shodan_my_ip,
    shodan_ports,
    shodan_protocols,
    shodan_search,
    shodan_search_count,
    shodan_search_facets,
    shodan_search_filters,
    shodan_search_tokens,
    validate_cve_id,
    validate_domain,
    validate_hostnames,
    validate_ip,
    validate_query,
)
from shodan_mcp.consts import (
    DEFAULT_REQUEST_TIMEOUT,
    LOG_LEVEL,
    SHODAN_API_KEY,
)
from shodan_mcp.models import (
    AccountProfileResult,
    ApiInfoResult,
    CpeSearchResult,
    CveReference,
    CveResult,
    CveSearchResult,
    CvssV3,
    DnsDomainRecord,
    DnsResolveEntry,
    DnsResolveResult,
    DnsReverseEntry,
    DnsReverseResult,
    DomainResult,
    EpssScore,
    HoneypotResult,
    HttpHeadersResult,
    InternetDbResult,
    PortsResult,
    ProtocolsResult,
    QueryTokensResult,
    SearchCountResult,
    SearchFacetsResult,
    SearchFiltersResult,
    ShodanHostResult,
    ShodanLocation,
    ShodanSearchResult,
    ShodanService,
)


# Set up logging
logger.remove()
logger.add(sys.stderr, level=LOG_LEVEL)


mcp = FastMCP(
    'shodan-mcp',
    instructions="""# Shodan Internet Intelligence MCP Server

This MCP server provides 20 tools for passive internet intelligence gathering using the Shodan API.

## IMPORTANT: Authorization Required
CRITICAL: Only query targets you are explicitly authorized to assess.
While Shodan queries are passive (no packets touch the target), you should still ensure you have
proper authorization before investigating any IP address or network.

## Available Tools

### FREE Tools (No API Key Required)
- `shodan-cve-lookup` — Look up CVE details (CVSS, EPSS, references, CPEs)
- `shodan-search-cves` — Search CVEs with filters (KEV catalog, EPSS sorting, date range)
- `shodan-search-cpes` — Search CPE identifiers by product name
- `shodan-internetdb-lookup` — Quick IP intelligence (ports, vulns, hostnames) via InternetDB

### API Key Required Tools
- `shodan-ip-lookup` — Detailed IP reconnaissance (ports, services, vulns, geolocation)
- `shodan-search` — Search Shodan's device database with powerful query syntax
- `shodan-search-count` — Count search results without consuming query credits
- `shodan-dns-resolve` — Resolve hostnames to IP addresses
- `shodan-dns-reverse` — Reverse DNS lookup for IP addresses
- `shodan-domain-info` — Domain reconnaissance (subdomains, DNS records)
- `shodan-honeypot-score` — Check if an IP is likely a honeypot
- `shodan-api-info` — Check your API key usage and remaining credits
- `shodan-my-ip` — Get your external IP address as seen by Shodan
- `shodan-account-profile` — Get your Shodan account profile information

### Reference & Utility Tools (API Key Required)
- `shodan-list-facets` — List available search facets for query breakdowns
- `shodan-list-filters` — List available search filters
- `shodan-parse-query` — Analyze and break down a search query into tokens
- `shodan-list-ports` — List port numbers that Shodan crawlers scan
- `shodan-list-protocols` — List protocols available for on-demand scanning
- `shodan-http-headers` — Show HTTP headers your client sends (debug utility)

## Recommended Workflow

1. Start with FREE tools to research vulnerabilities and exploits (no key needed)
2. Use `shodan-internetdb-lookup` for quick, free IP intelligence
3. Use `shodan-ip-lookup` for detailed host reconnaissance
4. Use `shodan-search` + `shodan-search-count` to find and quantify exposed hosts
5. Use `shodan-dns-resolve` and `shodan-domain-info` for DNS reconnaissance
6. Use `shodan-honeypot-score` to filter out honeypots from results
7. Use `shodan-list-facets` and `shodan-list-filters` to discover available query options
8. Use `shodan-parse-query` to debug and understand complex search queries

## Query Syntax Examples (for shodan-search)

- `apache` — Find Apache servers
- `port:8080` — Find services on port 8080
- `country:US` — Filter by country
- `org:"Google"` — Filter by organization
- `ssl.cert.subject.CN:example.com` — Find by SSL certificate
- `product:nginx version:1.19` — Find specific software versions
- `vuln:CVE-2021-44228` — Find hosts affected by a specific CVE

## API Key Configuration
Set the SHODAN_API_KEY environment variable with your Shodan API key.
Get a key at https://account.shodan.io/
""",
    dependencies=['pydantic', 'loguru', 'httpx'],
)


def _parse_services(data: dict) -> list[ShodanService]:
    """Parse service information from Shodan host data.

    Args:
        data: Raw Shodan API response dictionary.

    Returns:
        List of parsed ShodanService models.
    """
    services = []
    for item in data.get('data', []):
        cpe_list = item.get('cpe', None)
        if isinstance(cpe_list, list) and not cpe_list:
            cpe_list = None

        services.append(
            ShodanService(
                port=item.get('port', 0),
                transport=item.get('transport', 'tcp'),
                product=item.get('product'),
                version=item.get('version'),
                banner=item.get('data', '')[:500] if item.get('data') else None,
                cpe=cpe_list,
            )
        )
    return services


def _parse_location(data: dict) -> ShodanLocation | None:
    """Parse geolocation information from Shodan host data.

    Args:
        data: Raw Shodan API response dictionary.

    Returns:
        Parsed ShodanLocation model, or None if no location data.
    """
    # Shodan returns location in a nested 'location' dict for host lookups
    loc = data.get('location', {}) or {}
    if not loc:
        # Fallback: check top-level keys (some endpoints put location at root)
        loc = data

    if not any(
        loc.get(k) for k in ('city', 'country_name', 'country_code', 'latitude', 'longitude')
    ):
        return None

    return ShodanLocation(
        city=loc.get('city'),
        country_name=loc.get('country_name'),
        country_code=loc.get('country_code'),
        latitude=loc.get('latitude'),
        longitude=loc.get('longitude'),
    )


def _parse_host(data: dict) -> ShodanHostResult:
    """Parse a full host result from Shodan API response.

    Args:
        data: Raw Shodan API response dictionary.

    Returns:
        Parsed ShodanHostResult model.
    """
    vulns = data.get('vulns')
    if isinstance(vulns, list) and not vulns:
        vulns = None

    return ShodanHostResult(
        ip_str=data.get('ip_str', ''),
        hostnames=data.get('hostnames', []),
        ports=data.get('ports', []),
        os=data.get('os'),
        services=_parse_services(data),
        location=_parse_location(data),
        vulns=vulns,
        last_update=data.get('last_update'),
        isp=data.get('isp'),
        org=data.get('org'),
        asn=data.get('asn'),
    )


def _parse_search_match(match: dict) -> ShodanHostResult:
    """Parse a single search result match into a ShodanHostResult.

    Args:
        match: A single match entry from the Shodan search API response.

    Returns:
        Parsed ShodanHostResult model.
    """
    # Search matches have a flatter structure than host lookups
    location_data = match.get('location', {}) or {}
    location = (
        ShodanLocation(
            city=location_data.get('city'),
            country_name=location_data.get('country_name'),
            country_code=location_data.get('country_code'),
            latitude=location_data.get('latitude'),
            longitude=location_data.get('longitude'),
        )
        if location_data
        else None
    )

    cpe_list = match.get('cpe', None)
    if isinstance(cpe_list, list) and not cpe_list:
        cpe_list = None

    service = ShodanService(
        port=match.get('port', 0),
        transport=match.get('transport', 'tcp'),
        product=match.get('product'),
        version=match.get('version'),
        banner=match.get('data', '')[:500] if match.get('data') else None,
        cpe=cpe_list,
    )

    vulns = match.get('vulns')
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())
    if isinstance(vulns, list) and not vulns:
        vulns = None

    return ShodanHostResult(
        ip_str=match.get('ip_str', ''),
        hostnames=match.get('hostnames', []),
        ports=[match.get('port', 0)],
        os=match.get('os'),
        services=[service],
        location=location,
        vulns=vulns,
        last_update=match.get('timestamp'),
        isp=match.get('isp'),
        org=match.get('org'),
        asn=match.get('asn'),
    )


def _parse_cve(data: dict) -> CveResult:
    """Parse CVE data from Shodan CVE database response.

    Args:
        data: Raw Shodan CVEDB API response dictionary.

    Returns:
        Parsed CveResult model.
    """
    # Parse CVSS v3
    cvss_v3 = None
    cvss_data = data.get('cvss_v3') or data.get('cvss')
    if isinstance(cvss_data, (int, float)):
        cvss_v3 = CvssV3(base_score=float(cvss_data))
    elif isinstance(cvss_data, dict):
        cvss_v3 = CvssV3(
            base_score=cvss_data.get('base_score') or cvss_data.get('score'),
            severity=cvss_data.get('severity'),
            vector_string=cvss_data.get('vector_string') or cvss_data.get('vector'),
        )

    # Parse EPSS
    epss = None
    epss_data = data.get('epss')
    if isinstance(epss_data, (int, float)):
        epss = EpssScore(score=float(epss_data))
    elif isinstance(epss_data, dict):
        epss = EpssScore(
            score=epss_data.get('score'),
            percentile=epss_data.get('percentile'),
        )

    # Parse references
    references = []
    refs_data = data.get('references', [])
    if isinstance(refs_data, list):
        for ref in refs_data:
            if isinstance(ref, str):
                references.append(CveReference(url=ref))
            elif isinstance(ref, dict):
                references.append(
                    CveReference(
                        url=ref.get('url', ''),
                        source=ref.get('source'),
                    )
                )

    # Parse CPEs
    cpes = data.get('cpes', []) or []
    if not isinstance(cpes, list):
        cpes = []

    return CveResult(
        cve_id=data.get('cve_id', ''),
        summary=data.get('summary') or data.get('description'),
        cvss_v3=cvss_v3,
        epss=epss,
        references=references,
        cpes=cpes,
        published=data.get('published_time') or data.get('published'),
        last_modified=data.get('last_modified_time') or data.get('last_modified'),
    )


@mcp.tool(name='shodan-ip-lookup')
async def ip_lookup(
    ctx: Context,
    target: str = Field(
        description='IP address to look up (IPv4 or IPv6). '
        'Example: "8.8.8.8" or "2001:4860:4860::8888".',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> ShodanHostResult:
    """Look up detailed information about an IP address using Shodan.

    Returns open ports, services, banners, SSL certificates, geolocation,
    hostnames, vulnerabilities, and last seen date. This is PASSIVE
    reconnaissance — no packets are sent to the target.

    IMPORTANT: Only query targets you are authorized to assess.

    Returns:
        ShodanHostResult with detailed host information from Shodan's database.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    target = validate_ip(target)

    await ctx.info(f'Looking up host information for {target}')
    logger.info(f'IP lookup: target={target}')

    try:
        data = await shodan_host_lookup(target, SHODAN_API_KEY, timeout=timeout)
        result = _parse_host(data)

        services_count = len(result.services)
        ports_count = len(result.ports)
        vulns_count = len(result.vulns) if result.vulns else 0

        await ctx.info(
            f'Lookup complete: {ports_count} port(s), '
            f'{services_count} service(s), {vulns_count} vulnerability(ies)'
        )

        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'IP lookup failed: {safe}')
        await ctx.error(f'IP lookup failed: {safe}')
        raise safe


@mcp.tool(name='shodan-search')
async def search(
    ctx: Context,
    query: str = Field(
        description='Shodan search query. Examples: "apache port:8080 country:US", '
        '"product:nginx", "ssl.cert.subject.CN:example.com", "vuln:CVE-2021-44228".',
    ),
    page: int = Field(
        default=1,
        description='Results page number (1-indexed). Each page returns up to 100 results.',
        ge=1,
        le=10,
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> ShodanSearchResult:
    """Search Shodan's database for hosts matching a query.

    Uses Shodan's powerful search syntax to find internet-connected devices and services.
    Supports filters for port, country, organization, product, version, and more.
    Requires a paid Shodan API key.

    IMPORTANT: Only query targets you are authorized to assess.

    Returns:
        ShodanSearchResult with matching hosts and total result count.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    query = validate_query(query)

    await ctx.info(f'Searching Shodan: "{query}" (page {page})')
    logger.info(f'Shodan search: query="{query}", page={page}')

    try:
        data = await shodan_search(query, SHODAN_API_KEY, page=page, timeout=timeout)

        matches = [_parse_search_match(match) for match in data.get('matches', [])]
        total = data.get('total', 0)

        result = ShodanSearchResult(
            matches=matches,
            total=total,
            query=query,
        )

        await ctx.info(
            f'Search complete: {len(matches)} result(s) on this page, {total} total match(es)'
        )

        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Shodan search failed: {safe}')
        await ctx.error(f'Shodan search failed: {safe}')
        raise safe


@mcp.tool(name='shodan-cve-lookup')
async def cve_lookup(
    ctx: Context,
    cve_id: str = Field(
        description='CVE identifier to look up. Example: "CVE-2021-44228".',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> CveResult:
    """Look up CVE details from Shodan's vulnerability database.

    Returns CVSS scores, EPSS exploit prediction scores, references,
    and affected CPE identifiers. This endpoint is FREE and does NOT
    require a paid Shodan API key.

    Returns:
        CveResult with detailed vulnerability information.
    """
    cve_id = validate_cve_id(cve_id)

    await ctx.info(f'Looking up CVE: {cve_id}')
    logger.info(f'CVE lookup: {cve_id}')

    try:
        data = await shodan_cve_lookup(cve_id, timeout=timeout)
        result = _parse_cve(data)

        severity = result.cvss_v3.severity if result.cvss_v3 and result.cvss_v3.severity else 'N/A'
        score = (
            result.cvss_v3.base_score if result.cvss_v3 and result.cvss_v3.base_score else 'N/A'
        )

        await ctx.info(f'CVE lookup complete: {cve_id} — CVSS: {score} ({severity})')

        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'CVE lookup failed: {safe}')
        await ctx.error(f'CVE lookup failed: {safe}')
        raise safe


@mcp.tool(name='shodan-dns-resolve')
async def dns_resolve(
    ctx: Context,
    hostnames: str = Field(
        description='Comma-separated hostnames to resolve. '
        'Example: "google.com,bing.com,github.com". Maximum 100 hostnames.',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> DnsResolveResult:
    """Resolve hostnames to IP addresses using Shodan's DNS service.

    Useful for mapping domain names to IPs before performing IP lookups.
    Requires a Shodan API key.

    Returns:
        DnsResolveResult with hostname-to-IP mappings.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    hostnames = validate_hostnames(hostnames)

    await ctx.info(f'Resolving hostnames: {hostnames}')
    logger.info(f'DNS resolve: {hostnames}')

    try:
        data = await shodan_dns_resolve(hostnames, SHODAN_API_KEY, timeout=timeout)

        entries = [DnsResolveEntry(hostname=hostname, ip=ip) for hostname, ip in data.items()]

        result = DnsResolveResult(entries=entries)
        await ctx.info(f'Resolved {len(entries)} hostname(s)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'DNS resolve failed: {safe}')
        await ctx.error(f'DNS resolve failed: {safe}')
        raise safe


@mcp.tool(name='shodan-dns-reverse')
async def dns_reverse(
    ctx: Context,
    ips: str = Field(
        description='Comma-separated IP addresses for reverse DNS lookup. '
        'Example: "8.8.8.8,1.1.1.1". Maximum 100 IPs.',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> DnsReverseResult:
    """Reverse DNS lookup — find hostnames for IP addresses.

    Useful for identifying what domains are hosted on specific IPs.
    Requires a Shodan API key.

    Returns:
        DnsReverseResult with IP-to-hostnames mappings.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    # Validate each IP in the comma-separated list
    ip_list = [ip.strip() for ip in ips.split(',')]
    validated_ips = [validate_ip(ip) for ip in ip_list]
    ips_str = ','.join(validated_ips)

    await ctx.info(f'Reverse DNS lookup: {ips_str}')
    logger.info(f'DNS reverse: {ips_str}')

    try:
        data = await shodan_dns_reverse(ips_str, SHODAN_API_KEY, timeout=timeout)

        entries = [
            DnsReverseEntry(ip=ip, hostnames=hostnames if isinstance(hostnames, list) else [])
            for ip, hostnames in data.items()
        ]

        result = DnsReverseResult(entries=entries)
        await ctx.info(f'Reverse DNS complete for {len(entries)} IP(s)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'DNS reverse failed: {safe}')
        await ctx.error(f'DNS reverse failed: {safe}')
        raise safe


@mcp.tool(name='shodan-search-count')
async def search_count(
    ctx: Context,
    query: str = Field(
        description='Shodan search query. Same syntax as shodan-search. '
        'Examples: "apache port:8080", "vuln:CVE-2021-44228 country:US".',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> SearchCountResult:
    """Count how many hosts match a Shodan query WITHOUT consuming query credits.

    Use this to check result volume before running a full search.
    Requires a Shodan API key but does NOT consume query credits.

    Returns:
        SearchCountResult with total count.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    query = validate_query(query)

    await ctx.info(f'Counting results for: "{query}"')
    logger.info(f'Shodan search count: query="{query}"')

    try:
        data = await shodan_search_count(query, SHODAN_API_KEY, timeout=timeout)

        result = SearchCountResult(
            total=data.get('total', 0),
            query=query,
            facets=data.get('facets'),
        )

        await ctx.info(f'Count complete: {result.total} total match(es)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Search count failed: {safe}')
        await ctx.error(f'Search count failed: {safe}')
        raise safe


@mcp.tool(name='shodan-domain-info')
async def domain_info(
    ctx: Context,
    domain: str = Field(
        description='Domain name to look up. Example: "example.com".',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> DomainResult:
    """Get DNS information about a domain — subdomains, DNS records, and tags.

    Powerful for domain reconnaissance and subdomain discovery.
    Requires a Shodan API key.

    Returns:
        DomainResult with subdomains, DNS records, and domain tags.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    domain = validate_domain(domain)

    await ctx.info(f'Looking up domain: {domain}')
    logger.info(f'Domain info: {domain}')

    try:
        data = await shodan_domain_info(domain, SHODAN_API_KEY, timeout=timeout)

        records = []
        for record in data.get('data', []):
            records.append(
                DnsDomainRecord(
                    subdomain=record.get('subdomain', ''),
                    type=record.get('type', ''),
                    value=record.get('value', ''),
                    last_seen=record.get('last_seen'),
                )
            )

        result = DomainResult(
            domain=data.get('domain', domain),
            subdomains=data.get('subdomains', []),
            records=records,
            tags=data.get('tags') or None,
        )

        await ctx.info(
            f'Domain lookup complete: {len(result.subdomains)} subdomain(s), '
            f'{len(result.records)} DNS record(s)'
        )
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Domain info failed: {safe}')
        await ctx.error(f'Domain info failed: {safe}')
        raise safe


@mcp.tool(name='shodan-internetdb-lookup')
async def internetdb_lookup(
    ctx: Context,
    ip: str = Field(
        description='IP address to look up (IPv4). Example: "8.8.8.8".',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> InternetDbResult:
    """Quick, free IP intelligence from Shodan's InternetDB.

    Returns open ports, known vulnerabilities, hostnames, CPEs, and tags.
    This is FREE — no API key required. Faster but less detailed than shodan-ip-lookup.

    Returns:
        InternetDbResult with quick IP intelligence data.
    """
    ip = validate_ip(ip)

    await ctx.info(f'InternetDB lookup: {ip}')
    logger.info(f'InternetDB lookup: {ip}')

    try:
        data = await shodan_internetdb_lookup(ip, timeout=timeout)

        result = InternetDbResult(
            ip=data.get('ip', ip),
            hostnames=data.get('hostnames', []),
            ports=data.get('ports', []),
            cpes=data.get('cpes', []),
            vulns=data.get('vulns', []),
            tags=data.get('tags', []),
        )

        await ctx.info(
            f'InternetDB complete: {len(result.ports)} port(s), '
            f'{len(result.vulns)} vuln(s), {len(result.hostnames)} hostname(s)'
        )
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'InternetDB lookup failed: {safe}')
        await ctx.error(f'InternetDB lookup failed: {safe}')
        raise safe


@mcp.tool(name='shodan-honeypot-score')
async def honeypot_score(
    ctx: Context,
    ip: str = Field(
        description='IP address to check. Example: "8.8.8.8".',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> HoneypotResult:
    """Check if an IP address is likely a honeypot.

    Returns a probability score from 0.0 (not a honeypot) to 1.0 (definitely a honeypot).
    Useful for filtering scan results and identifying deceptive hosts.
    Requires a Shodan API key.

    Returns:
        HoneypotResult with IP address and honeypot probability score.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    ip = validate_ip(ip)

    await ctx.info(f'Checking honeypot score: {ip}')
    logger.info(f'Honeypot score: {ip}')

    try:
        score = await shodan_honeyscore(ip, SHODAN_API_KEY, timeout=timeout)

        result = HoneypotResult(
            ip=ip,
            score=score,
        )

        label = 'likely honeypot' if score > 0.5 else 'likely legitimate'
        await ctx.info(f'Honeypot score for {ip}: {score:.2f} ({label})')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Honeypot score failed: {safe}')
        await ctx.error(f'Honeypot score failed: {safe}')
        raise safe


@mcp.tool(name='shodan-api-info')
async def api_info(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> ApiInfoResult:
    """Check your Shodan API key usage — plan type, remaining credits, and limits.

    Useful for monitoring API usage and checking remaining query/scan credits.
    Requires a Shodan API key.

    Returns:
        ApiInfoResult with plan info and remaining credits.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Checking API key info')
    logger.info('API info lookup')

    try:
        data = await shodan_api_info(SHODAN_API_KEY, timeout=timeout)

        result = ApiInfoResult(
            plan=data.get('plan'),
            query_credits=data.get('query_credits'),
            scan_credits=data.get('scan_credits'),
            monitored_ips=data.get('monitored_ips'),
            unlocked=data.get('unlocked'),
            telnet=data.get('telnet'),
            https=data.get('https'),
        )

        await ctx.info(
            f'Plan: {result.plan}, '
            f'Query credits: {result.query_credits}, '
            f'Scan credits: {result.scan_credits}'
        )
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'API info failed: {safe}')
        await ctx.error(f'API info failed: {safe}')
        raise safe


@mcp.tool(name='shodan-my-ip')
async def my_ip(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> str:
    """Get your current external IP address as seen by Shodan.

    Useful for checking what IP address your requests are coming from.
    Requires a Shodan API key.

    Returns:
        Your external IP address as a string.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Looking up external IP')
    logger.info('My IP lookup')

    try:
        ip = await shodan_my_ip(SHODAN_API_KEY, timeout=timeout)
        await ctx.info(f'Your external IP: {ip}')
        return ip

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'My IP lookup failed: {safe}')
        await ctx.error(f'My IP lookup failed: {safe}')
        raise safe


@mcp.tool(name='shodan-search-cves')
async def search_cves(
    ctx: Context,
    is_kev: bool = Field(
        default=False,
        description='Only return CVEs in CISA Known Exploited Vulnerabilities catalog.',
    ),
    sort_by_epss: bool = Field(
        default=False,
        description='Sort results by EPSS score (most likely to be exploited first).',
    ),
    start_date: str = Field(
        default='',
        description='Filter CVEs published after this date (YYYY-MM-DD). Leave empty for no filter.',
    ),
    end_date: str = Field(
        default='',
        description='Filter CVEs published before this date (YYYY-MM-DD). Leave empty for no filter.',
    ),
    limit: int = Field(
        default=20,
        description='Maximum number of results (1-100).',
        ge=1,
        le=100,
    ),
    skip: int = Field(
        default=0,
        description='Number of results to skip (for pagination).',
        ge=0,
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> CveSearchResult:
    """Search CVEs in Shodan's vulnerability database with powerful filters.

    Filter by CISA KEV catalog, sort by EPSS exploit probability, and filter by date range.
    This is FREE — no API key required.

    Returns:
        CveSearchResult with matching CVEs and total count.
    """
    await ctx.info(f'Searching CVEs: kev={is_kev}, epss_sort={sort_by_epss}')
    logger.info(f'CVE search: kev={is_kev}, epss_sort={sort_by_epss}')

    try:
        data = await shodan_cve_search(
            is_kev=is_kev,
            sort_by_epss=sort_by_epss,
            skip=skip,
            limit=limit,
            start_date=start_date or None,
            end_date=end_date or None,
            timeout=timeout,
        )

        cves = [_parse_cve(cve) for cve in data.get('cves', [])]

        result = CveSearchResult(
            cves=cves,
            total=data.get('total', 0),
        )

        await ctx.info(f'CVE search complete: {result.total} total, returning {len(cves)}')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'CVE search failed: {safe}')
        await ctx.error(f'CVE search failed: {safe}')
        raise safe


@mcp.tool(name='shodan-search-cpes')
async def search_cpes(
    ctx: Context,
    product: str = Field(
        description='Product name to search for. Examples: "apache", "nginx", "openssh".',
    ),
    limit: int = Field(
        default=100,
        description='Maximum number of results.',
        ge=1,
        le=1000,
    ),
    skip: int = Field(
        default=0,
        description='Number of results to skip (for pagination).',
        ge=0,
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> CpeSearchResult:
    """Search CPE (Common Platform Enumeration) identifiers by product name.

    Useful for finding exact CPE strings to use in vulnerability lookups.
    This is FREE — no API key required.

    Returns:
        CpeSearchResult with matching CPE identifiers and total count.
    """
    product = validate_query(product)

    await ctx.info(f'Searching CPEs for product: "{product}"')
    logger.info(f'CPE search: product="{product}"')

    try:
        data = await shodan_cpe_search(
            product=product,
            skip=skip,
            limit=limit,
            timeout=timeout,
        )

        result = CpeSearchResult(
            cpes=data.get('cpes', []),
            total=data.get('total', 0),
        )

        await ctx.info(f'CPE search complete: {result.total} total, returning {len(result.cpes)}')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'CPE search failed: {safe}')
        await ctx.error(f'CPE search failed: {safe}')
        raise safe


@mcp.tool(name='shodan-list-facets')
async def list_facets(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> SearchFacetsResult:
    """List available search facets for Shodan queries.

    Facets let you break down search results by property (e.g., country, org, port).
    Use these with shodan-search-count for result distribution analysis.
    Requires a Shodan API key.

    Returns:
        SearchFacetsResult with list of available facet names.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Listing available search facets')
    logger.info('Search facets listing')

    try:
        data = await shodan_search_facets(SHODAN_API_KEY, timeout=timeout)
        result = SearchFacetsResult(facets=data if isinstance(data, list) else [])
        await ctx.info(f'Found {len(result.facets)} available facet(s)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Search facets listing failed: {safe}')
        await ctx.error(f'Search facets listing failed: {safe}')
        raise safe


@mcp.tool(name='shodan-list-filters')
async def list_filters(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> SearchFiltersResult:
    """List available search filters for Shodan queries.

    Filters let you narrow search results (e.g., port:, country:, org:, product:).
    Use these to discover all available filter options for shodan-search.
    Requires a Shodan API key.

    Returns:
        SearchFiltersResult with list of available filter names.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Listing available search filters')
    logger.info('Search filters listing')

    try:
        data = await shodan_search_filters(SHODAN_API_KEY, timeout=timeout)
        result = SearchFiltersResult(filters=data if isinstance(data, list) else [])
        await ctx.info(f'Found {len(result.filters)} available filter(s)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Search filters listing failed: {safe}')
        await ctx.error(f'Search filters listing failed: {safe}')
        raise safe


@mcp.tool(name='shodan-parse-query')
async def parse_query(
    ctx: Context,
    query: str = Field(
        description='Shodan search query to analyze. '
        'Example: "apache port:8080 country:US".',
    ),
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> QueryTokensResult:
    """Parse and analyze a Shodan search query into its components.

    Breaks down a query into attributes, filters, errors, and the remaining
    search string. Useful for debugging complex queries and understanding
    how Shodan interprets them.
    Requires a Shodan API key.

    Returns:
        QueryTokensResult with parsed query components.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    query = validate_query(query)

    await ctx.info(f'Parsing query: "{query}"')
    logger.info(f'Parse query: "{query}"')

    try:
        data = await shodan_search_tokens(query, SHODAN_API_KEY, timeout=timeout)

        result = QueryTokensResult(
            attributes=data.get('attributes', {}),
            errors=data.get('errors', []),
            filters=data.get('filters', []),
            string=data.get('string', ''),
        )

        filter_count = len(result.filters)
        error_count = len(result.errors)
        await ctx.info(
            f'Query parsed: {filter_count} filter(s), {error_count} error(s), '
            f'string="{result.string}"'
        )
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Parse query failed: {safe}')
        await ctx.error(f'Parse query failed: {safe}')
        raise safe


@mcp.tool(name='shodan-list-ports')
async def list_ports(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> PortsResult:
    """List port numbers that Shodan crawlers are actively scanning.

    Returns the list of ports that the Shodan crawlers are looking for on the Internet.
    Useful for understanding Shodan's scanning coverage.
    Requires a Shodan API key.

    Returns:
        PortsResult with list of scanned port numbers.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Listing Shodan crawled ports')
    logger.info('Ports listing')

    try:
        data = await shodan_ports(SHODAN_API_KEY, timeout=timeout)
        result = PortsResult(ports=data if isinstance(data, list) else [])
        await ctx.info(f'Shodan crawls {len(result.ports)} port(s)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Ports listing failed: {safe}')
        await ctx.error(f'Ports listing failed: {safe}')
        raise safe


@mcp.tool(name='shodan-list-protocols')
async def list_protocols(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> ProtocolsResult:
    """List protocols available for on-demand Shodan scanning.

    Returns the protocols that can be used when launching an on-demand scan.
    Requires a Shodan API key.

    Returns:
        ProtocolsResult with protocol names and descriptions.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Listing available protocols')
    logger.info('Protocols listing')

    try:
        data = await shodan_protocols(SHODAN_API_KEY, timeout=timeout)
        result = ProtocolsResult(protocols=data if isinstance(data, dict) else {})
        await ctx.info(f'Found {len(result.protocols)} available protocol(s)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Protocols listing failed: {safe}')
        await ctx.error(f'Protocols listing failed: {safe}')
        raise safe


@mcp.tool(name='shodan-account-profile')
async def account_profile(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> AccountProfileResult:
    """Get your Shodan account profile information.

    Returns account membership status, credits, display name, and creation date.
    Requires a Shodan API key.

    Returns:
        AccountProfileResult with account profile details.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Looking up account profile')
    logger.info('Account profile lookup')

    try:
        data = await shodan_account_profile(SHODAN_API_KEY, timeout=timeout)

        result = AccountProfileResult(
            member=data.get('member'),
            credits=data.get('credits'),
            display_name=data.get('display_name'),
            created=data.get('created'),
        )

        await ctx.info(f'Account: {result.display_name}, credits: {result.credits}')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'Account profile failed: {safe}')
        await ctx.error(f'Account profile failed: {safe}')
        raise safe


@mcp.tool(name='shodan-http-headers')
async def http_headers(
    ctx: Context,
    timeout: int = Field(
        default=DEFAULT_REQUEST_TIMEOUT,
        description=f'HTTP request timeout in seconds. Default: {DEFAULT_REQUEST_TIMEOUT}.',
        gt=0,
        le=120,
    ),
) -> HttpHeadersResult:
    """Show the HTTP headers your client sends when connecting to a web server.

    Useful for debugging and seeing what information your client exposes.
    Requires a Shodan API key.

    Returns:
        HttpHeadersResult with HTTP header name-value pairs.
    """
    if not SHODAN_API_KEY:
        await ctx.error(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )
        raise ValueError(
            'SHODAN_API_KEY environment variable is not set. '
            'Get a key at https://account.shodan.io/'
        )

    await ctx.info('Looking up HTTP headers')
    logger.info('HTTP headers lookup')

    try:
        data = await shodan_http_headers(SHODAN_API_KEY, timeout=timeout)
        result = HttpHeadersResult(headers=data if isinstance(data, dict) else {})
        await ctx.info(f'Found {len(result.headers)} HTTP header(s)')
        return result

    except Exception as e:
        safe = _sanitize_error(e)
        logger.error(f'HTTP headers lookup failed: {safe}')
        await ctx.error(f'HTTP headers lookup failed: {safe}')
        raise safe


def main():
    """Run the MCP server with CLI argument support."""
    logger.info('Starting Shodan MCP Server')
    mcp.run()


if __name__ == '__main__':
    main()
