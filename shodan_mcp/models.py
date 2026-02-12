"""Pydantic models for the Shodan MCP server."""

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


class ShodanService(BaseModel):
    """Information about a service detected on a host port."""

    port: int = Field(description='Port number the service is running on')
    transport: str = Field(default='tcp', description='Transport protocol (tcp/udp)')
    product: Optional[str] = Field(default=None, description='Product name (e.g., Apache, nginx)')
    version: Optional[str] = Field(default=None, description='Product version string')
    banner: Optional[str] = Field(default=None, description='Service banner or response snippet')
    cpe: Optional[List[str]] = Field(
        default=None, description='Common Platform Enumeration identifiers'
    )


class ShodanLocation(BaseModel):
    """Geolocation information for a Shodan host."""

    city: Optional[str] = Field(default=None, description='City name')
    country_name: Optional[str] = Field(default=None, description='Country name')
    country_code: Optional[str] = Field(default=None, description='ISO country code (e.g., US)')
    latitude: Optional[float] = Field(default=None, description='Latitude coordinate')
    longitude: Optional[float] = Field(default=None, description='Longitude coordinate')


class ShodanHostResult(BaseModel):
    """Detailed information about a single host from Shodan."""

    ip_str: str = Field(description='IP address of the host')
    hostnames: List[str] = Field(
        default_factory=list, description='Hostnames associated with the IP'
    )
    ports: List[int] = Field(default_factory=list, description='List of open ports')
    os: Optional[str] = Field(default=None, description='Detected operating system')
    services: List[ShodanService] = Field(
        default_factory=list, description='Services detected on open ports'
    )
    location: Optional[ShodanLocation] = Field(default=None, description='Geolocation information')
    vulns: Optional[List[str]] = Field(
        default=None, description='Known vulnerability identifiers (CVE IDs)'
    )
    last_update: Optional[str] = Field(
        default=None, description='Timestamp of when the host was last seen by Shodan'
    )
    isp: Optional[str] = Field(default=None, description='Internet service provider')
    org: Optional[str] = Field(default=None, description='Organization that owns the IP')
    asn: Optional[str] = Field(
        default=None, description='Autonomous system number (e.g., AS15169)'
    )


class ShodanSearchResult(BaseModel):
    """Result set from a Shodan search query."""

    matches: List[ShodanHostResult] = Field(
        default_factory=list, description='Matching hosts from the search'
    )
    total: int = Field(default=0, description='Total number of matching results in Shodan')
    query: str = Field(description='The search query that was executed')


class CveReference(BaseModel):
    """A reference link for a CVE entry."""

    url: str = Field(description='Reference URL')
    source: Optional[str] = Field(
        default=None, description='Source of the reference (e.g., NVD, MITRE)'
    )


class CvssV3(BaseModel):
    """CVSS v3 scoring information for a CVE."""

    base_score: Optional[float] = Field(default=None, description='CVSS v3 base score (0.0-10.0)')
    severity: Optional[str] = Field(
        default=None, description='Severity rating (NONE, LOW, MEDIUM, HIGH, CRITICAL)'
    )
    vector_string: Optional[str] = Field(
        default=None, description='CVSS v3 vector string (e.g., CVSS:3.1/AV:N/AC:L/...)'
    )


class EpssScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data for a CVE."""

    score: Optional[float] = Field(default=None, description='EPSS probability score (0.0-1.0)')
    percentile: Optional[float] = Field(
        default=None, description='EPSS percentile ranking (0.0-1.0)'
    )


class CveResult(BaseModel):
    """Detailed information about a single CVE from Shodan CVE database."""

    cve_id: str = Field(description='CVE identifier (e.g., CVE-2021-44228)')
    summary: Optional[str] = Field(default=None, description='CVE description/summary')
    cvss_v3: Optional[CvssV3] = Field(default=None, description='CVSS v3 scoring details')
    epss: Optional[EpssScore] = Field(default=None, description='EPSS exploit prediction score')
    references: List[CveReference] = Field(
        default_factory=list, description='Reference links for the CVE'
    )
    cpes: List[str] = Field(default_factory=list, description='Affected CPE identifiers')
    published: Optional[str] = Field(default=None, description='Date the CVE was published')
    last_modified: Optional[str] = Field(
        default=None, description='Date the CVE was last modified'
    )


class DnsResolveEntry(BaseModel):
    """A single hostname-to-IP resolution result."""

    hostname: str = Field(description='The hostname that was resolved')
    ip: Optional[str] = Field(
        default=None, description='Resolved IP address, or null if unresolvable'
    )


class DnsResolveResult(BaseModel):
    """Result of resolving one or more hostnames to IP addresses."""

    entries: List[DnsResolveEntry] = Field(
        default_factory=list, description='Hostname-to-IP resolution entries'
    )


class DnsReverseEntry(BaseModel):
    """A single IP-to-hostnames reverse DNS result."""

    ip: str = Field(description='The IP address that was looked up')
    hostnames: List[str] = Field(
        default_factory=list, description='Hostnames associated with this IP'
    )


class DnsReverseResult(BaseModel):
    """Result of reverse DNS lookup for one or more IPs."""

    entries: List[DnsReverseEntry] = Field(
        default_factory=list, description='IP-to-hostnames reverse DNS entries'
    )


class SearchCountResult(BaseModel):
    """Result of a Shodan search count (total matches without full results)."""

    total: int = Field(description='Total number of matching results')
    query: str = Field(description='The search query that was executed')
    facets: Optional[Dict[str, Any]] = Field(
        default=None, description='Facet breakdown if facets were requested'
    )


class DnsDomainRecord(BaseModel):
    """A single DNS record for a domain."""

    subdomain: str = Field(description='Subdomain name (empty string for apex)')
    type: str = Field(description='DNS record type (A, AAAA, CNAME, MX, TXT, etc.)')
    value: str = Field(description='DNS record value')
    last_seen: Optional[str] = Field(
        default=None, description='When this record was last observed'
    )


class DomainResult(BaseModel):
    """DNS information about a domain including subdomains and records."""

    domain: str = Field(description='The domain that was queried')
    subdomains: List[str] = Field(default_factory=list, description='Discovered subdomain names')
    records: List[DnsDomainRecord] = Field(
        default_factory=list, description='DNS records for the domain'
    )
    tags: Optional[List[str]] = Field(
        default=None, description='Tags associated with this domain (e.g., ipv6, dmarc)'
    )


class InternetDbResult(BaseModel):
    """Quick IP intelligence from Shodan InternetDB (free, no API key)."""

    ip: str = Field(description='The IP address that was queried')
    hostnames: List[str] = Field(default_factory=list, description='Associated hostnames')
    ports: List[int] = Field(default_factory=list, description='Open ports')
    cpes: List[str] = Field(
        default_factory=list, description='CPE identifiers for detected software'
    )
    vulns: List[str] = Field(default_factory=list, description='Known CVE identifiers')
    tags: List[str] = Field(default_factory=list, description='Tags (e.g., cloud, vpn, honeypot)')


class HoneypotResult(BaseModel):
    """Honeypot likelihood score for an IP address."""

    ip: str = Field(description='The IP address that was scored')
    score: float = Field(
        description='Honeypot probability score (0.0 = not a honeypot, 1.0 = honeypot)'
    )


class ApiInfoResult(BaseModel):
    """Shodan API key usage and plan information."""

    plan: Optional[str] = Field(default=None, description='API plan name (e.g., dev, oss, basic)')
    query_credits: Optional[int] = Field(
        default=None, description='Remaining query credits for the current month'
    )
    scan_credits: Optional[int] = Field(
        default=None, description='Remaining scan credits for the current month'
    )
    monitored_ips: Optional[int] = Field(
        default=None, description='Number of IPs currently being monitored'
    )
    unlocked: Optional[bool] = Field(
        default=None, description='Whether the API key has been unlocked for paid features'
    )
    telnet: Optional[bool] = Field(default=None, description='Whether telnet access is enabled')
    https: Optional[bool] = Field(default=None, description='Whether HTTPS access is enabled')


class CveSearchResult(BaseModel):
    """Result set from a CVEDB CVE search."""

    cves: List[CveResult] = Field(default_factory=list, description='Matching CVE entries')
    total: int = Field(default=0, description='Total number of matching CVEs')


class CpeSearchResult(BaseModel):
    """Result set from a CVEDB CPE search."""

    cpes: List[str] = Field(default_factory=list, description='Matching CPE identifiers')
    total: int = Field(default=0, description='Total number of matching CPEs')


class SearchFacetsResult(BaseModel):
    """List of available search facets for Shodan queries."""

    facets: List[str] = Field(default_factory=list, description='Available search facet names')


class SearchFiltersResult(BaseModel):
    """List of available search filters for Shodan queries."""

    filters: List[str] = Field(default_factory=list, description='Available search filter names')


class QueryTokensResult(BaseModel):
    """Parsed/tokenized Shodan search query."""

    attributes: Dict[str, Any] = Field(
        default_factory=dict, description='Parsed query attributes and their values'
    )
    errors: List[str] = Field(default_factory=list, description='Errors found in the query')
    filters: List[str] = Field(
        default_factory=list, description='Filters used in the query'
    )
    string: str = Field(default='', description='The remaining unprocessed query string')


class PortsResult(BaseModel):
    """List of port numbers that Shodan crawlers scan."""

    ports: List[int] = Field(default_factory=list, description='Port numbers Shodan crawls')


class ProtocolsResult(BaseModel):
    """Protocols available for on-demand Shodan scanning."""

    protocols: Dict[str, str] = Field(
        default_factory=dict,
        description='Mapping of protocol names to their descriptions',
    )


class AccountProfileResult(BaseModel):
    """Shodan account profile information."""

    member: Optional[bool] = Field(default=None, description='Whether the account is a member')
    credits: Optional[int] = Field(default=None, description='Remaining query credits')
    display_name: Optional[str] = Field(default=None, description='Account display name')
    created: Optional[str] = Field(default=None, description='Account creation date')


class HttpHeadersResult(BaseModel):
    """HTTP headers as seen by Shodan when your client connects."""

    headers: Dict[str, str] = Field(
        default_factory=dict,
        description='HTTP header name-value pairs sent by your client',
    )


