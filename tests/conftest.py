"""Test fixtures for the Shodan MCP server."""

import pytest
from unittest.mock import AsyncMock


@pytest.fixture
def mock_context():
    """Create a mock MCP context."""
    context = AsyncMock()
    context.info = AsyncMock()
    context.error = AsyncMock()
    context.warning = AsyncMock()
    return context


@pytest.fixture
def sample_shodan_host_response():
    """Sample Shodan host lookup API response for 8.8.8.8."""
    return {
        'ip_str': '8.8.8.8',
        'hostnames': ['dns.google'],
        'ports': [53, 443],
        'os': None,
        'isp': 'Google LLC',
        'org': 'Google LLC',
        'asn': 'AS15169',
        'last_update': '2026-02-10T12:00:00.000000',
        'vulns': ['CVE-2024-1234'],
        'data': [
            {
                'port': 53,
                'transport': 'udp',
                'product': 'Google DNS',
                'version': None,
                'data': 'DNS server banner',
                'cpe': ['cpe:/a:google:dns'],
            },
            {
                'port': 443,
                'transport': 'tcp',
                'product': 'Google Frontend',
                'version': '2.0',
                'data': 'HTTP/1.1 200 OK',
                'cpe': [],
            },
        ],
        'location': {
            'city': 'Mountain View',
            'country_name': 'United States',
            'country_code': 'US',
            'latitude': 37.386,
            'longitude': -122.0838,
        },
    }


@pytest.fixture
def sample_shodan_search_response():
    """Sample Shodan search API response."""
    return {
        'matches': [
            {
                'ip_str': '1.2.3.4',
                'hostnames': ['example.com'],
                'port': 80,
                'transport': 'tcp',
                'product': 'Apache',
                'version': '2.4.49',
                'data': 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.49',
                'os': 'Linux',
                'location': {
                    'city': 'San Francisco',
                    'country_name': 'United States',
                    'country_code': 'US',
                    'latitude': 37.7749,
                    'longitude': -122.4194,
                },
                'vulns': ['CVE-2021-41773'],
                'isp': 'Cloudflare',
                'org': 'Cloudflare',
                'asn': 'AS13335',
            },
        ],
        'total': 1,
    }


@pytest.fixture
def sample_cve_response():
    """Sample Shodan CVE database API response for CVE-2021-44228."""
    return {
        'cve_id': 'CVE-2021-44228',
        'summary': (
            'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, '
            'log messages, and parameters do not protect against attacker controlled LDAP '
            'and other JNDI related endpoints.'
        ),
        'cvss_v3': {
            'base_score': 10.0,
            'severity': 'CRITICAL',
            'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        },
        'epss': {
            'score': 0.97565,
            'percentile': 0.99996,
        },
        'references': [
            {
                'url': 'https://logging.apache.org/log4j/2.x/security.html',
                'source': 'apache',
            },
            {
                'url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
                'source': 'nvd',
            },
        ],
        'cpes': ['cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'],
        'published': '2021-12-10T00:00:00',
        'last_modified': '2023-11-06T00:00:00',
    }


