"""Tests for the Shodan MCP server tools."""

import pytest
from shodan_mcp.server import (
    account_profile,
    api_info,
    cve_lookup,
    dns_resolve,
    dns_reverse,
    domain_info,
    honeypot_score,
    http_headers,
    internetdb_lookup,
    ip_lookup,
    list_facets,
    list_filters,
    list_ports,
    list_protocols,
    my_ip,
    parse_query,
    search,
    search_count,
    search_cpes,
    search_cves,
)
from unittest.mock import patch


# All tools that require API key need it patched to a test value
MOCK_API_KEY = 'test-api-key-12345'


class TestShodanIpLookup:
    """Tests for the shodan-ip-lookup tool."""

    @patch('shodan_mcp.server.shodan_host_lookup')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_lookup(self, mock_host_lookup, mock_context, sample_shodan_host_response):
        """Test a basic IP lookup invocation."""
        mock_host_lookup.return_value = sample_shodan_host_response

        result = await ip_lookup(
            ctx=mock_context,
            target='8.8.8.8',
            timeout=30,
        )

        assert result.ip_str == '8.8.8.8'
        assert 'dns.google' in result.hostnames
        assert len(result.services) == 2
        assert result.isp == 'Google LLC'
        assert result.org == 'Google LLC'
        assert result.asn == 'AS15169'
        assert 'CVE-2024-1234' in result.vulns
        assert result.location.city == 'Mountain View'
        assert result.location.country_name == 'United States'
        assert result.location.country_code == 'US'

        mock_host_lookup.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await ip_lookup(
                ctx=mock_context,
                target='8.8.8.8',
                timeout=30,
            )

    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_invalid_target(self, mock_context):
        """Test that invalid targets with injection characters are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            await ip_lookup(
                ctx=mock_context,
                target='; rm -rf /',
                timeout=30,
            )


class TestShodanSearch:
    """Tests for the shodan-search tool."""

    @patch('shodan_mcp.server.shodan_search')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_search(
        self, mock_search_api, mock_context, sample_shodan_search_response
    ):
        """Test a basic Shodan search invocation."""
        mock_search_api.return_value = sample_shodan_search_response

        result = await search(
            ctx=mock_context,
            query='apache',
            page=1,
            timeout=30,
        )

        assert result.total == 1
        assert len(result.matches) == 1
        assert result.matches[0].ip_str == '1.2.3.4'
        assert result.matches[0].ports == [80]
        assert result.matches[0].services[0].product == 'Apache'
        assert 'CVE-2021-41773' in result.matches[0].vulns
        assert result.query == 'apache'

        mock_search_api.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await search(
                ctx=mock_context,
                query='apache',
                page=1,
                timeout=30,
            )

    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_invalid_query(self, mock_context):
        """Test that injection characters in queries are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            await search(
                ctx=mock_context,
                query='$(whoami)',
                page=1,
                timeout=30,
            )


class TestShodanCveLookup:
    """Tests for the shodan-cve-lookup tool."""

    @patch('shodan_mcp.server.shodan_cve_lookup')
    async def test_basic_cve_lookup(self, mock_cve_api, mock_context, sample_cve_response):
        """Test a basic CVE lookup invocation."""
        mock_cve_api.return_value = sample_cve_response

        result = await cve_lookup(
            ctx=mock_context,
            cve_id='CVE-2021-44228',
            timeout=30,
        )

        assert result.cve_id == 'CVE-2021-44228'
        assert 'Log4j' in result.summary
        assert result.cvss_v3.base_score == 10.0
        assert result.cvss_v3.severity == 'CRITICAL'
        assert result.epss.score == 0.97565
        assert result.epss.percentile == 0.99996
        assert len(result.references) == 2
        assert len(result.cpes) == 1

        mock_cve_api.assert_called_once()

    async def test_invalid_cve_id(self, mock_context):
        """Test that invalid CVE IDs are rejected."""
        with pytest.raises(ValueError, match='Invalid CVE'):
            await cve_lookup(
                ctx=mock_context,
                cve_id='not-a-cve',
                timeout=30,
            )

    @patch('shodan_mcp.server.shodan_cve_lookup')
    async def test_case_insensitive_cve_id(self, mock_cve_api, mock_context):
        """Test that lowercase CVE IDs are accepted and normalized."""
        mock_cve_api.return_value = {
            'cve_id': 'CVE-2021-44228',
            'summary': 'Test summary',
            'cvss_v3': None,
            'epss': None,
            'references': [],
            'cpes': [],
            'published': '2021-12-10T00:00:00',
            'last_modified': '2023-11-06T00:00:00',
        }

        result = await cve_lookup(
            ctx=mock_context,
            cve_id='cve-2021-44228',
            timeout=30,
        )

        assert result.cve_id == 'CVE-2021-44228'


class TestDnsResolve:
    """Tests for the shodan-dns-resolve tool."""

    @patch('shodan_mcp.server.shodan_dns_resolve')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_dns_resolve(self, mock_dns_resolve, mock_context):
        """Test a basic DNS resolve invocation."""
        mock_dns_resolve.return_value = {
            'google.com': '142.250.80.46',
            'bing.com': '204.79.197.200',
        }

        result = await dns_resolve(
            ctx=mock_context,
            hostnames='google.com,bing.com',
            timeout=30,
        )

        assert len(result.entries) == 2
        hostnames_map = {e.hostname: e.ip for e in result.entries}
        assert hostnames_map['google.com'] == '142.250.80.46'
        assert hostnames_map['bing.com'] == '204.79.197.200'

        mock_dns_resolve.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await dns_resolve(
                ctx=mock_context,
                hostnames='google.com,bing.com',
                timeout=30,
            )


class TestDnsReverse:
    """Tests for the shodan-dns-reverse tool."""

    @patch('shodan_mcp.server.shodan_dns_reverse')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_dns_reverse(self, mock_dns_reverse, mock_context):
        """Test a basic DNS reverse lookup invocation."""
        mock_dns_reverse.return_value = {
            '8.8.8.8': ['dns.google'],
            '1.1.1.1': ['one.one.one.one'],
        }

        result = await dns_reverse(
            ctx=mock_context,
            ips='8.8.8.8,1.1.1.1',
            timeout=30,
        )

        assert len(result.entries) == 2
        ip_map = {e.ip: e.hostnames for e in result.entries}
        assert 'dns.google' in ip_map['8.8.8.8']
        assert 'one.one.one.one' in ip_map['1.1.1.1']

        mock_dns_reverse.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await dns_reverse(
                ctx=mock_context,
                ips='8.8.8.8,1.1.1.1',
                timeout=30,
            )


class TestSearchCount:
    """Tests for the shodan-search-count tool."""

    @patch('shodan_mcp.server.shodan_search_count')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_search_count(self, mock_search_count, mock_context):
        """Test a basic search count invocation."""
        mock_search_count.return_value = {
            'total': 12345,
            'facets': {},
        }

        result = await search_count(
            ctx=mock_context,
            query='apache',
            timeout=30,
        )

        assert result.total == 12345
        assert result.query == 'apache'

        mock_search_count.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await search_count(
                ctx=mock_context,
                query='apache',
                timeout=30,
            )


class TestDomainInfo:
    """Tests for the shodan-domain-info tool."""

    @patch('shodan_mcp.server.shodan_domain_info')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_domain_info(self, mock_domain_info, mock_context):
        """Test a basic domain info invocation."""
        mock_domain_info.return_value = {
            'domain': 'example.com',
            'subdomains': ['www', 'mail'],
            'data': [
                {
                    'subdomain': 'www',
                    'type': 'A',
                    'value': '1.2.3.4',
                    'last_seen': '2026-02-10',
                },
            ],
            'tags': ['ipv6'],
        }

        result = await domain_info(
            ctx=mock_context,
            domain='example.com',
            timeout=30,
        )

        assert result.domain == 'example.com'
        assert 'www' in result.subdomains
        assert 'mail' in result.subdomains
        assert len(result.records) == 1
        assert result.records[0].subdomain == 'www'
        assert result.records[0].type == 'A'
        assert result.records[0].value == '1.2.3.4'
        assert 'ipv6' in result.tags

        mock_domain_info.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await domain_info(
                ctx=mock_context,
                domain='example.com',
                timeout=30,
            )


class TestInternetdbLookup:
    """Tests for the shodan-internetdb-lookup tool."""

    @patch('shodan_mcp.server.shodan_internetdb_lookup')
    async def test_basic_internetdb_lookup(self, mock_internetdb, mock_context):
        """Test a basic InternetDB lookup invocation."""
        mock_internetdb.return_value = {
            'ip': '8.8.8.8',
            'hostnames': ['dns.google'],
            'ports': [53, 443],
            'cpes': ['cpe:/a:google:dns'],
            'vulns': ['CVE-2024-1234'],
            'tags': ['cloud'],
        }

        result = await internetdb_lookup(
            ctx=mock_context,
            ip='8.8.8.8',
            timeout=30,
        )

        assert result.ip == '8.8.8.8'
        assert 'dns.google' in result.hostnames
        assert 53 in result.ports
        assert 443 in result.ports
        assert 'cpe:/a:google:dns' in result.cpes
        assert 'CVE-2024-1234' in result.vulns
        assert 'cloud' in result.tags

        mock_internetdb.assert_called_once()


class TestHoneypotScore:
    """Tests for the shodan-honeypot-score tool."""

    @patch('shodan_mcp.server.shodan_honeyscore')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_honeypot_score(self, mock_honeyscore, mock_context):
        """Test a basic honeypot score invocation."""
        mock_honeyscore.return_value = 0.3

        result = await honeypot_score(
            ctx=mock_context,
            ip='8.8.8.8',
            timeout=30,
        )

        assert result.ip == '8.8.8.8'
        assert result.score == 0.3

        mock_honeyscore.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await honeypot_score(
                ctx=mock_context,
                ip='8.8.8.8',
                timeout=30,
            )


class TestApiInfo:
    """Tests for the shodan-api-info tool."""

    @patch('shodan_mcp.server.shodan_api_info')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_api_info(self, mock_api_info, mock_context):
        """Test a basic API info invocation."""
        mock_api_info.return_value = {
            'plan': 'dev',
            'query_credits': 100,
            'scan_credits': 50,
            'monitored_ips': 0,
            'unlocked': True,
            'telnet': False,
            'https': True,
        }

        result = await api_info(
            ctx=mock_context,
            timeout=30,
        )

        assert result.plan == 'dev'
        assert result.query_credits == 100
        assert result.scan_credits == 50
        assert result.monitored_ips == 0
        assert result.unlocked is True
        assert result.telnet is False
        assert result.https is True

        mock_api_info.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await api_info(
                ctx=mock_context,
                timeout=30,
            )


class TestMyIp:
    """Tests for the shodan-my-ip tool."""

    @patch('shodan_mcp.server.shodan_my_ip')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_my_ip(self, mock_my_ip, mock_context):
        """Test a basic my IP invocation."""
        mock_my_ip.return_value = '203.0.113.1'

        result = await my_ip(
            ctx=mock_context,
            timeout=30,
        )

        assert result == '203.0.113.1'

        mock_my_ip.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await my_ip(
                ctx=mock_context,
                timeout=30,
            )


class TestSearchCves:
    """Tests for the shodan-search-cves tool."""

    @patch('shodan_mcp.server.shodan_cve_search')
    async def test_basic_search_cves(self, mock_cve_search, mock_context):
        """Test a basic CVE search invocation."""
        mock_cve_search.return_value = {
            'cves': [
                {
                    'cve_id': 'CVE-2021-44228',
                    'summary': 'Log4j RCE',
                    'cvss_v3': {
                        'base_score': 10.0,
                        'severity': 'CRITICAL',
                    },
                    'epss': {
                        'score': 0.97565,
                    },
                    'references': [],
                    'cpes': [],
                    'published': '2021-12-10T00:00:00',
                    'last_modified': '2023-11-06T00:00:00',
                },
            ],
            'total': 1,
        }

        result = await search_cves(
            ctx=mock_context,
            is_kev=False,
            sort_by_epss=False,
            start_date='',
            end_date='',
            limit=20,
            skip=0,
            timeout=30,
        )

        assert result.total == 1
        assert len(result.cves) == 1
        assert result.cves[0].cve_id == 'CVE-2021-44228'
        assert result.cves[0].summary == 'Log4j RCE'
        assert result.cves[0].cvss_v3.base_score == 10.0
        assert result.cves[0].cvss_v3.severity == 'CRITICAL'
        assert result.cves[0].epss.score == 0.97565

        mock_cve_search.assert_called_once()


class TestSearchCpes:
    """Tests for the shodan-search-cpes tool."""

    @patch('shodan_mcp.server.shodan_cpe_search')
    async def test_basic_search_cpes(self, mock_cpe_search, mock_context):
        """Test a basic CPE search invocation."""
        mock_cpe_search.return_value = {
            'cpes': [
                'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
                'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*',
            ],
            'total': 2,
        }

        result = await search_cpes(
            ctx=mock_context,
            product='apache',
            limit=100,
            skip=0,
            timeout=30,
        )

        assert result.total == 2
        assert len(result.cpes) == 2
        assert 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*' in result.cpes
        assert 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' in result.cpes

        mock_cpe_search.assert_called_once()


class TestListFacets:
    """Tests for the shodan-list-facets tool."""

    @patch('shodan_mcp.server.shodan_search_facets')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_list_facets(self, mock_facets, mock_context):
        """Test a basic facets listing invocation."""
        mock_facets.return_value = ['country', 'org', 'port', 'asn', 'isp']

        result = await list_facets(ctx=mock_context, timeout=30)

        assert len(result.facets) == 5
        assert 'country' in result.facets
        assert 'port' in result.facets

        mock_facets.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await list_facets(ctx=mock_context, timeout=30)


class TestListFilters:
    """Tests for the shodan-list-filters tool."""

    @patch('shodan_mcp.server.shodan_search_filters')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_list_filters(self, mock_filters, mock_context):
        """Test a basic filters listing invocation."""
        mock_filters.return_value = ['port', 'city', 'country', 'net', 'org', 'product']

        result = await list_filters(ctx=mock_context, timeout=30)

        assert len(result.filters) == 6
        assert 'port' in result.filters
        assert 'country' in result.filters

        mock_filters.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await list_filters(ctx=mock_context, timeout=30)


class TestParseQuery:
    """Tests for the shodan-parse-query tool."""

    @patch('shodan_mcp.server.shodan_search_tokens')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_parse_query(self, mock_tokens, mock_context):
        """Test a basic query parsing invocation."""
        mock_tokens.return_value = {
            'attributes': {'ports': [8080]},
            'errors': [],
            'filters': ['port'],
            'string': 'apache',
        }

        result = await parse_query(
            ctx=mock_context,
            query='apache port:8080',
            timeout=30,
        )

        assert result.string == 'apache'
        assert 'port' in result.filters
        assert result.attributes == {'ports': [8080]}
        assert result.errors == []

        mock_tokens.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await parse_query(ctx=mock_context, query='apache', timeout=30)

    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_invalid_query(self, mock_context):
        """Test that injection characters in queries are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            await parse_query(ctx=mock_context, query='$(whoami)', timeout=30)


class TestListPorts:
    """Tests for the shodan-list-ports tool."""

    @patch('shodan_mcp.server.shodan_ports')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_list_ports(self, mock_ports, mock_context):
        """Test a basic ports listing invocation."""
        mock_ports.return_value = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]

        result = await list_ports(ctx=mock_context, timeout=30)

        assert len(result.ports) == 9
        assert 80 in result.ports
        assert 443 in result.ports

        mock_ports.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await list_ports(ctx=mock_context, timeout=30)


class TestListProtocols:
    """Tests for the shodan-list-protocols tool."""

    @patch('shodan_mcp.server.shodan_protocols')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_list_protocols(self, mock_protocols, mock_context):
        """Test a basic protocols listing invocation."""
        mock_protocols.return_value = {
            'dns-tcp': 'DNS over TCP',
            'http': 'HTTP',
            'https': 'HTTPS',
            'ssh': 'SSH',
        }

        result = await list_protocols(ctx=mock_context, timeout=30)

        assert len(result.protocols) == 4
        assert result.protocols['http'] == 'HTTP'
        assert result.protocols['ssh'] == 'SSH'

        mock_protocols.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await list_protocols(ctx=mock_context, timeout=30)


class TestAccountProfile:
    """Tests for the shodan-account-profile tool."""

    @patch('shodan_mcp.server.shodan_account_profile')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_account_profile(self, mock_profile, mock_context):
        """Test a basic account profile invocation."""
        mock_profile.return_value = {
            'member': True,
            'credits': 100,
            'display_name': 'testuser',
            'created': '2024-01-15T00:00:00',
        }

        result = await account_profile(ctx=mock_context, timeout=30)

        assert result.member is True
        assert result.credits == 100
        assert result.display_name == 'testuser'
        assert result.created == '2024-01-15T00:00:00'

        mock_profile.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await account_profile(ctx=mock_context, timeout=30)


class TestHttpHeaders:
    """Tests for the shodan-http-headers tool."""

    @patch('shodan_mcp.server.shodan_http_headers')
    @patch('shodan_mcp.server.SHODAN_API_KEY', MOCK_API_KEY)
    async def test_basic_http_headers(self, mock_headers, mock_context):
        """Test a basic HTTP headers invocation."""
        mock_headers.return_value = {
            'Host': 'api.shodan.io',
            'User-Agent': 'python-httpx/0.28.0',
            'Accept': '*/*',
        }

        result = await http_headers(ctx=mock_context, timeout=30)

        assert len(result.headers) == 3
        assert result.headers['Host'] == 'api.shodan.io'
        assert 'User-Agent' in result.headers

        mock_headers.assert_called_once()

    @patch('shodan_mcp.server.SHODAN_API_KEY', '')
    async def test_missing_api_key(self, mock_context):
        """Test that missing API key raises an error."""
        with pytest.raises(ValueError, match='SHODAN_API_KEY'):
            await http_headers(ctx=mock_context, timeout=30)


