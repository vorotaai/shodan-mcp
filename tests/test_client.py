"""Tests for the Shodan client validation functions."""

import httpx
import pytest
from unittest.mock import patch
from shodan_mcp.client import (
    _sanitize_error,
    validate_cve_id,
    validate_domain,
    validate_hostnames,
    validate_ip,
    validate_query,
)


class TestValidateIp:
    """Tests for validate_ip function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip('8.8.8.8') == '8.8.8.8'
        assert validate_ip('192.168.1.1') == '192.168.1.1'
        assert validate_ip('10.0.0.1') == '10.0.0.1'

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip('::1') == '::1'
        assert validate_ip('2001:4860:4860::8888') == '2001:4860:4860::8888'

    def test_rejects_empty(self):
        """Test that empty IP addresses are rejected."""
        with pytest.raises(ValueError, match='cannot be empty'):
            validate_ip('')

    def test_rejects_command_injection(self):
        """Test that command injection characters are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            validate_ip('8.8.8.8; rm -rf /')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_ip('8.8.8.8 | cat /etc/passwd')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_ip('8.8.8.8 & echo hacked')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_ip('$(whoami)')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_ip('`id`')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_ip('8.8.8.8&10.0.0.1')

    def test_rejects_hostname(self):
        """Test that hostnames are rejected (Shodan IP lookup only takes IPs)."""
        with pytest.raises(ValueError, match='[Ii]nvalid IP'):
            validate_ip('example.com')

        with pytest.raises(ValueError, match='[Ii]nvalid IP'):
            validate_ip('dns.google')

    def test_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        assert validate_ip('  8.8.8.8  ') == '8.8.8.8'

    def test_rejects_cidr(self):
        """Test that CIDR notation is rejected (Shodan expects single IPs)."""
        with pytest.raises(ValueError, match='[Ii]nvalid IP'):
            validate_ip('192.168.1.0/24')


class TestValidateQuery:
    """Tests for validate_query function."""

    def test_valid_queries(self):
        """Test valid Shodan search queries."""
        assert validate_query('apache') == 'apache'
        assert validate_query('port:8080') == 'port:8080'
        assert validate_query('apache port:8080 country:US') == 'apache port:8080 country:US'
        assert validate_query('product:nginx') == 'product:nginx'

    def test_rejects_empty(self):
        """Test that empty queries are rejected."""
        with pytest.raises(ValueError, match='cannot be empty'):
            validate_query('')

    def test_rejects_injection_chars(self):
        """Test that injection characters are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            validate_query('apache; rm -rf /')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_query('apache | cat /etc/passwd')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_query('$(whoami)')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_query('`id`')

    def test_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        assert validate_query('  apache  ') == 'apache'

    def test_preserves_internal_whitespace(self):
        """Test that internal whitespace in queries is preserved."""
        assert validate_query('apache port:80') == 'apache port:80'


class TestValidateCveId:
    """Tests for validate_cve_id function."""

    def test_valid_cve_ids(self):
        """Test valid CVE identifiers."""
        assert validate_cve_id('CVE-2021-44228') == 'CVE-2021-44228'
        assert validate_cve_id('CVE-2024-1234') == 'CVE-2024-1234'
        assert validate_cve_id('CVE-2026-25253') == 'CVE-2026-25253'

    def test_case_insensitive(self):
        """Test that lowercase CVE IDs are uppercased."""
        assert validate_cve_id('cve-2021-44228') == 'CVE-2021-44228'

    def test_rejects_empty(self):
        """Test that empty CVE IDs are rejected."""
        with pytest.raises(ValueError, match='cannot be empty'):
            validate_cve_id('')

    def test_rejects_invalid_format(self):
        """Test that invalid CVE ID formats are rejected."""
        with pytest.raises(ValueError, match='[Ii]nvalid CVE'):
            validate_cve_id('not-a-cve')

        with pytest.raises(ValueError, match='[Ii]nvalid CVE'):
            validate_cve_id('CVE-')

        with pytest.raises(ValueError, match='[Ii]nvalid CVE'):
            validate_cve_id('CVE-2021')

        with pytest.raises(ValueError, match='[Ii]nvalid CVE'):
            validate_cve_id('CVE-abcd-1234')

    def test_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        assert validate_cve_id('  CVE-2021-44228  ') == 'CVE-2021-44228'

    def test_rejects_injection_in_cve(self):
        """Test that injection characters within CVE-like strings are rejected."""
        with pytest.raises(ValueError, match='[Ii]nvalid CVE|forbidden characters'):
            validate_cve_id('CVE-2021-44228; rm -rf /')


class TestValidateHostnames:
    """Tests for validate_hostnames function."""

    def test_valid_single_hostname(self):
        """Test a single valid hostname."""
        assert validate_hostnames('google.com') == 'google.com'

    def test_valid_multiple_hostnames(self):
        """Test multiple comma-separated valid hostnames."""
        assert validate_hostnames('google.com,bing.com') == 'google.com,bing.com'

    def test_rejects_empty(self):
        """Test that empty hostnames are rejected."""
        with pytest.raises(ValueError, match='cannot be empty'):
            validate_hostnames('')

    def test_rejects_injection_chars(self):
        """Test that injection characters are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            validate_hostnames('google.com; rm -rf /')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_hostnames('google.com | cat /etc/passwd')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_hostnames('$(whoami)')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_hostnames('`id`')

    def test_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        assert validate_hostnames('  google.com  ') == 'google.com'
        assert validate_hostnames('google.com , bing.com') == 'google.com,bing.com'

    def test_rejects_invalid_hostname(self):
        """Test that invalid hostnames are rejected."""
        with pytest.raises(ValueError, match='[Ii]nvalid hostname'):
            validate_hostnames('goo gle.com')

        with pytest.raises(ValueError, match='[Ii]nvalid hostname'):
            validate_hostnames('-google.com')


class TestValidateDomain:
    """Tests for validate_domain function."""

    def test_valid_domains(self):
        """Test valid domain names."""
        assert validate_domain('example.com') == 'example.com'
        assert validate_domain('sub.example.com') == 'sub.example.com'

    def test_lowercases_domain(self):
        """Test that domains are lowercased."""
        assert validate_domain('EXAMPLE.COM') == 'example.com'

    def test_rejects_empty(self):
        """Test that empty domains are rejected."""
        with pytest.raises(ValueError, match='cannot be empty'):
            validate_domain('')

    def test_rejects_injection_chars(self):
        """Test that injection characters are rejected."""
        with pytest.raises(ValueError, match='forbidden characters'):
            validate_domain('example.com; rm -rf /')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_domain('example.com | cat /etc/passwd')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_domain('$(whoami)')

        with pytest.raises(ValueError, match='forbidden characters'):
            validate_domain('`id`')

    def test_rejects_invalid_domain(self):
        """Test that domains without dots are rejected."""
        with pytest.raises(ValueError, match='[Ii]nvalid domain'):
            validate_domain('localhost')

        with pytest.raises(ValueError, match='[Ii]nvalid domain'):
            validate_domain('nodots')

    def test_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        assert validate_domain('  example.com  ') == 'example.com'


class TestSanitizeError:
    """Tests for _sanitize_error function."""

    @patch('shodan_mcp.client.SHODAN_API_KEY', 'secret123key')
    def test_strips_api_key_from_message(self):
        """Test that the API key is replaced with *** in error messages."""
        err = RuntimeError('Request to https://api.shodan.io?key=secret123key failed')
        safe = _sanitize_error(err)
        assert 'secret123key' not in str(safe)
        assert '***' in str(safe)
        assert isinstance(safe, RuntimeError)

    @patch('shodan_mcp.client.SHODAN_API_KEY', 'secret123key')
    def test_strips_key_from_httpx_error(self):
        """Test sanitization works with httpx exception types."""
        err = httpx.HTTPStatusError(
            'Server error 500 for url https://api.shodan.io/shodan/host/search?key=secret123key&query=test',
            request=httpx.Request('GET', 'https://api.shodan.io'),
            response=httpx.Response(500),
        )
        safe = _sanitize_error(err)
        assert 'secret123key' not in str(safe)
        assert '***' in str(safe)
        # Falls back to Exception since HTTPStatusError needs extra args
        assert isinstance(safe, Exception)

    @patch('shodan_mcp.client.SHODAN_API_KEY', '')
    def test_no_key_set_passthrough(self):
        """Test that errors pass through unchanged when no API key is set."""
        err = RuntimeError('some error')
        safe = _sanitize_error(err)
        assert str(safe) == 'some error'

    @patch('shodan_mcp.client.SHODAN_API_KEY', 'mykey')
    def test_preserves_exception_type(self):
        """Test that the sanitized error preserves the original exception type."""
        err = ValueError('bad value with mykey inside')
        safe = _sanitize_error(err)
        assert isinstance(safe, ValueError)
        assert 'mykey' not in str(safe)
        assert '***' in str(safe)
