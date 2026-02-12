"""Constants for the Shodan MCP server."""

import os


# Logging
LOG_LEVEL = os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')

# Shodan API key (required for host lookup and search; not needed for CVE lookup)
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')

# Shodan API base URLs
SHODAN_BASE_URL = 'https://api.shodan.io'
SHODAN_CVEDB_URL = 'https://cvedb.shodan.io'
SHODAN_INTERNETDB_URL = 'https://internetdb.shodan.io'
# Default HTTP request timeout in seconds
DEFAULT_REQUEST_TIMEOUT = 30

# Characters that are forbidden in queries (command/injection prevention)
FORBIDDEN_QUERY_CHARS = frozenset(
    {
        ';',
        '|',
        '&',
        '$',
        '`',
        '(',
        ')',
        '{',
        '}',
        '<',
        '>',
        '\n',
        '\r',
    }
)
