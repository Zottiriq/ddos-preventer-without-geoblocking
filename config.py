# config.py

# --- APPLICATION LAYER (HTTP Proxy) LIMITS ---
# Limits applied to each individual IP address.
DEFAULT_RATE = 15
DEFAULT_BURST = 40
DEFAULT_CONN_LIMIT = 100
DEFAULT_BLOCK_SEC = 300  # 5 minutes

# <--- REMOVED: GEO-BLOCKING SETTINGS ARE NO LONGER NEEDED --->
# TRUSTED_COUNTRIES, COUNTRY_RATE_LIMIT, and COUNTRY_BLOCK_SEC are removed.

# --- TRANSPARENT PROXY AND PORT FORWARDING SETTINGS ---
# This list serves as a base for ports you want to protect manually.
# The auto-discovery feature will add other public ports to this list.
TARGET_PORTS = {
    22: 'tcp',       # Always protect the SSH port.
}

# The auto-discovery will classify these ports as 'http'.
# If you run a web service on a different port (e.g., 8000), add it here.
WELL_KNOWN_HTTP_PORTS = {80, 443, 5000, 8000, 8080}

# The internal ports our Python script will listen on.
# Make sure these ports are NOT in the lists above!
HTTP_PROXY_LISTEN_PORT = 8081
GENERIC_TCP_LISTEN_PORT = 9000

# --- SYSTEM AND SERVICE SETTINGS ---
DEFAULT_IPSET_NAME = "ddos_blockset"
DEFAULT_LOG_FILE = "/var/log/ddos-preventer.log"
IPTABLES_CHAIN = "DDOS_GATEWAY"