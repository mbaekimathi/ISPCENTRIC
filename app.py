import json
import logging
import os
import re
import socket
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

import pymysql
import routeros_api
from cryptography.fernet import Fernet
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")
# Increase request timeout for MikroTik operations
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("isp-mtaani")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "isp_mtaani"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True,
}

FERNET_KEY = os.getenv("MIKROTIK_CRED_KEY", "")
FERNET_KEY_PATH = os.getenv("MIKROTIK_CRED_KEY_PATH", "data/fernet.key")

# Router API socket timeout (seconds). Increase if requests time out with slow routers.
def _router_timeout():
    try:
        return int(os.getenv("ROUTER_API_TIMEOUT", "15"))
    except (TypeError, ValueError):
        return 15
ROUTER_API_TIMEOUT = _router_timeout()


def get_db_connection():
    return pymysql.connect(**DB_CONFIG)


def get_server_connection():
    server_config = DB_CONFIG.copy()
    server_config.pop("database", None)
    return pymysql.connect(**server_config)


def get_cipher():
    if FERNET_KEY:
        return Fernet(FERNET_KEY.encode())

    key_path = os.path.abspath(FERNET_KEY_PATH)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    if os.path.exists(key_path):
        with open(key_path, "rb") as handle:
            return Fernet(handle.read().strip())

    new_key = Fernet.generate_key()
    with open(key_path, "wb") as handle:
        handle.write(new_key)
    return Fernet(new_key)


def ensure_db_and_tables():
    create_db_sql = f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['database']}`;"
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS routers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        router_name VARCHAR(100) NOT NULL,
        router_role ENUM('core', 'access', 'edge') NOT NULL,
        management_ip VARCHAR(45) NOT NULL,
        api_port INT NOT NULL,
        use_ssl BOOLEAN NOT NULL,
        api_username VARCHAR(100) NOT NULL,
        api_password_encrypted TEXT NOT NULL,
        status ENUM('ACTIVE', 'ERROR') NOT NULL,
        error_reason TEXT NULL,
        identity_json JSON NULL,
        resource_json JSON NULL,
        last_verified_at DATETIME NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    create_pppoe_table_sql = """
    CREATE TABLE IF NOT EXISTS pppoe_routers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        mikrotik_router_id INT NOT NULL,
        customer_name VARCHAR(150) NOT NULL,
        phone_number VARCHAR(40) NOT NULL,
        pppoe_username VARCHAR(100) NOT NULL,
        pppoe_password_encrypted TEXT NOT NULL,
        mikrotik_secret_id VARCHAR(50) NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        upload_speed_mbps DECIMAL(10,2) NULL,
        download_speed_mbps DECIMAL(10,2) NULL,
        max_devices INT NULL DEFAULT 1,
        mikrotik_queue_id VARCHAR(50) NULL,
        expiration_date DATETIME NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE KEY unique_username_per_router (mikrotik_router_id, pppoe_username),
        FOREIGN KEY (mikrotik_router_id) REFERENCES routers(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    create_subscription_plans_table_sql = """
    CREATE TABLE IF NOT EXISTS subscription_plans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        plan_name VARCHAR(150) NOT NULL,
        duration_days INT NOT NULL,
        download_speed_mbps DECIMAL(10,2) NOT NULL,
        upload_speed_mbps DECIMAL(10,2) NOT NULL,
        cost DECIMAL(10,2) NOT NULL,
        data_cap_gb DECIMAL(10,2) NULL,
        cap_reset_days INT NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    create_settings_table_sql = """
    CREATE TABLE IF NOT EXISTS settings (
        `key` VARCHAR(100) PRIMARY KEY,
        value TEXT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    create_usage_daily_sql = """
    CREATE TABLE IF NOT EXISTS usage_daily (
        id INT AUTO_INCREMENT PRIMARY KEY,
        router_id INT NOT NULL,
        pppoe_username VARCHAR(100) NOT NULL,
        usage_date DATE NOT NULL,
        bytes_sent BIGINT NOT NULL DEFAULT 0,
        bytes_received BIGINT NOT NULL DEFAULT 0,
        UNIQUE KEY unique_router_user_date (router_id, pppoe_username, usage_date),
        FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    create_billing_payments_sql = """
    CREATE TABLE IF NOT EXISTS billing_payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        router_id INT NOT NULL,
        user_id INT NOT NULL,
        payment_year INT NOT NULL,
        payment_month TINYINT NOT NULL,
        is_paid TINYINT(1) NOT NULL DEFAULT 0,
        paid_at DATETIME NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE KEY unique_router_user_year_month (router_id, user_id, payment_year, payment_month),
        FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES pppoe_routers(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    create_hotspot_plan_requests_sql = """
    CREATE TABLE IF NOT EXISTS hotspot_plan_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        plan_id INT NULL,
        plan_name VARCHAR(150) NULL,
        customer_name VARCHAR(150) NULL,
        phone_number VARCHAR(40) NULL,
        hotspot_mac VARCHAR(80) NULL,
        client_ip VARCHAR(45) NULL,
        redirect_dst TEXT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        created_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    create_hotspot_access_sessions_sql = """
    CREATE TABLE IF NOT EXISTS hotspot_access_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        router_id INT NOT NULL,
        hotspot_plan_request_id INT NULL,
        plan_id INT NULL,
        plan_name VARCHAR(150) NULL,
        customer_name VARCHAR(150) NULL,
        phone_number VARCHAR(40) NULL,
        hotspot_mac VARCHAR(80) NULL,
        client_ip VARCHAR(45) NULL,
        granted_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'active',
        updated_at DATETIME NOT NULL,
        INDEX idx_hotspot_access_router_status (router_id, status),
        INDEX idx_hotspot_access_expires (expires_at),
        FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    
    # Add new columns if they don't exist (for existing databases)
    alter_pppoe_table_sql = """
    ALTER TABLE pppoe_routers
    ADD COLUMN IF NOT EXISTS upload_speed_mbps DECIMAL(10,2) NULL,
    ADD COLUMN IF NOT EXISTS download_speed_mbps DECIMAL(10,2) NULL,
    ADD COLUMN IF NOT EXISTS max_devices INT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS mikrotik_queue_id VARCHAR(50) NULL,
    ADD COLUMN IF NOT EXISTS expiration_date DATETIME NULL,
    ADD COLUMN IF NOT EXISTS mikrotik_router_id INT NULL;
    """
    with get_server_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(create_db_sql)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(create_table_sql)
            cur.execute(create_pppoe_table_sql)
            cur.execute(create_subscription_plans_table_sql)
            cur.execute(create_settings_table_sql)
            cur.execute(create_usage_daily_sql)
            cur.execute(create_billing_payments_sql)
            cur.execute(create_hotspot_plan_requests_sql)
            cur.execute(create_hotspot_access_sessions_sql)
            # Always try to add newer columns (ignore if already exist)
            for col_sql in [
                "ALTER TABLE subscription_plans ADD COLUMN data_cap_gb DECIMAL(10,2) NULL",
                "ALTER TABLE subscription_plans ADD COLUMN cap_reset_days INT NULL",
                "ALTER TABLE pppoe_routers ADD COLUMN data_usage_bytes_this_period BIGINT NOT NULL DEFAULT 0",
                "ALTER TABLE pppoe_routers ADD COLUMN cap_reset_at DATETIME NULL",
                "ALTER TABLE pppoe_routers ADD COLUMN last_seen_cumulative_bytes BIGINT NOT NULL DEFAULT 0",
                "ALTER TABLE pppoe_routers ADD COLUMN over_cap_suspended TINYINT(1) NOT NULL DEFAULT 0",
                "ALTER TABLE pppoe_routers ADD COLUMN customer_wifi_ssid VARCHAR(100) NULL",
                "ALTER TABLE pppoe_routers ADD COLUMN customer_wifi_password_encrypted TEXT NULL",
                "ALTER TABLE pppoe_routers ADD COLUMN plan_allocated_at DATETIME NULL",
                "ALTER TABLE pppoe_routers ADD COLUMN last_seen_bytes_sent BIGINT NOT NULL DEFAULT 0",
                "ALTER TABLE pppoe_routers ADD COLUMN last_seen_bytes_received BIGINT NOT NULL DEFAULT 0",
                "ALTER TABLE pppoe_routers ADD COLUMN guest_network_enabled TINYINT(1) NOT NULL DEFAULT 0",
            ]:
                try:
                    cur.execute(col_sql)
                except Exception:  # noqa: BLE001
                    pass
            # Try to add new columns (will fail silently if they exist)
            try:
                cur.execute(alter_pppoe_table_sql.replace("IF NOT EXISTS", "").replace("ADD COLUMN IF NOT EXISTS", "ADD COLUMN"))
            except Exception:  # noqa: BLE001
                # Columns might already exist, try individual ALTER statements
                for col_sql in [
                    "ALTER TABLE pppoe_routers ADD COLUMN upload_speed_mbps DECIMAL(10,2) NULL",
                    "ALTER TABLE pppoe_routers ADD COLUMN download_speed_mbps DECIMAL(10,2) NULL",
                    "ALTER TABLE pppoe_routers ADD COLUMN max_devices INT NULL DEFAULT 1",
                    "ALTER TABLE pppoe_routers ADD COLUMN mikrotik_queue_id VARCHAR(50) NULL",
                    "ALTER TABLE pppoe_routers ADD COLUMN expiration_date DATETIME NULL",
                    "ALTER TABLE pppoe_routers ADD COLUMN mikrotik_router_id INT NULL",
                ]:
                    try:
                        cur.execute(col_sql)
                    except Exception:  # noqa: BLE001
                        pass  # Column already exists
                
                # Add foreign key constraint if mikrotik_router_id column exists but constraint doesn't
                try:
                    cur.execute("""
                        SELECT COUNT(*) as cnt 
                        FROM information_schema.KEY_COLUMN_USAGE 
                        WHERE TABLE_SCHEMA = DATABASE() 
                        AND TABLE_NAME = 'pppoe_routers' 
                        AND COLUMN_NAME = 'mikrotik_router_id' 
                        AND CONSTRAINT_NAME != 'PRIMARY'
                    """)
                    result = cur.fetchone()
                    if result and result.get('cnt', 0) == 0:
                        # Try to add foreign key (may fail if routers table doesn't exist or data exists)
                        try:
                            cur.execute("""
                                ALTER TABLE pppoe_routers 
                                ADD CONSTRAINT fk_pppoe_mikrotik_router 
                                FOREIGN KEY (mikrotik_router_id) REFERENCES routers(id) ON DELETE CASCADE
                            """)
                        except Exception:  # noqa: BLE001
                            pass  # Constraint might already exist or can't be added
                except Exception:  # noqa: BLE001
                    pass
                
                # Add unique constraint for username per router if it doesn't exist
                try:
                    cur.execute("""
                        SELECT COUNT(*) as cnt 
                        FROM information_schema.TABLE_CONSTRAINTS 
                        WHERE TABLE_SCHEMA = DATABASE() 
                        AND TABLE_NAME = 'pppoe_routers' 
                        AND CONSTRAINT_NAME = 'unique_username_per_router'
                    """)
                    result = cur.fetchone()
                    if result and result.get('cnt', 0) == 0:
                        cur.execute("""
                            ALTER TABLE pppoe_routers 
                            ADD UNIQUE KEY unique_username_per_router (mikrotik_router_id, pppoe_username)
                        """)
                except Exception:  # noqa: BLE001
                    pass  # Constraint might already exist


def sanitize_error_message(message: str) -> str:
    if not message:
        return "Unknown error"
    redacted = message
    redacted = re.sub(r"=password=[^ ]+", "=password=REDACTED", redacted)
    redacted = re.sub(r"password=[^ ,)]+", "password=REDACTED", redacted, flags=re.IGNORECASE)
    return redacted[:500]


def compact_router_error_message(message: str) -> str:
    """Return short, user-facing router error text for UI toasts."""
    sanitized = sanitize_error_message(message or "")
    lower = sanitized.lower()
    if "private ip address" in lower or "winerror 10051" in lower or "unreachable network" in lower:
        return "Router is unreachable from this host (private IP route issue). Use same LAN, VPN, or public IP with port forwarding."
    if "timed out" in lower or "timeout" in lower:
        return "Router connection timed out. Check API service/firewall/port and network route."
    if "connection refused" in lower or "refused" in lower:
        return "Router refused connection. Verify API port and RouterOS firewall allow this server."
    one_line = " ".join(sanitized.split())
    return one_line[:220] + ("..." if len(one_line) > 220 else "")


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is a private (non-routable) IP address."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1])
        
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        # 10.0.0.0/8
        if first == 10:
            return True
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        # 127.0.0.0/8 (localhost)
        if first == 127:
            return True
        return False
    except (ValueError, AttributeError):
        return False


def get_server_public_ip():
    """Get the public IP address of the server (for reference when setting up firewall rules)."""
    try:
        # Try multiple services for reliability
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ifconfig.me/ip',
        ]
        
        for service in services:
            try:
                with urllib.request.urlopen(service, timeout=3) as response:
                    ip = response.read().decode('utf-8').strip()
                    if ip and not is_private_ip(ip):
                        return ip
            except (urllib.error.URLError, socket.timeout, ValueError):
                continue
        
        return None
    except Exception:
        return None


def is_running_on_localhost():
    """Check if the application is running on localhost/127.0.0.1."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip in ['127.0.0.1', 'localhost', '::1'] or 'localhost' in hostname.lower()
    except Exception:
        return False


def get_connection_method_recommendation(router_ip: str, router_port: int) -> dict:
    """Provide recommendations for connecting to a router based on IP address."""
    is_private = is_private_ip(router_ip)
    is_local = is_running_on_localhost()
    
    recommendation = {
        "is_private_ip": is_private,
        "is_localhost": is_local,
        "methods": [],
        "recommended_method": None,
        "warnings": [],
    }
    
    if is_private:
        if is_local:
            # Running locally, private IP should work
            recommendation["methods"].append({
                "method": "direct",
                "name": "Direct Connection (Local)",
                "description": "You're running locally, so private IP should work.",
                "status": "available"
            })
            recommendation["recommended_method"] = "direct"
        else:
            # Running on remote server, private IP won't work
            recommendation["warnings"].append(
                f"⚠️ Router IP {router_ip} is a private IP address. "
                "Private IPs are only accessible on the local network and cannot be reached from a remote server."
            )
            
            # Method 1: Public IP
            recommendation["methods"].append({
                "method": "public_ip",
                "name": "Use Public IP Address",
                "description": "Configure the router to use its public IP address instead of the private IP.",
                "steps": [
                    "1. Find the router's public IP: Check `/ip address print` on the router (look for WAN interface)",
                    "2. Configure firewall: Allow API access from your server's public IP",
                    "3. Use public IP: Enter the public IP when registering/login",
                    f"4. Port: Use {router_port} (or 8729 for SSL)"
                ],
                "status": "recommended"
            })
            
            # Method 2: Port Forwarding
            recommendation["methods"].append({
                "method": "port_forwarding",
                "name": "Port Forwarding",
                "description": "Set up port forwarding on your upstream router/gateway.",
                "steps": [
                    "1. On upstream router: Configure port forwarding",
                    f"   - External Port: 20828 (or any available port)",
                    f"   - Internal IP: {router_ip} (MikroTik's private IP)",
                    f"   - Internal Port: {router_port}",
                    "   - Protocol: TCP",
                    "2. Find upstream router's public IP",
                    "3. Use forwarded address: Enter upstream router's public IP and external port (20828)",
                    "4. Configure MikroTik firewall to allow connections"
                ],
                "status": "available"
            })
            
            # Method 3: VPN
            recommendation["methods"].append({
                "method": "vpn",
                "name": "VPN Connection",
                "description": "Set up a VPN tunnel between your server and the MikroTik network.",
                "steps": [
                    "1. Configure MikroTik as VPN server (PPTP or OpenVPN)",
                    "2. Create VPN user for your server",
                    "3. Connect server to VPN",
                    "4. Use VPN IP: Enter the router's VPN IP address (e.g., 10.0.0.1)",
                    f"5. Port: Use {router_port}"
                ],
                "status": "available",
                "note": "Requires VPN support on your hosting provider (VPS recommended)"
            })
            
            recommendation["recommended_method"] = "public_ip"
    else:
        # Public IP - should work from anywhere
        recommendation["methods"].append({
            "method": "direct",
            "name": "Direct Connection (Public IP)",
            "description": f"Router IP {router_ip} is a public IP address. It should be reachable from your server.",
            "status": "available"
        })
        recommendation["recommended_method"] = "direct"
        
        recommendation["warnings"].append(
            "🔒 Security: When using a public IP, ensure:"
            "\n• RouterOS API uses SSL (port 8729)"
            "\n• Firewall restricts access to your server's IP only"
            "\n• Strong passwords are used"
        )
    
    return recommendation


def get_connection_error_help(host: str, port: int, error_msg: str) -> str:
    """Generate helpful error messages with troubleshooting guidance."""
    is_private = is_private_ip(host)
    help_text = ""
    
    if is_private:
        help_text = (
            f"\n\n⚠️ NETWORK ISSUE DETECTED: The IP address {host} is a private IP address "
            "(192.168.x.x, 10.x.x.x, or 172.16-31.x.x). Private IPs are only accessible "
            "on the local network and cannot be reached from a remote server.\n\n"
            "SOLUTIONS:\n"
            "1. Use the router's PUBLIC IP address instead of the private IP\n"
            "2. Set up port forwarding on your upstream router to forward a public port to the MikroTik\n"
            "3. Configure a VPN connection between your cPanel server and the MikroTik network\n"
            "4. If testing locally, ensure you're on the same network as the router\n\n"
        )
    
    if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
        help_text += (
            "CONNECTION TIMEOUT - Possible causes:\n"
            "• RouterOS API service not enabled on the router\n"
            "• Firewall blocking connections from your server\n"
            "• Port {port} is blocked by your hosting provider\n"
            "• Network routing issue - router not reachable from server\n"
            "• Wrong IP address or port number\n\n"
        ).format(port=port)
    
    if "connection refused" in error_msg.lower() or "refused" in error_msg.lower():
        help_text += (
            "CONNECTION REFUSED - Possible causes:\n"
            "• RouterOS API service not running on port {port}\n"
            "• Firewall on MikroTik is blocking the connection\n"
            "• Wrong port number (use 8728 for non-SSL, 8729 for SSL)\n\n"
        ).format(port=port)
    
    if "name or service not known" in error_msg.lower() or "gaierror" in error_msg.lower():
        help_text += (
            "DNS/HOSTNAME ERROR - Possible causes:\n"
            "• Invalid IP address or hostname\n"
            "• Hostname cannot be resolved\n"
            "• Use IP address instead of hostname if possible\n\n"
        )
    
    if not is_private:
        help_text += (
            "GENERAL TROUBLESHOOTING:\n"
            "• Verify the router is powered on and accessible\n"
            "• Check that RouterOS API is enabled: /ip service print (should show api enabled)\n"
            "• Ensure firewall allows connections from your cPanel server IP\n"
            "• Test connectivity from your server: telnet {host} {port}\n"
            "• If using SSL, ensure port is 8729 and SSL is enabled\n"
            "• If not using SSL, ensure port is 8728 and SSL is disabled\n\n"
        ).format(host=host, port=port)
    
    return help_text


def preflight_connection(host: str, port: int, timeout_seconds: int):
    """Test if we can establish a TCP connection to the host:port.
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    # Check if it's a private IP and provide warning
    is_private = is_private_ip(host)
    
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True, None
    except socket.timeout:
        error_msg = f"Connection timed out after {timeout_seconds} seconds"
        help_text = get_connection_error_help(host, port, error_msg)
        return False, error_msg + help_text
    except ConnectionRefusedError:
        error_msg = "Connection refused - router may not be accepting connections on this port"
        help_text = get_connection_error_help(host, port, error_msg)
        return False, error_msg + help_text
    except socket.gaierror as e:
        error_msg = f"Cannot resolve hostname or invalid IP address: {str(e)}"
        help_text = get_connection_error_help(host, port, error_msg)
        return False, error_msg + help_text
    except OSError as e:
        error_msg = f"Network error: {sanitize_error_message(str(e))}"
        help_text = get_connection_error_help(host, port, error_msg)
        if is_private:
            help_text = get_connection_error_help(host, port, "private_ip") + help_text
        return False, error_msg + help_text
    except Exception as exc:  # noqa: BLE001 - want to capture connectivity failures
        error_msg = sanitize_error_message(str(exc))
        help_text = get_connection_error_help(host, port, error_msg)
        if is_private:
            help_text = get_connection_error_help(host, port, "private_ip") + help_text
        return False, error_msg + help_text


def verify_mikrotik(details):
    host = details["management_ip"]
    port = details["api_port"]
    username = details["api_username"]
    password = details["api_password"]
    use_ssl = details["use_ssl"]

    timeout_seconds = 5
    socket.setdefaulttimeout(timeout_seconds)

    # Check for private IP warning
    is_private = is_private_ip(host)
    if is_private:
        logger.warning("Attempting to connect to private IP %s - may not be reachable from remote server", host)
    
    ok, failure = preflight_connection(host, port, timeout_seconds)
    if not ok:
        error_msg = f"Unable to reach router on {host}:{port}."
        if failure:
            error_msg += f"\n\n{failure}"
        return False, None, error_msg

    try:
        pool = routeros_api.RouterOsApiPool(
            host,
            username=username,
            password=password,
            port=port,
            use_ssl=use_ssl,
            plaintext_login=True,
        )
        api = pool.get_api()

        identity = api.get_resource("/system/identity").get()
        resource = api.get_resource("/system/resource").get()

        pool.disconnect()
        return True, {"identity": identity, "resource": resource}, None
    except Exception as exc:  # noqa: BLE001 - want to capture API failures
        return False, None, sanitize_error_message(str(exc))


def verify_mikrotik_login(host, port, use_ssl, username, password):
    timeout_seconds = 5
    socket.setdefaulttimeout(timeout_seconds)

    # Check for private IP warning
    is_private = is_private_ip(host)
    if is_private:
        logger.warning("Attempting to connect to private IP %s - may not be reachable from remote server", host)
    
    ok, failure = preflight_connection(host, port, timeout_seconds)
    if not ok:
        error_msg = f"Unable to reach router on {host}:{port}."
        if failure:
            error_msg += f"\n\n{failure}"
        return False, None, error_msg

    try:
        pool = routeros_api.RouterOsApiPool(
            host,
            username=username,
            password=password,
            port=port,
            use_ssl=use_ssl,
            plaintext_login=True,
        )
        api = pool.get_api()
        identity = api.get_resource("/system/identity").get()
        pool.disconnect()
        return True, identity, None
    except Exception as exc:  # noqa: BLE001 - want to capture API failures
        error = sanitize_error_message(str(exc))
        if "no response from remote server" in error.lower():
            error = (
                f"{error}. Check that API is enabled on the router, the IP/port are correct "
                "and SSL matches the port (8728 non-SSL, 8729 SSL)."
            )
        return False, None, error


def get_session_router_credentials():
    """Get router credentials from database based on selected router in session."""
    if not session.get("user"):
        return None, "Login session not found."
    
    router_id = session.get("selected_router_id")
    if not router_id:
        return None, "No router selected. Please select a router."
    
    # Get router from database
    router = db_get_mikrotik_router_by_id(router_id)
    if not router:
        return None, f"Router with ID {router_id} not found in database."
    
    if router.get("status") != "ACTIVE":
        return None, f"Router '{router.get('router_name')}' is not active. Status: {router.get('status')}"
    
    try:
        cipher = get_cipher()
        encrypted_password = router.get("api_password_encrypted")
        if not encrypted_password:
            return None, "Router password not found in database."
        password = cipher.decrypt(encrypted_password.encode()).decode()
    except Exception as exc:  # noqa: BLE001 - want to capture decryption issues
        return None, f"Unable to decrypt router credentials: {sanitize_error_message(str(exc))}"

    return {
        "host": router.get("management_ip"),
        "port": router.get("api_port"),
        "use_ssl": bool(router.get("use_ssl")),
        "username": router.get("api_username"),
        "password": password,
        "router_id": router_id,
        "router_name": router.get("router_name"),
    }, None


def get_router_credentials_by_id(router_id):
    """Get router API credentials by router_id (without using session)."""
    router = db_get_mikrotik_router_by_id(router_id)
    if not router:
        return None, "Router not found."
    if router.get("status") != "ACTIVE":
        return None, f"Router '{router.get('router_name')}' is not active."
    try:
        cipher = get_cipher()
        enc = router.get("api_password_encrypted")
        if not enc:
            return None, "Router password not found."
        password = cipher.decrypt(enc.encode()).decode()
    except Exception as exc:  # noqa: BLE001
        return None, f"Unable to decrypt router credentials: {sanitize_error_message(str(exc))}"
    return {
        "host": router.get("management_ip"),
        "port": router.get("api_port"),
        "use_ssl": bool(router.get("use_ssl")),
        "username": router.get("api_username"),
        "password": password,
        "router_id": router_id,
        "router_name": router.get("router_name"),
    }, None


def require_session():
    if not session.get("user"):
        return False
    return True


def maybe_enforce_pppoe_access_rules(creds, router_id):
    """Apply PPPoE-only access policy automatically when always_enforce_pppoe is enabled."""
    enabled = (db_get_setting("always_enforce_pppoe", "1") or "1").strip() in {"1", "true", "yes", "on"}
    if not enabled:
        return
    if not creds or not router_id:
        return
    try:
        pool, api = get_router_api(creds)
        try:
            pppoe_pool_network = "192.168.1.0/24"
            try:
                pools = api.get_resource("/ip/pool").get(name="pppoe-pool")
                if pools and pools[0].get("ranges"):
                    first_ip = (pools[0]["ranges"] or "").split("-")[0].strip()
                    if first_ip:
                        pppoe_pool_network = first_ip.rsplit(".", 1)[0] + ".0/24"
            except Exception:  # noqa: BLE001
                pass
            allow_wifi = (db_get_setting("allow_wifi_access", "0") or "0").strip() in {"1", "true", "yes", "on"}
            wifi_network = None
            if allow_wifi:
                _pppoe_net, detected_wifi = _get_router_pppoe_and_wifi_networks(api)
                wifi_network = detected_wifi
            wan_interface = (db_get_setting("wan_interface", "") or "").strip() or None
            wan_interface, wan_interfaces, _wan_note = _get_enforcement_wan_targets(api, wan_interface)
            if wan_interface:
                db_set_setting("wan_interface", wan_interface)
            mikrotik_fix_firewall_rule(
                api,
                pppoe_pool_network,
                wan_interface=wan_interface,
                wan_interfaces=wan_interfaces,
                allow_wifi=allow_wifi,
                wifi_network=wifi_network if allow_wifi else None,
            )
            mikrotik_remove_unknown_pppoe_secrets(api, router_id)
        finally:
            pool.disconnect()
    except Exception as exc:  # noqa: BLE001
        logger.info("Auto PPPoE enforcement skipped: %s", sanitize_error_message(str(exc)))


def verify_user_belongs_to_router(user, router_id=None):
    """Verify that a user belongs to the selected router."""
    if not router_id:
        router_id = session.get("selected_router_id")
    if not router_id:
        return False, "No router selected."
    if user.get("mikrotik_router_id") != router_id:
        return False, "User does not belong to selected router."
    return True, None


def normalize_device_status(device):
    status_raw = (device.get("status") or "").lower()
    uptime = device.get("uptime") or device.get("expires-after")
    source = device.get("source") or ""

    active = False
    if source == "DHCP Lease":
        active = status_raw == "bound"
    elif source == "ARP":
        active = status_raw in {"reachable", "permanent"}
    elif source == "Wireless":
        active = True if uptime or device.get("signal") else False
    else:
        active = status_raw in {"bound", "reachable", "ok", "true", "yes"} or bool(uptime)

    device["active"] = active
    if not device.get("status"):
        device["status"] = "active" if active else "inactive"
    return device


def is_nonzero_rate(rate_value):
    if rate_value is None:
        return False
    if isinstance(rate_value, (int, float)):
        return rate_value > 0
    rate_str = str(rate_value).strip().lower()
    if not rate_str:
        return False
    zero_tokens = {"0", "0bps", "0kbps", "0kb/s", "0b", "0.0"}
    return rate_str not in zero_tokens


def parse_duration_to_seconds(value):
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text == "never":
        return None

    if ":" in text:
        parts = text.split(":")
        if len(parts) == 3:
            try:
                hours = int(parts[0])
                minutes = int(parts[1])
                seconds = int(parts[2])
                return hours * 3600 + minutes * 60 + seconds
            except ValueError:
                return None

    total = 0
    matches = re.findall(r"(\d+)([dhms])", text)
    if matches:
        for amount, unit in matches:
            value_int = int(amount)
            if unit == "d":
                total += value_int * 86400
            elif unit == "h":
                total += value_int * 3600
            elif unit == "m":
                total += value_int * 60
            elif unit == "s":
                total += value_int
        return total
    return None


def normalize_device_transmission(device):
    tx_rate = device.get("tx_rate")
    rx_rate = device.get("rx_rate")
    if tx_rate is None and rx_rate is None:
        last_seen = parse_duration_to_seconds(device.get("last_seen"))
        device["transmitting"] = last_seen is not None and last_seen <= 30
        return device
    device["transmitting"] = (
        is_nonzero_rate(tx_rate)
        or is_nonzero_rate(rx_rate)
        or (parse_duration_to_seconds(device.get("last_seen")) or 999999) <= 30
    )
    return device


def fetch_connected_devices(creds):
    timeout_seconds = 5
    socket.setdefaulttimeout(timeout_seconds)

    ok, failure = preflight_connection(creds["host"], creds["port"], timeout_seconds)
    if not ok:
        return None, f"Unable to reach router on {creds['host']}:{creds['port']}. {failure}"

    devices = []
    bridge_by_mac = {}
    try:
        pool = routeros_api.RouterOsApiPool(
            creds["host"],
            username=creds["username"],
            password=creds["password"],
            port=creds["port"],
            use_ssl=creds["use_ssl"],
            plaintext_login=True,
        )
        api = pool.get_api()

        try:
            bridge_hosts = api.get_resource("/interface/bridge/host").get()
            for host in bridge_hosts:
                mac = host.get("mac-address")
                if not mac:
                    continue
                bridge_by_mac[mac] = host
        except Exception as exc:  # noqa: BLE001
            logger.info("Unable to read bridge host table: %s", sanitize_error_message(str(exc)))

        try:
            leases = api.get_resource("/ip/dhcp-server/lease").get()
            for lease in leases:
                mac = lease.get("mac-address")
                bridge = bridge_by_mac.get(mac, {})
                devices.append(
                    normalize_device_transmission(
                        normalize_device_status(
                            {
                        "source": "DHCP Lease",
                        "ip": lease.get("address"),
                        "mac": mac,
                        "host": lease.get("host-name") or lease.get("comment"),
                        "interface": lease.get("interface"),
                        "status": lease.get("status"),
                        "uptime": lease.get("expires-after"),
                        "signal": None,
                        "tx_rate": bridge.get("tx-rate"),
                        "rx_rate": bridge.get("rx-rate"),
                        "last_seen": bridge.get("last-seen"),
                            }
                        )
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.info("Unable to read DHCP leases: %s", sanitize_error_message(str(exc)))

        try:
            arps = api.get_resource("/ip/arp").get()
            for arp in arps:
                mac = arp.get("mac-address")
                bridge = bridge_by_mac.get(mac, {})
                devices.append(
                    normalize_device_transmission(
                        normalize_device_status(
                            {
                        "source": "ARP",
                        "ip": arp.get("address"),
                        "mac": mac,
                        "host": arp.get("comment"),
                        "interface": arp.get("interface"),
                        "status": arp.get("status"),
                        "uptime": None,
                        "signal": None,
                        "tx_rate": bridge.get("tx-rate"),
                        "rx_rate": bridge.get("rx-rate"),
                        "last_seen": bridge.get("last-seen"),
                            }
                        )
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.info("Unable to read ARP table: %s", sanitize_error_message(str(exc)))

        try:
            wireless = api.get_resource("/interface/wireless/registration-table").get()
            for entry in wireless:
                mac = entry.get("mac-address")
                devices.append(
                    normalize_device_transmission(
                        normalize_device_status(
                            {
                        "source": "Wireless",
                        "ip": entry.get("address"),
                        "mac": mac,
                        "host": entry.get("comment"),
                        "interface": entry.get("interface"),
                        "status": entry.get("radio-name"),
                        "uptime": entry.get("uptime"),
                        "signal": entry.get("signal-strength"),
                        "tx_rate": entry.get("tx-rate"),
                        "rx_rate": entry.get("rx-rate"),
                        "last_seen": entry.get("last-seen"),
                            }
                        )
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.info("Unable to read wireless registration table: %s", sanitize_error_message(str(exc)))

        pool.disconnect()
        return devices, None
    except Exception as exc:  # noqa: BLE001 - want to capture API failures
        return None, sanitize_error_message(str(exc))


def get_router_api(creds):
    timeout_seconds = ROUTER_API_TIMEOUT
    socket.setdefaulttimeout(timeout_seconds)
    ok, failure = preflight_connection(creds["host"], creds["port"], timeout_seconds)
    if not ok:
        raise RuntimeError(f"Unable to reach router on {creds['host']}:{creds['port']}. {failure}")
    pool = routeros_api.RouterOsApiPool(
        creds["host"],
        username=creds["username"],
        password=creds["password"],
        port=creds["port"],
        use_ssl=creds["use_ssl"],
        plaintext_login=True,
    )
    return pool, pool.get_api()


def encrypt_password(raw_password: str) -> str:
    cipher = get_cipher()
    return cipher.encrypt(raw_password.encode()).decode()


def decrypt_password(enc_password: str) -> str:
    cipher = get_cipher()
    return cipher.decrypt(enc_password.encode()).decode()


def db_insert_pppoe_router(payload):
    ensure_db_and_tables()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    # Get router_id from payload or session
    router_id = payload.get("mikrotik_router_id")
    if not router_id:
        router_id = session.get("selected_router_id")
    if not router_id:
        raise ValueError("No router selected. Please select a router before registering PPPoE users.")
    
    sql = """
        INSERT INTO pppoe_routers (
            mikrotik_router_id,
            customer_name,
            phone_number,
            pppoe_username,
            pppoe_password_encrypted,
            mikrotik_secret_id,
            status,
            plan_allocated_at,
            created_at,
            updated_at
        ) VALUES (
            %(mikrotik_router_id)s,
            %(customer_name)s,
            %(phone_number)s,
            %(pppoe_username)s,
            %(pppoe_password_encrypted)s,
            %(mikrotik_secret_id)s,
            %(status)s,
            %(plan_allocated_at)s,
            %(created_at)s,
            %(updated_at)s
        );
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    sql,
                    {
                        "mikrotik_router_id": router_id,
                        "customer_name": payload["customer_name"],
                        "phone_number": payload["phone_number"],
                        "pppoe_username": payload["pppoe_username"],
                        "pppoe_password_encrypted": payload["pppoe_password_encrypted"],
                        "mikrotik_secret_id": payload.get("mikrotik_secret_id"),
                        "status": payload.get("status", "active"),
                        "plan_allocated_at": now,
                        "created_at": now,
                        "updated_at": now,
                    },
                )
                return cur.lastrowid
            except Exception as e:
                error_msg = str(e).lower()
                if "duplicate" in error_msg or "unique" in error_msg:
                    raise ValueError(f"PPPoE username '{payload['pppoe_username']}' is already registered on this router. Each username can only be used once per router.")
                raise


def db_update_pppoe_router(router_id, updates):
    ensure_db_and_tables()
    updates["updated_at"] = datetime.now(timezone.utc).replace(tzinfo=None)
    fields = []
    values = []
    for key, value in updates.items():
        fields.append(f"{key} = %s")
        values.append(value)
    values.append(router_id)
    sql = f"UPDATE pppoe_routers SET {', '.join(fields)} WHERE id = %s;"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, values)


def db_get_pppoe_router_by_id(router_id):
    ensure_db_and_tables()
    sql = "SELECT * FROM pppoe_routers WHERE id = %s;"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (router_id,))
            return cur.fetchone()


def db_get_pppoe_router_by_username(username, router_id=None):
    ensure_db_and_tables()
    if router_id:
        sql = "SELECT * FROM pppoe_routers WHERE pppoe_username = %s AND mikrotik_router_id = %s;"
        params = (username, router_id)
    else:
        sql = "SELECT * FROM pppoe_routers WHERE pppoe_username = %s;"
        params = (username,)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def db_get_mikrotik_router_by_id(router_id):
    """Get MikroTik router by ID from routers table."""
    ensure_db_and_tables()
    sql = "SELECT * FROM routers WHERE id = %s;"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (router_id,))
            return cur.fetchone()


def db_list_mikrotik_routers():
    """List all MikroTik routers from routers table."""
    ensure_db_and_tables()
    sql = "SELECT * FROM routers ORDER BY router_name, created_at DESC;"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()


def db_list_pppoe_routers(router_id=None):
    """List PPPoE users, optionally filtered by router_id."""
    ensure_db_and_tables()
    if router_id:
        sql = "SELECT * FROM pppoe_routers WHERE mikrotik_router_id = %s ORDER BY created_at DESC;"
        params = (router_id,)
    else:
        sql = "SELECT * FROM pppoe_routers ORDER BY created_at DESC;"
        params = ()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def db_delete_pppoe_router(router_id):
    ensure_db_and_tables()
    sql = "DELETE FROM pppoe_routers WHERE id = %s;"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (router_id,))


def db_reset_network_monitoring_usage_for_router(router_id, active_connections=None, registered_users=None):
    """Remove usage_daily history for a router and realign last-seen byte counters.
    If registered_users and active_connections are provided, last_seen is set to each user's live
    MikroTik totals so the next poll only counts new traffic. Otherwise counters are zeroed.
    Does not change client profiles, plans, or data_usage_bytes_this_period (billing caps)."""
    if not router_id:
        return
    ensure_db_and_tables()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM usage_daily WHERE router_id = %s", (router_id,))
            if registered_users:
                for user in registered_users:
                    user_id = user.get("id")
                    if not user_id:
                        continue
                    username = (user.get("pppoe_username") or "").strip()
                    info = (active_connections or {}).get(username) if active_connections else None
                    if info:
                        try:
                            cur_sent = int(info.get("bytes_sent") or 0)
                            cur_received = int(info.get("bytes_received") or 0)
                        except (TypeError, ValueError):
                            cur_sent, cur_received = 0, 0
                    else:
                        cur_sent, cur_received = 0, 0
                    cur.execute(
                        """UPDATE pppoe_routers SET last_seen_bytes_sent = %s, last_seen_bytes_received = %s, updated_at = %s
                           WHERE id = %s AND mikrotik_router_id = %s""",
                        (cur_sent, cur_received, now, user_id, router_id),
                    )
            else:
                cur.execute(
                    """UPDATE pppoe_routers SET last_seen_bytes_sent = 0, last_seen_bytes_received = 0, updated_at = %s
                       WHERE mikrotik_router_id = %s""",
                    (now, router_id),
                )


def db_insert_subscription_plan(plan_name, duration_days, download_speed_mbps, upload_speed_mbps, cost, data_cap_gb=None, cap_reset_days=None):
    ensure_db_and_tables()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    sql = """
        INSERT INTO subscription_plans (
            plan_name,
            duration_days,
            download_speed_mbps,
            upload_speed_mbps,
            cost,
            data_cap_gb,
            cap_reset_days,
            created_at,
            updated_at
        ) VALUES (
            %(plan_name)s,
            %(duration_days)s,
            %(download_speed_mbps)s,
            %(upload_speed_mbps)s,
            %(cost)s,
            %(data_cap_gb)s,
            %(cap_reset_days)s,
            %(created_at)s,
            %(updated_at)s
        );
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                {
                    "plan_name": plan_name,
                    "duration_days": duration_days,
                    "download_speed_mbps": download_speed_mbps,
                    "upload_speed_mbps": upload_speed_mbps,
                    "cost": cost,
                    "data_cap_gb": data_cap_gb,
                    "cap_reset_days": cap_reset_days,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            return cur.lastrowid


def db_list_subscription_plans():
    ensure_db_and_tables()
    sql = "SELECT * FROM subscription_plans ORDER BY created_at DESC"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()


def db_get_subscription_plan_by_id(plan_id):
    ensure_db_and_tables()
    sql = "SELECT * FROM subscription_plans WHERE id = %s"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (plan_id,))
            return cur.fetchone()


def db_update_subscription_plan(plan_id, updates):
    ensure_db_and_tables()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    set_clauses = []
    values = []
    for key, value in updates.items():
        set_clauses.append(f"{key} = %s")
        values.append(value)
    set_clauses.append("updated_at = %s")
    values.append(now)
    values.append(plan_id)
    sql = f"UPDATE subscription_plans SET {', '.join(set_clauses)} WHERE id = %s"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, values)


def db_delete_subscription_plan(plan_id):
    ensure_db_and_tables()
    sql = "DELETE FROM subscription_plans WHERE id = %s"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (plan_id,))


def db_get_billing_payments_by_year(payment_year, router_id=None):
    """Return payment checkbox states as {(user_id, month): bool} for a year."""
    ensure_db_and_tables()
    if router_id is None:
        sql = """
            SELECT user_id, payment_month, is_paid
            FROM billing_payments
            WHERE payment_year = %s
        """
        params = (payment_year,)
    else:
        sql = """
            SELECT user_id, payment_month, is_paid
            FROM billing_payments
            WHERE router_id = %s AND payment_year = %s
        """
        params = (router_id, payment_year)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    states = {}
    for row in rows:
        try:
            user_id = int(row.get("user_id"))
            month = int(row.get("payment_month"))
        except (TypeError, ValueError):
            continue
        states[(user_id, month)] = bool(row.get("is_paid"))
    return states


def db_set_billing_payment_status(router_id, user_id, payment_year, payment_month, is_paid):
    """Insert/update a monthly payment checkbox state."""
    ensure_db_and_tables()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    paid_at = now if is_paid else None
    sql = """
        INSERT INTO billing_payments (
            router_id, user_id, payment_year, payment_month, is_paid, paid_at, updated_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            is_paid = VALUES(is_paid),
            paid_at = VALUES(paid_at),
            updated_at = VALUES(updated_at)
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (router_id, user_id, payment_year, payment_month, 1 if is_paid else 0, paid_at, now))


def db_insert_hotspot_plan_request(plan_id, plan_name, customer_name, phone_number, hotspot_mac, client_ip, redirect_dst):
    """Store a public hotspot portal plan-selection request."""
    ensure_db_and_tables()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    sql = """
        INSERT INTO hotspot_plan_requests (
            plan_id, plan_name, customer_name, phone_number, hotspot_mac, client_ip, redirect_dst, status, created_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, 'pending', %s
        )
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (plan_id, plan_name, customer_name, phone_number, hotspot_mac, client_ip, redirect_dst, now))
            return cur.lastrowid


def db_update_hotspot_plan_request_status(request_id, status):
    """Update status for a hotspot plan request row."""
    ensure_db_and_tables()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE hotspot_plan_requests SET status = %s WHERE id = %s", (status, request_id))


def db_insert_hotspot_access_session(
    router_id,
    hotspot_plan_request_id,
    plan_id,
    plan_name,
    customer_name,
    phone_number,
    hotspot_mac,
    client_ip,
    granted_at,
    expires_at,
):
    """Store an active hotspot access grant session."""
    ensure_db_and_tables()
    sql = """
        INSERT INTO hotspot_access_sessions (
            router_id, hotspot_plan_request_id, plan_id, plan_name, customer_name, phone_number,
            hotspot_mac, client_ip, granted_at, expires_at, status, updated_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s)
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    router_id,
                    hotspot_plan_request_id,
                    plan_id,
                    plan_name,
                    customer_name,
                    phone_number,
                    hotspot_mac,
                    client_ip,
                    granted_at,
                    expires_at,
                    granted_at,
                ),
            )
            return cur.lastrowid


def db_list_expired_hotspot_access_sessions(router_id, now):
    """List active hotspot sessions that have expired for a router."""
    ensure_db_and_tables()
    sql = """
        SELECT id, hotspot_mac, client_ip
        FROM hotspot_access_sessions
        WHERE router_id = %s AND status = 'active' AND expires_at <= %s
        ORDER BY expires_at ASC
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (router_id, now))
            return cur.fetchall()


def db_mark_hotspot_access_session_expired(session_id, now):
    """Mark hotspot access session as expired."""
    ensure_db_and_tables()
    sql = "UPDATE hotspot_access_sessions SET status = 'expired', updated_at = %s WHERE id = %s"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (now, session_id))


def db_get_setting(key, default=None):
    """Get a value from the settings table."""
    ensure_db_and_tables()
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM settings WHERE `key` = %s", (key,))
                row = cur.fetchone()
                return row["value"] if row and row.get("value") is not None else default
    except Exception:  # noqa: BLE001
        return default


def db_set_setting(key, value):
    """Set a value in the settings table (insert or replace)."""
    ensure_db_and_tables()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO settings (`key`, value) VALUES (%s, %s) ON DUPLICATE KEY UPDATE value = %s",
                (key, str(value) if value is not None else None, str(value) if value is not None else None),
            )


def insert_router_record(details, status, error_reason, identity, resource):
    ensure_db_and_tables()
    cipher = get_cipher()
    encrypted_password = cipher.encrypt(details["api_password"].encode()).decode()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    sql = """
        INSERT INTO routers (
            router_name,
            router_role,
            management_ip,
            api_port,
            use_ssl,
            api_username,
            api_password_encrypted,
            status,
            error_reason,
            identity_json,
            resource_json,
            last_verified_at,
            created_at,
            updated_at
        ) VALUES (
            %(router_name)s,
            %(router_role)s,
            %(management_ip)s,
            %(api_port)s,
            %(use_ssl)s,
            %(api_username)s,
            %(api_password_encrypted)s,
            %(status)s,
            %(error_reason)s,
            %(identity_json)s,
            %(resource_json)s,
            %(last_verified_at)s,
            %(created_at)s,
            %(updated_at)s
        );
    """
    payload = {
        "router_name": details["router_name"],
        "router_role": details["router_role"],
        "management_ip": details["management_ip"],
        "api_port": details["api_port"],
        "use_ssl": details["use_ssl"],
        "api_username": details["api_username"],
        "api_password_encrypted": encrypted_password,
        "status": status,
        "error_reason": error_reason,
        "identity_json": json.dumps(identity) if identity else None,
        "resource_json": json.dumps(resource) if resource else None,
        "last_verified_at": now if status == "ACTIVE" else None,
        "created_at": now,
        "updated_at": now,
    }
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, payload)
            return cur.lastrowid


def update_router_credentials_by_id(router_id: int, api_username: str, api_password: str):
    cipher = get_cipher()
    encrypted_password = cipher.encrypt(api_password.encode()).decode()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    sql = """
        UPDATE routers
        SET api_username = %s,
            api_password_encrypted = %s,
            updated_at = %s
        WHERE id = %s;
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (api_username, encrypted_password, now, router_id))


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    if not require_session():
        return redirect(url_for("mikrotik_page"))
    
    # Get all routers and selected router
    routers = db_list_mikrotik_routers()
    selected_router_id = session.get("selected_router_id")
    selected_router = None
    if selected_router_id:
        selected_router = db_get_mikrotik_router_by_id(selected_router_id)
    
    return render_template("dashboard.html", routers=routers, selected_router=selected_router, selected_router_id=selected_router_id)


@app.route("/api/select-router", methods=["POST"])
def select_router():
    """Select a router to work with."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    
    data = request.get_json(force=True, silent=True) or {}
    router_id = data.get("router_id")
    
    if not router_id:
        return jsonify({"error": "router_id is required."}), 400
    
    # Verify router exists
    router = db_get_mikrotik_router_by_id(router_id)
    if not router:
        return jsonify({"error": "Router not found."}), 404
    
    # Set selected router in session
    session["selected_router_id"] = router_id
    
    return jsonify({
        "message": f"Router '{router.get('router_name')}' selected successfully.",
        "router": {
            "id": router.get("id"),
            "name": router.get("router_name"),
            "role": router.get("router_role"),
            "ip": router.get("management_ip"),
            "status": router.get("status"),
        }
    })


@app.route("/api/mikrotik-routers", methods=["GET"])
def api_mikrotik_routers():
    """Get list of all registered MikroTik routers."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    
    routers = db_list_mikrotik_routers()
    selected_router_id = session.get("selected_router_id")
    
    router_list = []
    for router in routers:
        router_list.append({
            "id": router.get("id"),
            "name": router.get("router_name"),
            "role": router.get("router_role"),
            "ip": router.get("management_ip"),
            "port": router.get("api_port"),
            "status": router.get("status"),
            "is_selected": router.get("id") == selected_router_id,
        })
    
    return jsonify(router_list)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    host = request.form.get("management_ip", "").strip()
    port = int(request.form.get("api_port", "8728"))
    use_ssl = request.form.get("use_ssl", "false") == "true"
    username = request.form.get("api_username", "").strip()
    password = request.form.get("api_password", "")

    if not all([host, username, password]):
        return render_template("login.html", error="All fields are required.")

    if use_ssl and port == 8728:
        return render_template("login.html", error="SSL is enabled but port is 8728. Use 8729 for SSL.")
    if not use_ssl and port == 8729:
        return render_template("login.html", error="SSL is disabled but port is 8729. Use 8728 without SSL.")

    # Check if router exists in database first (used by both online and offline login paths)
    routers = db_list_mikrotik_routers()
    matching_router = None
    for r in routers:
        if (r.get("management_ip") == host and
            r.get("api_port") == port and
            r.get("api_username") == username):
            matching_router = r
            break

    success, identity, error = verify_mikrotik_login(host, port, use_ssl, username, password)
    if not success:
        logger.info("Login failed: %s", error)
        # Fallback mode: allow login if router is registered and password matches stored credential.
        # This helps when remote hosting/network policy blocks API reachability.
        if matching_router:
            try:
                cipher = get_cipher()
                stored_enc = matching_router.get("api_password_encrypted")
                stored_password = cipher.decrypt(stored_enc.encode()).decode() if stored_enc else ""
                if stored_password and stored_password == password:
                    session["user"] = {
                        "username": username,
                        "identity": matching_router.get("router_name", "Router (offline)"),
                        "offline_mode": True,
                    }
                    session["selected_router_id"] = matching_router.get("id")
                    return redirect(url_for("dashboard"))
            except Exception as exc:  # noqa: BLE001
                logger.info("Offline login fallback check failed: %s", sanitize_error_message(str(exc)))
        return render_template("login.html", error=f"Login failed: {error}")

    # Check if router exists in database, if not, redirect to registration
    if not matching_router:
        # Router not registered, store login info temporarily and redirect to registration
        session["pending_router"] = {
            "host": host,
            "port": port,
            "use_ssl": use_ssl,
            "username": username,
            "password": password,
            "identity": identity,
        }
        return redirect(url_for("mikrotik_page"))
    
    # Router exists, set it as selected
    session["user"] = {
        "username": username,
        "identity": identity,
    }
    session["selected_router_id"] = matching_router.get("id")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("dashboard"))


def format_bytes(value):
    """Format bytes to human-readable format."""
    try:
        val = int(value)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if val < 1024.0:
                return f"{val:.1f} {unit}"
            val /= 1024.0
        return f"{val:.1f} PB"
    except (ValueError, TypeError):
        return "0 B"


@app.context_processor
def inject_format_bytes():
    """Make format_bytes available in all templates."""
    return dict(format_bytes=format_bytes)


def get_router_wifi_info(creds, router_id):
    """Get WiFi SSID (from MikroTik) and WiFi password (from settings if stored when set in System Config). Returns (wifi_ssid, wifi_password)."""
    wifi_ssid = ""
    wifi_password = ""
    try:
        pool, api = get_router_api(creds)
        try:
            wireless = api.get_resource("/interface/wireless")
            interfaces = wireless.get()
            if interfaces:
                wifi_ssid = (interfaces[0].get("ssid") or "").strip()
                if isinstance(wifi_ssid, bytes):
                    wifi_ssid = wifi_ssid.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        pool.disconnect()
    except Exception:  # noqa: BLE001
        pass
    enc = db_get_setting(f"router_wifi_password_{router_id}")
    if enc:
        try:
            wifi_password = decrypt_password(enc)
        except Exception:  # noqa: BLE001
            pass
    return wifi_ssid or "", wifi_password or ""


def fetch_active_pppoe_connections(creds, enforce_single_session=True):
    """Fetch active PPPoE connections from MikroTik and enforce single session per username."""
    pool = None
    try:
        # Use shorter timeout for connection status to prevent page load delays
        timeout_seconds = 5  # Increased from 3 to 5 for more reliability
        socket.setdefaulttimeout(timeout_seconds)
        
        ok, failure = preflight_connection(creds["host"], creds["port"], timeout_seconds)
        if not ok:
            return {}, f"Unable to reach router: {failure}"
        
        pool = routeros_api.RouterOsApiPool(
            creds["host"],
            username=creds["username"],
            password=creds["password"],
            port=creds["port"],
            use_ssl=creds["use_ssl"],
            plaintext_login=True,
        )
        api = pool.get_api()
        
        # Set timeout for API operations
        active_connections = api.get_resource("/ppp/active").get()
        
        # Enforce single session per username if enabled (skip on network monitoring to avoid delays)
        if enforce_single_session:
            # Group connections by username
            username_connections = {}
            for conn in active_connections:
                username = conn.get("name", "")
                if username:
                    if username not in username_connections:
                        username_connections[username] = []
                    username_connections[username].append(conn)
            
            # Immediately disconnect duplicate sessions to block internet access
            duplicates_found = False
            for username, conns in username_connections.items():
                if len(conns) > 1:
                    duplicates_found = True
                    logger.warning("SECURITY ALERT: Multiple sessions detected for user %s. Blocking internet access for duplicates immediately.", username)
                    try:
                        mikrotik_enforce_single_session(api, username)
                    except Exception as session_exc:  # noqa: BLE001
                        logger.warning("Error enforcing single session: %s", sanitize_error_message(str(session_exc)))
                        # Continue even if session enforcement fails
            
            # Re-fetch to get updated connection list after cleanup (only if we made changes)
            if duplicates_found:
                try:
                    active_connections = api.get_resource("/ppp/active").get()
                except Exception as refetch_exc:  # noqa: BLE001
                    logger.warning("Error re-fetching connections: %s", sanitize_error_message(str(refetch_exc)))
                    # Use original connections if re-fetch fails
        
        # RouterOS 6.x/7 does not return "bytes" on /ppp/active. Get traffic from /interface stats.
        # PPPoE interfaces can be named pppoe-in1, <pppoe-07049>, etc. Normalize for lookup.
        def _norm_if(s):
            if not s:
                return ""
            s = (s or "").strip()
            if isinstance(s, bytes):
                s = s.decode("utf-8", errors="replace")
            if s.startswith("<") and s.endswith(">"):
                s = s[1:-1]
            return s

        def _get(d, *keys):
            """Get first present key from dict; handle bytes keys."""
            for k in keys:
                v = d.get(k)
                if v is None and isinstance(k, str) and d:
                    v = d.get(k.encode("utf-8"))
                if v is not None:
                    return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
            return None

        interface_stats = {}
        pppoe_interface_list = []  # ordered list of (name_or_id, entry) for fallback match by position
        if active_connections:
            ifaces_raw = None
            # Binary API: pass bytes to avoid "Non-bytes value" warning; =stats= to get rx-byte/tx-byte
            try:
                ifaces_raw = api.get_binary_resource("/interface").call("print", {"stats": b""}, {})
            except Exception:  # noqa: BLE001
                pass
            if ifaces_raw is None:
                try:
                    ifaces_raw = api.get_resource("/interface").get()
                except Exception:  # noqa: BLE001
                    pass
            if ifaces_raw is not None:
                try:
                    ifaces_list = list(ifaces_raw) if not isinstance(ifaces_raw, list) else ifaces_raw
                    for iface in ifaces_list:
                        name = _get(iface, "name", "default-name")
                        if not name:
                            name = _get(iface, ".id")
                        if not name:
                            continue
                        rx = _get(iface, "rx-byte", "rx_byte") or 0
                        tx = _get(iface, "tx-byte", "tx_byte") or 0
                        try:
                            rx, tx = int(rx), int(tx)
                        except (TypeError, ValueError):
                            rx, tx = 0, 0
                        entry = {"bytes_sent": str(rx), "bytes_received": str(tx)}
                        interface_stats[name] = entry
                        interface_stats[_norm_if(name)] = entry
                        # Keep ordered list of PPPoE interfaces for fallback (match by position)
                        if_type = _get(iface, "type", "type")
                        if if_type and "pppoe" in (if_type or "").lower():
                            pppoe_interface_list.append((name, entry))
                except Exception as parse_exc:  # noqa: BLE001
                    logger.info("Interface stats parse: %s", sanitize_error_message(str(parse_exc)))

        if pool:
            pool.disconnect()

        # Create a map of username -> connection info
        connections_map = {}
        for conn in active_connections:
            username = conn.get("name", "")
            if username:
                # Prefer bytes from /ppp/active (older ROS) if present; else use interface stats
                bytes_str = conn.get("bytes", "")
                bytes_sent = "0"
                bytes_received = "0"
                if bytes_str and "," in bytes_str:
                    parts = bytes_str.split(",")
                    bytes_sent = parts[0].strip() if len(parts) > 0 else "0"
                    bytes_received = parts[1].strip() if len(parts) > 1 else "0"
                elif bytes_str:
                    bytes_sent = bytes_str.strip()
                else:
                    # RouterOS may use "interface", "session", "link", etc. Try all and bytes keys
                    if_name = _get(conn, "interface", "session", "link")
                    if not if_name or not (if_name or "").strip():
                        if_name = None
                    else:
                        if_name = (if_name or "").strip()
                    st = None
                    if if_name:
                        st = interface_stats.get(if_name) or interface_stats.get(_norm_if(if_name))
                    if st:
                        bytes_sent = st.get("bytes_sent", "0")
                        bytes_received = st.get("bytes_received", "0")
                    else:
                        # Fallback: match by position (1st session -> 1st PPPoE interface, etc.)
                        idx = len(connections_map)
                        if idx < len(pppoe_interface_list):
                            _name, st = pppoe_interface_list[idx]
                            bytes_sent = st.get("bytes_sent", "0")
                            bytes_received = st.get("bytes_received", "0")
                    if not st and len(connections_map) == 0 and (interface_stats or pppoe_interface_list):
                        # Log once: what keys does /ppp/active actually return?
                        conn_keys = list(conn.keys()) if hasattr(conn, "keys") else []
                        logger.info(
                            "Data usage: conn interface=%r; ppp/active keys=%s; pppoe interfaces count=%s",
                            if_name or "(empty)",
                            conn_keys[:20],
                            len(pppoe_interface_list),
                        )

                connections_map[username] = {
                    "address": conn.get("address", ""),
                    "uptime": conn.get("uptime", ""),
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "bytes_sent_formatted": format_bytes(bytes_sent),
                    "bytes_received_formatted": format_bytes(bytes_received),
                    "interface": conn.get("interface", ""),
                }
        return connections_map, None
    except (socket.timeout, TimeoutError) as timeout_exc:
        logger.warning("Timeout while fetching PPPoE connections from MikroTik: %s", sanitize_error_message(str(timeout_exc)))
        if pool:
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass
        return {}, "Connection timeout - router may be slow or unreachable. Please try again."
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error fetching PPPoE connections: %s", sanitize_error_message(str(exc)))
        if pool:
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass
        return {}, sanitize_error_message(str(exc))


@app.route("/users")
def user_management():
    creds, error = get_session_router_credentials()
    if error:
        return redirect(url_for("login"))

    # Get selected router_id
    router_id = session.get("selected_router_id")
    if not router_id:
        routers = db_list_mikrotik_routers()
        return render_template("user_management.html", error="No router selected. Please select a router.", routers=routers)

    # Keep enforcement active even when admin is not manually applying rules.
    maybe_enforce_pppoe_access_rules(creds, router_id)

    # Check and disable expired accounts
    check_and_disable_expired_accounts()

    # Fetch registered PPPoE users from database for selected router
    registered_users = db_list_pppoe_routers(router_id=router_id)
    
    # Fetch subscription plans first (needed for matching)
    subscription_plans = db_list_subscription_plans()
    
    # Fetch active PPPoE connections from MikroTik
    active_connections, conn_error = fetch_active_pppoe_connections(creds)
    
    # Combine database users with live connection status
    users_with_status = []
    stats = {
        "total": 0,
        "active_accounts": 0,
        "suspended_accounts": 0,
        "connected": 0,
    }
    
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    for user in registered_users:
        username = user.get("pppoe_username", "")
        is_connected = username in active_connections
        connection_info = active_connections.get(username, {})
        user_status = user.get("status", "active")
        expiration_date = user.get("expiration_date")
        user_download = float(user.get("download_speed_mbps") or 0)
        user_upload = float(user.get("upload_speed_mbps") or 0)
        matched_plan = None
        for plan in subscription_plans:
            plan_download = float(plan.get("download_speed_mbps") or 0)
            plan_upload = float(plan.get("upload_speed_mbps") or 0)
            if user_download == plan_download and user_upload == plan_upload:
                matched_plan = plan
                break
        # When the customer was allocated this plan (start of using that package); fall back to created_at for old rows
        plan_allocated_at = user.get("plan_allocated_at") or user.get("created_at")
        # Keep remaining days stable on speed edits by prioritizing stored expiration_date.
        days_left, expiration_date = _days_left_from_expiration(expiration_date, now)
        if days_left is None:
            days_left = _days_left_from_plan(plan_allocated_at, matched_plan, now)
        
        stats["total"] += 1
        if user_status == "active":
            stats["active_accounts"] += 1
        else:
            stats["suspended_accounts"] += 1
        if is_connected:
            stats["connected"] += 1
        
        bytes_sent = connection_info.get("bytes_sent", "0")
        bytes_received = connection_info.get("bytes_received", "0")
        try:
            total_bytes = int(bytes_sent) + int(bytes_received)
        except (ValueError, TypeError):
            total_bytes = 0
        total_formatted = format_bytes(str(total_bytes))

        # Data cap tracking (from DB)
        data_usage_bytes = 0
        try:
            data_usage_bytes = int(user.get("data_usage_bytes_this_period") or 0)
        except (TypeError, ValueError):
            pass
        cap_reset_at = user.get("cap_reset_at")
        last_seen_bytes = 0
        try:
            last_seen_bytes = int(user.get("last_seen_cumulative_bytes") or 0)
        except (TypeError, ValueError):
            pass
        over_cap_suspended = bool(user.get("over_cap_suspended"))
        pppoe_password_display = ""
        try:
            enc = user.get("pppoe_password_encrypted")
            if enc:
                pppoe_password_display = decrypt_password(enc)
        except Exception:  # noqa: BLE001
            pppoe_password_display = ""

        customer_wifi_password_display = ""
        try:
            wenc = user.get("customer_wifi_password_encrypted")
            if wenc:
                customer_wifi_password_display = decrypt_password(wenc)
        except Exception:  # noqa: BLE001
            customer_wifi_password_display = ""

        users_with_status.append({
            "id": user.get("id"),
            "customer_name": user.get("customer_name", ""),
            "phone_number": user.get("phone_number", ""),
            "pppoe_username": username,
            "pppoe_password_display": pppoe_password_display,
            "customer_wifi_ssid": (user.get("customer_wifi_ssid") or "").strip() or "",
            "customer_wifi_password_display": customer_wifi_password_display,
            "status": user_status,
            "expiration_date": expiration_date,
            "days_left": days_left,
            "mikrotik_secret_id": user.get("mikrotik_secret_id"),
            "created_at": user.get("created_at"),
            "is_connected": is_connected,
            "connection_address": connection_info.get("address", ""),
            "connection_uptime": connection_info.get("uptime", ""),
            "connection_interface": connection_info.get("interface", ""),
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "bytes_sent_formatted": connection_info.get("bytes_sent_formatted", "0 B"),
            "bytes_received_formatted": connection_info.get("bytes_received_formatted", "0 B"),
            "total_bytes": total_bytes,
            "total_formatted": total_formatted,
            "download_speed_mbps": user_download,
            "upload_speed_mbps": user_upload,
            "mikrotik_queue_id": user.get("mikrotik_queue_id"),
            "matched_plan": matched_plan,
            "data_usage_bytes_this_period": data_usage_bytes,
            "cap_reset_at": cap_reset_at,
            "last_seen_cumulative_bytes": last_seen_bytes,
            "over_cap_suspended": over_cap_suspended,
            "over_cap": False,
        })

    # Record cumulative usage to usage_daily (for network monitoring accuracy)
    try:
        _record_usage_from_connections(router_id, registered_users, active_connections)
    except Exception:  # noqa: BLE001
        pass

    # Update data usage and enforce caps (disable or downgrade when over limit)
    enforce_data_caps(creds, users_with_status, active_connections)
    # Apply speed limits on router; enforce PPPoE-only internet and remove unknown secrets
    ensure_queues_for_connected_users(creds, users_with_status, router_id=router_id)
    # Show users alphabetically (A-Z) by customer name.
    users_with_status.sort(
        key=lambda x: (
            (x.get("customer_name") or "").lower(),
            (x.get("pppoe_username") or "").lower(),
        )
    )

    return render_template(
        "user_management.html",
        users=users_with_status,
        stats=stats,
        subscription_plans=subscription_plans,
        error=conn_error if conn_error else None,
    )


@app.route("/api/users/data-usage", methods=["GET"])
def api_users_data_usage():
    """Return live data usage (bytes sent/received) per PPPoE username for the selected router. Used for polling on /users."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401
    active_connections, conn_error = fetch_active_pppoe_connections(creds)
    if conn_error:
        return jsonify({"error": conn_error, "usage": {}}), 200
    usage = {}
    for username, info in active_connections.items():
        sent = info.get("bytes_sent", "0")
        recv = info.get("bytes_received", "0")
        try:
            total = int(sent) + int(recv)
        except (ValueError, TypeError):
            total = 0
        key = username.lower() if username else ""
        if not key:
            continue
        usage[key] = {
            "bytes_sent": sent,
            "bytes_received": recv,
            "bytes_sent_formatted": info.get("bytes_sent_formatted", "0 B"),
            "bytes_received_formatted": info.get("bytes_received_formatted", "0 B"),
            "total_bytes": total,
            "total_formatted": format_bytes(str(total)),
        }
    return jsonify({"usage": usage, "error": None})


@app.route("/users/<int:user_id>")
def client_detail(user_id):
    """User (client) detail page: PPPoE account, connection status, data usage, controls."""
    creds, error = get_session_router_credentials()
    if error:
        return redirect(url_for("login"))

    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return redirect(url_for("user_management"))

    router_id = session.get("selected_router_id")
    if not router_id or user.get("mikrotik_router_id") != router_id:
        return redirect(url_for("user_management"))

    check_and_disable_expired_accounts()
    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return redirect(url_for("user_management"))
    if user.get("mikrotik_router_id") != router_id:
        return redirect(url_for("user_management"))

    active_connections, conn_error = fetch_active_pppoe_connections(creds)
    username = user.get("pppoe_username", "")
    is_connected = username in active_connections
    connection_info = active_connections.get(username, {})
    user_status = user.get("status", "active")

    expiration_date_raw = user.get("expiration_date")
    expiration_date = None
    if expiration_date_raw:
        if isinstance(expiration_date_raw, str):
            try:
                expiration_date = datetime.strptime(expiration_date_raw[:19], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                try:
                    expiration_date = datetime.strptime(expiration_date_raw[:10], "%Y-%m-%d")
                except (ValueError, TypeError):
                    pass
        else:
            expiration_date = expiration_date_raw
        if expiration_date and getattr(expiration_date, "tzinfo", None):
            expiration_date = expiration_date.replace(tzinfo=None)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    subscription_plans = db_list_subscription_plans()
    user_download = float(user.get("download_speed_mbps") or 0)
    user_upload = float(user.get("upload_speed_mbps") or 0)
    matched_plan = None
    for plan in subscription_plans:
        plan_download = float(plan.get("download_speed_mbps") or 0)
        plan_upload = float(plan.get("upload_speed_mbps") or 0)
        if user_download == plan_download and user_upload == plan_upload:
            matched_plan = plan
            break
    # When the customer was allocated this plan (start of using that package); fall back to created_at for old rows
    plan_allocated_at = user.get("plan_allocated_at") or user.get("created_at")
    # Keep remaining days stable on speed edits by prioritizing stored expiration_date.
    days_remaining, expiration_date = _days_left_from_expiration(expiration_date, now)
    if days_remaining is None:
        days_remaining = _days_left_from_plan(plan_allocated_at, matched_plan, now)

    try:
        password = decrypt_password(user["pppoe_password_encrypted"])
    except Exception:
        password = "********"
    customer_wifi_password = ""
    try:
        wenc = user.get("customer_wifi_password_encrypted")
        if wenc:
            customer_wifi_password = decrypt_password(wenc)
    except Exception:  # noqa: BLE001
        pass

    client_data = {
        "id": user.get("id"),
        "customer_name": user.get("customer_name", ""),
        "phone_number": user.get("phone_number", ""),
        "pppoe_username": username,
        "pppoe_password": password,
        "customer_wifi_ssid": (user.get("customer_wifi_ssid") or "").strip() or "",
        "customer_wifi_password": customer_wifi_password,
        "status": user_status,
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "is_connected": is_connected,
        "connection_address": connection_info.get("address", ""),
        "connection_uptime": connection_info.get("uptime", ""),
        "connection_interface": connection_info.get("interface", ""),
        "bytes_sent": connection_info.get("bytes_sent", "0"),
        "bytes_received": connection_info.get("bytes_received", "0"),
        "bytes_sent_formatted": connection_info.get("bytes_sent_formatted", "0 B"),
        "bytes_received_formatted": connection_info.get("bytes_received_formatted", "0 B"),
        "mikrotik_secret_id": user.get("mikrotik_secret_id"),
        "upload_speed_mbps": float(user.get("upload_speed_mbps")) if user.get("upload_speed_mbps") else None,
        "download_speed_mbps": float(user.get("download_speed_mbps")) if user.get("download_speed_mbps") else None,
        "max_devices": user.get("max_devices", 1),
        "mikrotik_queue_id": user.get("mikrotik_queue_id"),
        "expiration_date": expiration_date.strftime("%Y-%m-%d %H:%M:%S") if expiration_date else None,
        "days_remaining": days_remaining,
    }

    return render_template(
        "client_detail.html",
        client=client_data,
        error=conn_error if conn_error else None,
    )


@app.route("/api/users/<int:user_id>/connection")
def api_user_connection(user_id):
    """API endpoint to fetch live connection data for a specific user."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    # Get user from database
    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    
    # Verify user belongs to selected router
    valid, error_msg = verify_user_belongs_to_router(user)
    if not valid:
        return jsonify({"error": error_msg}), 403

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    # Fetch active PPPoE connections from MikroTik
    active_connections, conn_error = fetch_active_pppoe_connections(creds)
    
    username = user.get("pppoe_username", "")
    is_connected = username in active_connections
    connection_info = active_connections.get(username, {})
    client_ip = connection_info.get("address", "")
    
    # If client is connected and has speed limits, ensure queue is created/updated with correct target
    if is_connected:
        upload_mbps = user.get("upload_speed_mbps")
        download_mbps = user.get("download_speed_mbps")
        queue_id = user.get("mikrotik_queue_id")
        
        if upload_mbps or download_mbps:
            try:
                pool, api = get_router_api(creds)
                # Use IP + interface for strict limit on both wired and wireless
                pppoe_interface = mikrotik_get_pppoe_interface(api, username)
                target = _build_queue_target(client_ip, pppoe_interface)
                
                if target:
                    # Create or update queue with dual target (IP + interface) for strict limit on wired and wireless
                    updated_queue_id = mikrotik_create_or_update_queue(
                        api, username, target, upload_mbps, download_mbps, queue_id
                    )
                    if updated_queue_id:
                        if updated_queue_id != queue_id:
                            # Queue ID changed or was created, update database
                            db_update_pppoe_router(user_id, {"mikrotik_queue_id": updated_queue_id})
                pool.disconnect()
            except Exception as exc:  # noqa: BLE001
                # Log but don't fail the request
                logger.info("Error creating/updating queue: %s", sanitize_error_message(str(exc)))
    
    return jsonify({
        "is_connected": is_connected,
        "connection_address": client_ip,
        "connection_uptime": connection_info.get("uptime", ""),
        "connection_interface": connection_info.get("interface", ""),
        "bytes_sent": connection_info.get("bytes_sent", "0"),
        "bytes_received": connection_info.get("bytes_received", "0"),
        "bytes_sent_formatted": connection_info.get("bytes_sent_formatted", "0 B"),
        "bytes_received_formatted": connection_info.get("bytes_received_formatted", "0 B"),
        "error": conn_error if conn_error else None,
    })


@app.route("/api/users/<int:user_id>/speed-limits", methods=["PUT"])
def api_update_speed_limits(user_id):
    """API endpoint to update speed limits and device limits for a user."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    # Get user from database
    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    
    # Verify user belongs to selected router
    valid, error_msg = verify_user_belongs_to_router(user)
    if not valid:
        return jsonify({"error": error_msg}), 403

    data = request.get_json(force=True, silent=True) or {}
    upload_mbps = data.get("upload_speed_mbps")
    download_mbps = data.get("download_speed_mbps")
    max_devices = data.get("max_devices")

    # Validate inputs
    if upload_mbps is not None and (not isinstance(upload_mbps, (int, float)) or upload_mbps < 0):
        return jsonify({"error": "Upload speed must be a positive number (Mbps)."}), 400
    if download_mbps is not None and (not isinstance(download_mbps, (int, float)) or download_mbps < 0):
        return jsonify({"error": "Download speed must be a positive number (Mbps)."}), 400
    if max_devices is not None and (not isinstance(max_devices, int) or max_devices < 1):
        return jsonify({"error": "Max devices must be at least 1."}), 400

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    try:
        pool, api = get_router_api(creds)
        username = user.get("pppoe_username", "")
        queue_id = user.get("mikrotik_queue_id")
        
        # Use IP + interface for strict limit on both wired and wireless
        pppoe_interface = mikrotik_get_pppoe_interface(api, username)
        client_ip = mikrotik_get_pppoe_client_ip(api, username)
        target = _build_queue_target(client_ip, pppoe_interface)
        # User must be connected to create/update queue (we need at least IP or interface)
        
        updates = {}
        new_queue_id = queue_id

        # Keep subscription days stable when only Mbps changes:
        # if expiration_date is missing, materialize current derived plan end date first.
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        _, normalized_expiration = _days_left_from_expiration(user.get("expiration_date"), now)
        if normalized_expiration is None:
            matched_plan = None
            user_download = float(user.get("download_speed_mbps") or 0)
            user_upload = float(user.get("upload_speed_mbps") or 0)
            for plan in db_list_subscription_plans():
                plan_download = float(plan.get("download_speed_mbps") or 0)
                plan_upload = float(plan.get("upload_speed_mbps") or 0)
                if abs(plan_download - user_download) < 0.001 and abs(plan_upload - user_upload) < 0.001:
                    matched_plan = plan
                    break
            plan_allocated_at = user.get("plan_allocated_at") or user.get("created_at")
            derived_expiration = _plan_expiration_from_allocation(plan_allocated_at, matched_plan)
            if derived_expiration is not None:
                updates["expiration_date"] = derived_expiration
        
        # Update speed limits if provided
        if upload_mbps is not None or download_mbps is not None:
            current_upload = user.get("upload_speed_mbps") if upload_mbps is None else upload_mbps
            current_download = user.get("download_speed_mbps") if download_mbps is None else download_mbps
            
            # Convert from old Kbps values if they exist (migration)
            if current_upload and current_upload > 1000:
                current_upload = current_upload / 1000  # Assume it's in Kbps, convert to Mbps
            if current_download and current_download > 1000:
                current_download = current_download / 1000  # Assume it's in Kbps, convert to Mbps
            
            if current_upload or current_download:
                # Only create/update queue if we have a valid target (user is connected)
                if target:
                    # Ensure PPPoE traffic is not FastTracked so queue limits apply strictly
                    pppoe_pool_network = "192.168.1.0/24"
                    try:
                        pools = api.get_resource("/ip/pool").get(name="pppoe-pool")
                        if pools and pools[0].get("ranges"):
                            first_ip = (pools[0]["ranges"] or "").split("-")[0].strip()
                            if first_ip:
                                pppoe_pool_network = first_ip.rsplit(".", 1)[0] + ".0/24"
                    except Exception:  # noqa: BLE001
                        pass
                    mikrotik_ensure_pppoe_not_fasttracked(api, pppoe_pool_network)
                    new_queue_id = mikrotik_create_or_update_queue(
                        api, username, target, current_upload, current_download, queue_id
                    )
                    if new_queue_id:
                        updates["mikrotik_queue_id"] = new_queue_id
                        logger.info("Queue created/updated for %s: target=%s, upload=%sMbps, download=%sMbps, queue_id=%s", 
                                  username, target, current_upload, current_download, new_queue_id)
                    else:
                        return jsonify({"error": "Failed to create/update speed limit queue on MikroTik."}), 502
                else:
                    # User not connected - just store speed limits, queue will be created when they connect
                    logger.info("User %s not connected - storing speed limits (upload=%sMbps, download=%sMbps). Queue will be created when user connects.", 
                              username, current_upload, current_download)
                
                # Always update speed limits in database
                if upload_mbps is not None:
                    updates["upload_speed_mbps"] = upload_mbps
                if download_mbps is not None:
                    updates["download_speed_mbps"] = download_mbps
            else:
                # Remove queue if both speeds are 0 or None
                if queue_id:
                    mikrotik_remove_queue(api, queue_id)
                    updates["mikrotik_queue_id"] = None
                if upload_mbps is not None:
                    updates["upload_speed_mbps"] = None
                if download_mbps is not None:
                    updates["download_speed_mbps"] = None
        
        # Update max devices
        if max_devices is not None:
            updates["max_devices"] = max_devices
        
        pool.disconnect()
        
        # Update database
        if updates:
            db_update_pppoe_router(user_id, updates)
        
        return jsonify({
            "message": "Speed limits and device limits updated successfully.",
            "upload_speed_mbps": updates.get("upload_speed_mbps", user.get("upload_speed_mbps")),
            "download_speed_mbps": updates.get("download_speed_mbps", user.get("download_speed_mbps")),
            "max_devices": updates.get("max_devices", user.get("max_devices", 1)),
        })
        
    except Exception as exc:  # noqa: BLE001
        logger.info("Error updating speed limits: %s", sanitize_error_message(str(exc)))
        return jsonify({"error": sanitize_error_message(str(exc))}), 502


def check_and_disable_expired_accounts():
    """Check for expired accounts and automatically disable them."""
    try:
        # Only proceed if we have a session (user is logged in)
        if not session.get("user"):
            return
        
        router_id = session.get("selected_router_id")
        if not router_id:
            return
        
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        sql = """
            SELECT id, pppoe_username, mikrotik_secret_id, status 
            FROM pppoe_routers 
            WHERE mikrotik_router_id = %s
            AND expiration_date IS NOT NULL 
            AND expiration_date <= %s 
            AND status = 'active'
        """
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (router_id, now))
                expired_users = cur.fetchall()
        
        if not expired_users:
            return
        
        creds, error = get_session_router_credentials()
        if error:
            logger.info("Cannot check expired accounts: %s", error)
            return
        
        try:
            pool, api = get_router_api(creds)
            for user in expired_users:
                username = user.get("pppoe_username", "")
                secret_id = user.get("mikrotik_secret_id")
                
                # Disable in MikroTik
                if secret_id:
                    mikrotik_set_pppoe_disabled(api, secret_id, True)
                    # Disconnect active session
                    mikrotik_disconnect_pppoe_session(api, username)
                
                # Update database
                db_update_pppoe_router(user.get("id"), {"status": "suspended"})
                logger.info("Auto-disabled expired account: %s (expired)", username)
            
            pool.disconnect()
        except Exception as exc:  # noqa: BLE001
            logger.info("Error disabling expired accounts: %s", sanitize_error_message(str(exc)))
    except Exception as exc:  # noqa: BLE001
        logger.info("Error checking expired accounts: %s", sanitize_error_message(str(exc)))


@app.route("/api/users/<int:user_id>/expiration", methods=["PUT"])
def api_update_expiration(user_id):
    """API endpoint to set expiration period for a user."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    # Get user from database
    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    
    # Verify user belongs to selected router
    valid, error_msg = verify_user_belongs_to_router(user)
    if not valid:
        return jsonify({"error": error_msg}), 403

    data = request.get_json(force=True, silent=True) or {}
    days = data.get("days")
    
    # Validate input
    if days is not None:
        if not isinstance(days, (int, float)) or days < 0:
            return jsonify({"error": "Days must be a positive number."}), 400
        if days == 0:
            # Remove expiration (set to None)
            expiration_date = None
        else:
            # Calculate expiration date from today + days
            expiration_date = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=int(days))
    else:
        expiration_date = None
    
    # Update database: when setting/renewing expiration, set plan_allocated_at = now (start of this period)
    updates = {"expiration_date": expiration_date}
    if expiration_date is not None:
        updates["plan_allocated_at"] = datetime.now(timezone.utc).replace(tzinfo=None)
    db_update_pppoe_router(user_id, updates)
    
    # Check if account should be disabled (if expiration is in the past)
    if expiration_date and expiration_date <= datetime.now(timezone.utc).replace(tzinfo=None):
        # Account is already expired, disable it
        creds, error = get_session_router_credentials()
        if not error:
            try:
                pool, api = get_router_api(creds)
                username = user.get("pppoe_username", "")
                secret_id = user.get("mikrotik_secret_id")
                if secret_id:
                    mikrotik_set_pppoe_disabled(api, secret_id, True)
                    mikrotik_disconnect_pppoe_session(api, username)
                db_update_pppoe_router(user_id, {"status": "suspended"})
                pool.disconnect()
            except Exception as exc:  # noqa: BLE001
                logger.info("Error disabling expired account: %s", sanitize_error_message(str(exc)))
    
    return jsonify({
        "message": "Expiration period updated successfully.",
        "expiration_date": expiration_date.isoformat() if expiration_date else None,
        "days_remaining": (expiration_date - datetime.now(timezone.utc).replace(tzinfo=None)).days if expiration_date else None,
    })


@app.route("/api/billing/users/<int:user_id>/plan-start-date", methods=["PUT"])
def api_update_billing_plan_start_date(user_id):
    """Update billing plan allocation date and recalculate plan expiration from plan duration."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    data = request.get_json(force=True, silent=True) or {}
    plan_allocated_at_raw = (data.get("plan_allocated_at") or "").strip()
    if not plan_allocated_at_raw:
        return jsonify({"error": "Plan allocated date is required (YYYY-MM-DD)."}), 400

    try:
        plan_allocated_at = datetime.strptime(plan_allocated_at_raw[:10], "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    subscription_plans = db_list_subscription_plans()
    user_download = float(user.get("download_speed_mbps") or 0)
    user_upload = float(user.get("upload_speed_mbps") or 0)
    matched_plan = None
    for plan in subscription_plans:
        plan_download = float(plan.get("download_speed_mbps") or 0)
        plan_upload = float(plan.get("upload_speed_mbps") or 0)
        if user_download == plan_download and user_upload == plan_upload:
            matched_plan = plan
            break

    updates = {"plan_allocated_at": plan_allocated_at}
    plan_expiration_date = _plan_expiration_from_allocation(plan_allocated_at, matched_plan)
    if plan_expiration_date is not None:
        # Keep expiration in sync so all pages use this plan start as the source of truth.
        updates["expiration_date"] = plan_expiration_date

    db_update_pppoe_router(user_id, updates)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    account_expiration_raw = updates.get("expiration_date", user.get("expiration_date"))
    days_left = (plan_expiration_date - now).days if plan_expiration_date else None
    _, account_expiration = _days_left_from_expiration(account_expiration_raw, now)
    if days_left is None:
        days_left, _ = _days_left_from_expiration(account_expiration_raw, now)
    return jsonify({
        "message": "Plan start date updated successfully.",
        "plan_allocated_at": plan_allocated_at.strftime("%Y-%m-%d"),
        "plan_allocated_at_display": _format_date_for_display(plan_allocated_at),
        "plan_expiration_date": plan_expiration_date.strftime("%Y-%m-%d") if plan_expiration_date else None,
        "plan_expiration_date_display": _format_date_for_display(plan_expiration_date) if plan_expiration_date else "—",
        "account_expiration_date_display": _format_date_for_display(account_expiration) if account_expiration else "—",
        "days_left": days_left,
    })


@app.route("/api/billing/users/<int:user_id>/payments", methods=["PUT"])
def api_update_billing_payment_checkbox(user_id):
    """Update monthly payment checkbox state for a user."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    data = request.get_json(force=True, silent=True) or {}
    month = data.get("month")
    year = data.get("year")
    paid = bool(data.get("paid"))

    try:
        month = int(month)
        year = int(year)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid month or year."}), 400
    if month < 1 or month > 12:
        return jsonify({"error": "Month must be between 1 and 12."}), 400
    if year < 2000 or year > 2100:
        return jsonify({"error": "Year is out of range."}), 400

    router_id = user.get("mikrotik_router_id")
    if not router_id:
        return jsonify({"error": "User has no router assigned."}), 400

    db_set_billing_payment_status(router_id, user_id, year, month, paid)
    return jsonify({
        "message": "Payment status updated.",
        "user_id": user_id,
        "month": month,
        "year": year,
        "paid": paid,
    })


def _record_usage_from_connections(router_id, registered_users, active_connections):
    """Update usage_daily with cumulative bytes from current connections. Call after fetching
    active_connections so we store accurate sent/received per day. Uses last_seen_bytes_sent/received
    to compute delta and flush to today's row; on disconnect we flush remaining bytes to today."""
    if not router_id or not registered_users:
        return
    today = datetime.now(timezone.utc).replace(tzinfo=None).date()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            for user in registered_users:
                username = (user.get("pppoe_username") or "").strip()
                if not username:
                    continue
                user_id = user.get("id")
                last_sent = int(user.get("last_seen_bytes_sent") or 0)
                last_received = int(user.get("last_seen_bytes_received") or 0)
                info = active_connections.get(username, {})
                try:
                    cur_sent = int(info.get("bytes_sent") or 0)
                    cur_received = int(info.get("bytes_received") or 0)
                except (TypeError, ValueError):
                    cur_sent, cur_received = 0, 0
                if info:
                    # Connected: delta since last poll (router counters are cumulative for this session)
                    delta_sent = max(0, cur_sent - last_sent)
                    delta_received = max(0, cur_received - last_received)
                    cur.execute(
                        """INSERT INTO usage_daily (router_id, pppoe_username, usage_date, bytes_sent, bytes_received)
                           VALUES (%s, %s, %s, %s, %s)
                           ON DUPLICATE KEY UPDATE
                           bytes_sent = bytes_sent + VALUES(bytes_sent),
                           bytes_received = bytes_received + VALUES(bytes_received)""",
                        (router_id, username, today, delta_sent, delta_received),
                    )
                    db_update_pppoe_router(user_id, {
                        "last_seen_bytes_sent": cur_sent,
                        "last_seen_bytes_received": cur_received,
                    })
                else:
                    # Disconnected: flush last known bytes to today and reset
                    if last_sent > 0 or last_received > 0:
                        cur.execute(
                            """INSERT INTO usage_daily (router_id, pppoe_username, usage_date, bytes_sent, bytes_received)
                               VALUES (%s, %s, %s, %s, %s)
                               ON DUPLICATE KEY UPDATE
                               bytes_sent = bytes_sent + VALUES(bytes_sent),
                               bytes_received = bytes_received + VALUES(bytes_received)""",
                            (router_id, username, today, last_sent, last_received),
                        )
                        db_update_pppoe_router(user_id, {
                            "last_seen_bytes_sent": 0,
                            "last_seen_bytes_received": 0,
                        })


def _get_usage_aggregated(router_id, filter_type, filter_date=None, start_date=None, end_date=None, filter_month=None):
    """Return dict: pppoe_username -> {bytes_sent, bytes_received}. filter_type: 'day','range','month','all'."""
    if not router_id:
        return {}
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            if filter_type == "day" and filter_date:
                cur.execute(
                    """SELECT pppoe_username, SUM(bytes_sent) AS bytes_sent, SUM(bytes_received) AS bytes_received
                       FROM usage_daily WHERE router_id = %s AND usage_date = %s
                       GROUP BY pppoe_username""",
                    (router_id, filter_date),
                )
            elif filter_type == "range" and start_date and end_date:
                cur.execute(
                    """SELECT pppoe_username, SUM(bytes_sent) AS bytes_sent, SUM(bytes_received) AS bytes_received
                       FROM usage_daily WHERE router_id = %s AND usage_date BETWEEN %s AND %s
                       GROUP BY pppoe_username""",
                    (router_id, start_date, end_date),
                )
            elif filter_type == "month" and filter_month:
                # filter_month is 'YYYY-MM'
                cur.execute(
                    """SELECT pppoe_username, SUM(bytes_sent) AS bytes_sent, SUM(bytes_received) AS bytes_received
                       FROM usage_daily WHERE router_id = %s AND DATE_FORMAT(usage_date, '%%Y-%%m') = %s
                       GROUP BY pppoe_username""",
                    (router_id, filter_month),
                )
            else:
                # all time
                cur.execute(
                    """SELECT pppoe_username, SUM(bytes_sent) AS bytes_sent, SUM(bytes_received) AS bytes_received
                       FROM usage_daily WHERE router_id = %s
                       GROUP BY pppoe_username""",
                    (router_id,),
                )
            rows = cur.fetchall()
    return {str(r["pppoe_username"]): {"bytes_sent": int(r["bytes_sent"] or 0), "bytes_received": int(r["bytes_received"] or 0)} for r in rows}


def _list_usage_months(router_id):
    """Return available usage months for a router as ['YYYY-MM', ...] newest first."""
    if not router_id:
        return []
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT DATE_FORMAT(usage_date, '%%Y-%%m') AS usage_month
                   FROM usage_daily
                   WHERE router_id = %s
                   ORDER BY usage_month DESC""",
                (router_id,),
            )
            rows = cur.fetchall()
    return [str(r.get("usage_month")) for r in rows if r.get("usage_month")]


@app.route("/network-monitoring")
def network_monitoring():
    creds, error = get_session_router_credentials()
    if error:
        return redirect(url_for("login"))

    # Get selected router_id
    router_id = session.get("selected_router_id")
    if not router_id:
        return render_template("clients.html", error="No router selected. Please select a router.", routers=db_list_mikrotik_routers())

    # Keep enforcement active even when admin is viewing monitoring.
    maybe_enforce_pppoe_access_rules(creds, router_id)

    # Skip expired account check on network monitoring to prevent timeouts
    # It will be checked on other pages
    
    # Fetch registered PPPoE users from database for selected router
    registered_users = db_list_pppoe_routers(router_id=router_id)
    subscription_plans = db_list_subscription_plans()
    
    # Fetch active PPPoE connections from MikroTik with timeout handling
    try:
        active_connections, conn_error = fetch_active_pppoe_connections(creds, enforce_single_session=False)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error in network monitoring: %s", sanitize_error_message(str(exc)))
        active_connections = {}
        conn_error = f"Error fetching connection data: {sanitize_error_message(str(exc))}"
    
    # Record cumulative usage from this poll (so usage_daily stays accurate and cumulative)
    try:
        _record_usage_from_connections(router_id, registered_users, active_connections)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error recording usage: %s", sanitize_error_message(str(exc)))
    
    # Date filter from query params
    filter_type = request.args.get("filter", "all")
    filter_date = request.args.get("date")
    start_date = request.args.get("start")
    end_date = request.args.get("end")
    filter_month = request.args.get("month")
    current_month = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m")
    if filter_type == "day":
        if not filter_date:
            filter_type = "all"
        else:
            try:
                datetime.strptime(filter_date, "%Y-%m-%d")
            except ValueError:
                filter_date = None
                filter_type = "all"
    if filter_type == "range" and (not start_date or not end_date):
        filter_type = "all"
    if filter_type == "month":
        if not filter_month:
            filter_month = current_month
        else:
            try:
                datetime.strptime(filter_month, "%Y-%m")
            except ValueError:
                filter_month = current_month
    usage_map = _get_usage_aggregated(
        router_id, filter_type,
        filter_date=filter_date, start_date=start_date, end_date=end_date, filter_month=filter_month,
    )
    
    # Calculate overall statistics from aggregated usage
    total_clients = len(registered_users)
    connected_clients = len(active_connections)
    total_bytes_sent = 0
    total_bytes_received = 0
    
    # Combine database users with live connection status; use cumulative usage for selected period
    clients_with_status = []
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    for user in registered_users:
        username = user.get("pppoe_username", "")
        is_connected = username in active_connections
        connection_info = active_connections.get(username, {})
        user_status = user.get("status", "active")
        expiration_date = user.get("expiration_date")
        user_download = float(user.get("download_speed_mbps") or 0)
        user_upload = float(user.get("upload_speed_mbps") or 0)
        matched_plan = None
        for plan in subscription_plans:
            plan_download = float(plan.get("download_speed_mbps") or 0)
            plan_upload = float(plan.get("upload_speed_mbps") or 0)
            if user_download == plan_download and user_upload == plan_upload:
                matched_plan = plan
                break
        plan_allocated_at = user.get("plan_allocated_at") or user.get("created_at")
        days_left, expiration_date = _days_left_from_expiration(expiration_date, now)
        if days_left is None:
            days_left = _days_left_from_plan(plan_allocated_at, matched_plan, now)
        
        # Use cumulative usage for selected period (accurate, does not reset)
        agg = usage_map.get(username, {"bytes_sent": 0, "bytes_received": 0})
        bytes_sent = agg["bytes_sent"]
        bytes_received = agg["bytes_received"]
        total_bytes_sent += bytes_sent
        total_bytes_received += bytes_received
        
        clients_with_status.append({
            "id": user.get("id"),
            "customer_name": user.get("customer_name", ""),
            "phone_number": user.get("phone_number", ""),
            "pppoe_username": username,
            "status": user_status,
            "is_connected": is_connected,
            "connection_address": connection_info.get("address", ""),
            "connection_uptime": connection_info.get("uptime", ""),
            "connection_interface": connection_info.get("interface", ""),
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "bytes_sent_formatted": format_bytes(str(bytes_sent)),
            "bytes_received_formatted": format_bytes(str(bytes_received)),
            "total_bytes": bytes_sent + bytes_received,
            "days_left": days_left,
            "download_speed_mbps": user.get("download_speed_mbps"),
            "upload_speed_mbps": user.get("upload_speed_mbps"),
        })
    
    clients_with_status.sort(key=lambda x: x["total_bytes"], reverse=True)
    
    stats = {
        "total_clients": total_clients,
        "connected_clients": connected_clients,
        "disconnected_clients": total_clients - connected_clients,
        "total_bytes_sent": total_bytes_sent,
        "total_bytes_received": total_bytes_received,
        "total_bytes_sent_formatted": format_bytes(str(total_bytes_sent)),
        "total_bytes_received_formatted": format_bytes(str(total_bytes_received)),
        "total_data_formatted": format_bytes(str(total_bytes_sent + total_bytes_received)),
    }
    
    today = now.date().isoformat() if now else ""
    month_options = _list_usage_months(router_id)
    if current_month not in month_options:
        month_options.insert(0, current_month)
    usage_reset_ok = request.args.get("usage_reset") == "1"
    return render_template(
        "network_monitoring.html",
        clients=clients_with_status,
        stats=stats,
        error=conn_error if conn_error else None,
        filter_type=filter_type,
        filter_date=filter_date or "",
        start_date=start_date or "",
        end_date=end_date or "",
        filter_month=filter_month or "",
        month_options=month_options,
        today=today,
        usage_reset_ok=usage_reset_ok,
    )


@app.route("/network-monitoring/reset-usage", methods=["POST"])
def network_monitoring_reset_usage():
    """Clear stored usage_daily stats for the selected router only (network monitoring data)."""
    creds, error = get_session_router_credentials()
    if error:
        return redirect(url_for("login"))
    router_id = session.get("selected_router_id")
    if not router_id:
        return redirect(url_for("network_monitoring"))
    maybe_enforce_pppoe_access_rules(creds, router_id)
    registered_users = db_list_pppoe_routers(router_id=router_id)
    active_connections = {}
    try:
        active_connections, _ = fetch_active_pppoe_connections(creds, enforce_single_session=False)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Reset usage: could not fetch MikroTik counters: %s", sanitize_error_message(str(exc)))
    db_reset_network_monitoring_usage_for_router(
        router_id, active_connections=active_connections, registered_users=registered_users
    )
    return redirect(url_for("network_monitoring", usage_reset=1))


def _get_hotspot_password_from_settings():
    """Return decrypted hotspot password from settings, or empty string."""
    enc = db_get_setting("hotspot_password_encrypted")
    if not enc:
        return ""
    try:
        return decrypt_password(enc)
    except Exception:  # noqa: BLE001
        return ""


@app.route("/hotspot")
def hotspot_management():
    creds, error = get_session_router_credentials()
    if error:
        return redirect(url_for("login"))
    router_name = creds.get("router_name", "Selected router") if creds else "Selected router"
    hotspot_ssid = db_get_setting("hotspot_ssid") or "Free WiFi"
    captive_portal_enabled = (db_get_setting("hotspot_captive_portal_enabled", "0") or "0").strip() in {"1", "true", "yes", "on"}
    captive_portal_url = (db_get_setting("hotspot_captive_portal_url", "") or "").strip()
    hotspot_enforcement_mode = (db_get_setting("hotspot_enforcement_mode", "portal_only") or "portal_only").strip().lower()
    if hotspot_enforcement_mode not in {"portal_only", "mikrotik_enforced"}:
        hotspot_enforcement_mode = "portal_only"
    default_portal_url = url_for("hotspot_portal", _external=True)
    # Password is stored encrypted; we don't show it back for security (admin re-enters to apply to customers)
    hotspot_password_set = bool(db_get_setting("hotspot_password_encrypted"))
    router_id = session.get("selected_router_id")
    all_customers = db_list_pppoe_routers(router_id=router_id) if router_id else []
    # Normalize guest_network_enabled (column may be 0/1 or missing in old rows)
    customers_with_guest = [
        c for c in all_customers
        if c.get("guest_network_enabled") in (1, True) or (isinstance(c.get("guest_network_enabled"), (int, float)) and c.get("guest_network_enabled") != 0)
    ]
    guest_ids = {c["id"] for c in customers_with_guest}
    customers_without_guest = [c for c in all_customers if c["id"] not in guest_ids]
    return render_template(
        "hotspot_management.html",
        router_name=router_name,
        hotspot_ssid=hotspot_ssid,
        hotspot_password_set=hotspot_password_set,
        captive_portal_enabled=captive_portal_enabled,
        captive_portal_url=captive_portal_url,
        hotspot_enforcement_mode=hotspot_enforcement_mode,
        default_portal_url=default_portal_url,
        customers_with_guest=customers_with_guest,
        customers_without_guest=customers_without_guest,
        all_customers=all_customers,
        error=error,
    )


@app.route("/api/hotspot/configure", methods=["POST"])
def api_hotspot_configure():
    """Save hotspot SSID and password for the guest/second broadcast on client routers.
    Does not change any customer's own WiFi settings. Techs configure the CPE to broadcast
    this as an extra SSID (guest/hotspot); when users connect to it they get internet."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401
    selected_router_id = session.get("selected_router_id")
    if not selected_router_id:
        return jsonify({"error": "No router selected."}), 400
    data = request.get_json(force=True, silent=True) or {}
    free_wifi_ssid = (data.get("free_wifi_ssid") or data.get("ssid") or "Free WiFi").strip() or "Free WiFi"
    free_wifi_password = (data.get("free_wifi_password") or data.get("password") or "").strip()
    captive_portal_enabled = bool(data.get("captive_portal_enabled"))
    captive_portal_url = (data.get("captive_portal_url") or "").strip()
    hotspot_enforcement_mode = (data.get("hotspot_enforcement_mode") or "portal_only").strip().lower()
    if hotspot_enforcement_mode not in {"portal_only", "mikrotik_enforced"}:
        hotspot_enforcement_mode = "portal_only"
    if captive_portal_enabled and not captive_portal_url:
        captive_portal_url = url_for("hotspot_portal", _external=True)
    if captive_portal_enabled and not re.match(r"^https?://", captive_portal_url, flags=re.IGNORECASE):
        return jsonify({"error": "Captive portal URL must start with http:// or https://"}), 400

    db_set_setting("hotspot_ssid", free_wifi_ssid)
    db_set_setting("hotspot_router_id", str(selected_router_id))
    db_set_setting("hotspot_enforcement_mode", hotspot_enforcement_mode)

    # Phase 1: in captive portal mode we enforce open guest WiFi and redirect support settings.
    if captive_portal_enabled:
        db_set_setting("hotspot_password_encrypted", "")
    elif free_wifi_password:
        db_set_setting("hotspot_password_encrypted", encrypt_password(free_wifi_password))
    db_set_setting("hotspot_captive_portal_enabled", "1" if captive_portal_enabled else "0")
    db_set_setting("hotspot_captive_portal_url", captive_portal_url if captive_portal_enabled else "")

    if captive_portal_enabled:
        message = (
            f"Hotspot network '{free_wifi_ssid}' saved in captive portal mode. "
            "Guest WiFi password is disabled (open SSID). Configure client CPE captive portal redirect to "
            f"'{captive_portal_url}' so users are redirected to choose a plan before internet access."
        )
    else:
        message = (
            f"Hotspot network '{free_wifi_ssid}' saved. Configure each client's router to broadcast this as a "
            "separate SSID (guest/hotspot) without changing the client's own WiFi. Users who connect to it get internet."
        )

    return jsonify({
        "message": message,
        "captive_portal_enabled": captive_portal_enabled,
        "captive_portal_url": captive_portal_url if captive_portal_enabled else "",
        "hotspot_enforcement_mode": hotspot_enforcement_mode,
    })


def _normalize_mac(mac):
    raw = (mac or "").strip().replace("-", ":").replace(".", "").upper()
    if "." in (mac or ""):
        raw = (mac or "").replace(".", "").upper()
        if len(raw) == 12:
            raw = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    if re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", raw):
        return raw
    return ""


def mikrotik_upsert_hotspot_ip_binding(api, hotspot_mac, client_ip, comment):
    """Create or update hotspot ip-binding as bypassed for MAC/IP."""
    bindings = api.get_resource("/ip/hotspot/ip-binding")
    mac_norm = _normalize_mac(hotspot_mac)
    address = (client_ip or "").strip()

    existing = []
    try:
        if mac_norm:
            existing = bindings.get(**{"mac-address": mac_norm})
    except Exception:  # noqa: BLE001
        existing = []
    if not existing and address:
        try:
            existing = bindings.get(address=address)
        except Exception:  # noqa: BLE001
            existing = []

    payload = {"type": "bypassed", "disabled": "no", "comment": comment}
    if mac_norm:
        payload["mac-address"] = mac_norm
    if address:
        payload["address"] = address

    if existing:
        bindings.set(id=existing[0]["id"], **payload)
    else:
        bindings.add(**payload)


def _cleanup_expired_hotspot_access_for_router(router_id, creds):
    """Remove bypass bindings for expired hotspot access sessions and mark them expired."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expired_rows = db_list_expired_hotspot_access_sessions(router_id, now)
    if not expired_rows:
        return
    pool = None
    try:
        pool, api = get_router_api(creds)
        bindings = api.get_resource("/ip/hotspot/ip-binding")
        for row in expired_rows:
            mac_norm = _normalize_mac(row.get("hotspot_mac"))
            ip_addr = (row.get("client_ip") or "").strip()
            matches = []
            try:
                if mac_norm:
                    matches = bindings.get(**{"mac-address": mac_norm})
            except Exception:  # noqa: BLE001
                matches = []
            if not matches and ip_addr:
                try:
                    matches = bindings.get(address=ip_addr)
                except Exception:  # noqa: BLE001
                    matches = []
            for b in matches:
                try:
                    bindings.remove(id=b["id"])
                except Exception:  # noqa: BLE001
                    pass
            db_mark_hotspot_access_session_expired(row["id"], now)
    finally:
        if pool:
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass


@app.route("/hotspot/portal")
def hotspot_portal():
    """Public portal page where hotspot users select a plan."""
    hotspot_ssid = db_get_setting("hotspot_ssid", "Hotspot WiFi")
    plans = db_list_subscription_plans()
    plans_sorted = sorted(
        plans,
        key=lambda p: float(p.get("cost") or 0),
    )
    return render_template(
        "hotspot_portal.html",
        hotspot_ssid=hotspot_ssid,
        plans=plans_sorted,
        mac=(request.args.get("mac") or request.args.get("mac-esc") or "").strip(),
        client_ip=(request.args.get("ip") or request.args.get("ip-address") or "").strip(),
        dst=(request.args.get("dst") or request.args.get("link-orig") or request.args.get("link-login-only") or "").strip(),
    )


@app.route("/api/hotspot/portal/select-plan", methods=["POST"])
def api_hotspot_portal_select_plan():
    """Capture hotspot plan selection. In MikroTik mode auto-grant access; in portal-only mode store request."""
    data = request.get_json(force=True, silent=True) or {}
    plan_id = data.get("plan_id")
    customer_name = (data.get("customer_name") or "").strip()
    phone_number = (data.get("phone_number") or "").strip()
    hotspot_mac = (data.get("mac") or "").strip()
    client_ip = (data.get("client_ip") or request.remote_addr or "").strip()
    redirect_dst = (data.get("dst") or "").strip()

    try:
        plan_id = int(plan_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Please select a plan."}), 400
    if not customer_name:
        return jsonify({"error": "Customer name is required."}), 400

    plan = db_get_subscription_plan_by_id(plan_id)
    if not plan:
        return jsonify({"error": "Selected plan not found."}), 404
    try:
        duration_days = int(plan.get("duration_days") or 0)
    except (TypeError, ValueError):
        duration_days = 0
    if duration_days < 1:
        return jsonify({"error": "Selected plan has invalid duration."}), 400

    request_id = db_insert_hotspot_plan_request(
        plan_id=plan_id,
        plan_name=plan.get("plan_name"),
        customer_name=customer_name,
        phone_number=phone_number,
        hotspot_mac=hotspot_mac,
        client_ip=client_ip,
        redirect_dst=redirect_dst,
    )

    enforcement_mode = (db_get_setting("hotspot_enforcement_mode", "portal_only") or "portal_only").strip().lower()
    if enforcement_mode not in {"portal_only", "mikrotik_enforced"}:
        enforcement_mode = "portal_only"

    if enforcement_mode == "portal_only":
        db_update_hotspot_plan_request_status(request_id, "portal_only")
        return jsonify({
            "message": "Plan selected successfully. Portal request received.",
            "request_id": request_id,
            "redirect_to": redirect_dst or "",
            "enforcement_mode": enforcement_mode,
        })

    router_id_raw = db_get_setting("hotspot_router_id")
    try:
        router_id = int(router_id_raw or 0)
    except (TypeError, ValueError):
        router_id = 0
    if not router_id:
        db_update_hotspot_plan_request_status(request_id, "failed")
        return jsonify({"error": "Hotspot router is not configured yet. Ask admin to save Hotspot settings first."}), 400

    creds, creds_error = get_router_credentials_by_id(router_id)
    if creds_error:
        db_update_hotspot_plan_request_status(request_id, "failed")
        return jsonify({"error": f"Unable to provision access: {creds_error}"}), 502

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = now + timedelta(days=duration_days)
    binding_comment = (
        f"portal:{request_id}:{plan.get('plan_name')}:{now.strftime('%Y-%m-%d')}->"
        f"{expires_at.strftime('%Y-%m-%d')}"
    )
    try:
        _cleanup_expired_hotspot_access_for_router(router_id, creds)
        pool, api = get_router_api(creds)
        try:
            mikrotik_upsert_hotspot_ip_binding(api, hotspot_mac, client_ip, binding_comment)
        finally:
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass

        db_insert_hotspot_access_session(
            router_id=router_id,
            hotspot_plan_request_id=request_id,
            plan_id=plan_id,
            plan_name=plan.get("plan_name"),
            customer_name=customer_name,
            phone_number=phone_number,
            hotspot_mac=hotspot_mac,
            client_ip=client_ip,
            granted_at=now,
            expires_at=expires_at,
        )
        db_update_hotspot_plan_request_status(request_id, "granted")
    except Exception as exc:  # noqa: BLE001
        db_update_hotspot_plan_request_status(request_id, "failed")
        return jsonify({"error": f"Failed to provision hotspot access: {sanitize_error_message(str(exc))}"}), 502

    redirect_to = redirect_dst or ""
    return jsonify({
        "message": "Plan selected and access granted. You can continue browsing.",
        "request_id": request_id,
        "granted_until": expires_at.isoformat(),
        "redirect_to": redirect_to,
        "enforcement_mode": enforcement_mode,
    })


@app.route("/api/hotspot/toggle-customer", methods=["POST"])
def api_hotspot_toggle_customer():
    """Mark a customer (client router) as having guest network activated or deactivated. Does not change any CPE settings."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401
    router_id = session.get("selected_router_id")
    if not router_id:
        return jsonify({"error": "No router selected."}), 400
    data = request.get_json(force=True, silent=True) or {}
    customer_id = data.get("customer_id")
    enabled = data.get("enabled", True)
    if customer_id is None:
        return jsonify({"error": "customer_id required."}), 400
    try:
        customer_id = int(customer_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid customer_id."}), 400
    customer = db_get_pppoe_router_by_id(customer_id)
    if not customer:
        return jsonify({"error": "Customer not found."}), 404
    if customer.get("mikrotik_router_id") != router_id:
        return jsonify({"error": "Customer does not belong to the selected router."}), 403
    db_update_pppoe_router(customer_id, {"guest_network_enabled": 1 if enabled else 0})
    return jsonify({
        "message": "Guest network marked as " + ("activated" if enabled else "deactivated") + " for this customer.",
        "enabled": bool(enabled),
    })


def _format_date_for_display(dt):
    """Format datetime for display (e.g. 22 Feb 2025). Returns None or string."""
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.strptime(dt[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            try:
                dt = datetime.strptime(dt[:10], "%Y-%m-%d")
            except ValueError:
                return dt
    if hasattr(dt, "tzinfo") and dt.tzinfo:
        dt = dt.replace(tzinfo=None)
    return dt.strftime("%d %b %Y")


def _days_left_from_expiration(expiration_date, now):
    """Calculate days left from stored expiration_date; return (days_left, normalized_expiration)."""
    if not expiration_date:
        return None, None
    normalized_expiration = expiration_date
    if isinstance(normalized_expiration, str):
        try:
            normalized_expiration = datetime.strptime(normalized_expiration[:19], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            try:
                normalized_expiration = datetime.strptime(normalized_expiration[:10], "%Y-%m-%d")
            except (ValueError, TypeError):
                return None, None
    if hasattr(normalized_expiration, "tzinfo") and normalized_expiration.tzinfo:
        normalized_expiration = normalized_expiration.replace(tzinfo=None)
    try:
        return (normalized_expiration - now).days, normalized_expiration
    except TypeError:
        return None, normalized_expiration


def _plan_expiration_from_allocation(plan_allocated_at, matched_plan):
    """Calculate plan expiration datetime from plan allocation date and plan duration."""
    if not plan_allocated_at or not matched_plan:
        return None
    try:
        duration_days = int(matched_plan.get("duration_days") or 0)
    except (TypeError, ValueError):
        return None
    if duration_days < 0:
        return None
    parsed_allocated = plan_allocated_at
    if isinstance(parsed_allocated, str):
        try:
            parsed_allocated = datetime.strptime(parsed_allocated[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            try:
                parsed_allocated = datetime.strptime(parsed_allocated[:10], "%Y-%m-%d")
            except ValueError:
                return None
    if hasattr(parsed_allocated, "tzinfo") and parsed_allocated.tzinfo:
        parsed_allocated = parsed_allocated.replace(tzinfo=None)
    start_date = parsed_allocated.date() if hasattr(parsed_allocated, "date") else parsed_allocated
    end_date = start_date + timedelta(days=duration_days)
    return datetime.combine(end_date, datetime.min.time())


def _days_left_from_plan(plan_allocated_at, matched_plan, now):
    """
    Calculate days left from when the customer was allocated this plan (start date of using that package):
    end_date = plan_allocated_at + plan.duration_days, then days_left = (end_date - today).days.
    Returns None if no plan or no plan_allocated_at; otherwise an int (can be negative if expired).
    """
    if not plan_allocated_at or not matched_plan:
        return None
    try:
        duration_days = int(matched_plan.get("duration_days") or 0)
    except (TypeError, ValueError):
        return None
    if duration_days < 0:
        return None
    # Parse plan_allocated_at to date
    if isinstance(plan_allocated_at, str):
        try:
            plan_allocated_at = datetime.strptime(plan_allocated_at[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            try:
                plan_allocated_at = datetime.strptime(plan_allocated_at[:10], "%Y-%m-%d")
            except ValueError:
                return None
    if hasattr(plan_allocated_at, "tzinfo") and plan_allocated_at.tzinfo:
        plan_allocated_at = plan_allocated_at.replace(tzinfo=None)
    plan_start_date = plan_allocated_at.date() if hasattr(plan_allocated_at, "date") else plan_allocated_at
    end_date = plan_start_date + timedelta(days=duration_days)
    today = now.date() if hasattr(now, "date") else now
    return (end_date - today).days


@app.route("/billing")
def billing_plans():
    if not require_session():
        return redirect(url_for("login"))
    # All clients across all routers
    registered = db_list_pppoe_routers(router_id=None)
    subscription_plans = db_list_subscription_plans()
    routers = db_list_mikrotik_routers()
    router_by_id = {r["id"]: r.get("router_name", "") for r in routers}
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    payment_year = now.year
    payment_states = db_get_billing_payments_by_year(payment_year)
    payment_state_map = {}
    for (user_id, month), is_paid in payment_states.items():
        payment_state_map[f"{user_id}-{month}"] = bool(is_paid)
    payment_months = [
        {"month": 1, "label": "Jan"},
        {"month": 2, "label": "Feb"},
        {"month": 3, "label": "Mar"},
        {"month": 4, "label": "Apr"},
        {"month": 5, "label": "May"},
        {"month": 6, "label": "Jun"},
        {"month": 7, "label": "Jul"},
        {"month": 8, "label": "Aug"},
        {"month": 9, "label": "Sep"},
        {"month": 10, "label": "Oct"},
        {"month": 11, "label": "Nov"},
        {"month": 12, "label": "Dec"},
    ]
    clients = []
    for user in registered:
        user_download = float(user.get("download_speed_mbps") or 0)
        user_upload = float(user.get("upload_speed_mbps") or 0)
        matched_plan = None
        for plan in subscription_plans:
            plan_download = float(plan.get("download_speed_mbps") or 0)
            plan_upload = float(plan.get("upload_speed_mbps") or 0)
            if user_download == plan_download and user_upload == plan_upload:
                matched_plan = plan
                break
        # When the customer was allocated this plan (start of using that package); fall back to created_at for old rows
        plan_allocated_at = user.get("plan_allocated_at") or user.get("created_at")
        plan_expiration_date = _plan_expiration_from_allocation(plan_allocated_at, matched_plan)
        # Keep remaining days stable on speed edits by prioritizing stored expiration_date.
        expiration_date = user.get("expiration_date")
        days_left = (plan_expiration_date - now).days if plan_expiration_date else None
        if days_left is None:
            days_left, expiration_date = _days_left_from_expiration(expiration_date, now)
            if days_left is None:
                days_left = _days_left_from_plan(plan_allocated_at, matched_plan, now)
        else:
            _, expiration_date = _days_left_from_expiration(expiration_date, now)

        plan_expiration_date_display = _format_date_for_display(plan_expiration_date) if plan_expiration_date else "—"
        expiration_date_display = _format_date_for_display(expiration_date) if expiration_date else "—"

        plan_allocated_at_input = ""
        if plan_allocated_at:
            parsed_allocated = plan_allocated_at
            if isinstance(parsed_allocated, str):
                try:
                    parsed_allocated = datetime.strptime(parsed_allocated[:19], "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    try:
                        parsed_allocated = datetime.strptime(parsed_allocated[:10], "%Y-%m-%d")
                    except (ValueError, TypeError):
                        parsed_allocated = None
            if parsed_allocated and getattr(parsed_allocated, "tzinfo", None):
                parsed_allocated = parsed_allocated.replace(tzinfo=None)
            if parsed_allocated and hasattr(parsed_allocated, "strftime"):
                plan_allocated_at_input = parsed_allocated.strftime("%Y-%m-%d")
        amount_to_pay = None
        if matched_plan is not None:
            try:
                amount_to_pay = float(matched_plan.get("cost") or 0)
            except (TypeError, ValueError):
                amount_to_pay = None
        router_id = user.get("mikrotik_router_id")
        router_name = router_by_id.get(router_id, "") if router_id else ""
        clients.append({
            "id": user.get("id"),
            "customer_name": user.get("customer_name", ""),
            "status": user.get("status", "active"),
            "phone_number": user.get("phone_number", ""),
            "pppoe_username": user.get("pppoe_username", ""),
            "router_name": router_name,
            "plan_allocated_at": plan_allocated_at,
            "plan_allocated_at_display": _format_date_for_display(plan_allocated_at) or "—",
            "plan_allocated_at_input": plan_allocated_at_input,
            "plan_expiration_date_display": plan_expiration_date_display,
            "expiration_date": expiration_date,
            "expiration_date_display": expiration_date_display or "—",
            "days_left": days_left,
            "amount_to_pay": amount_to_pay,
            "plan_name": matched_plan.get("plan_name") if matched_plan else "—",
        })
    clients.sort(
        key=lambda x: (
            x.get("days_left") is None,
            x.get("days_left") if x.get("days_left") is not None else 10**9,
            (x.get("customer_name") or "").lower(),
        )
    )
    payment_clients = sorted(
        clients,
        key=lambda x: (
            x.get("days_left") is None,
            x.get("days_left") if x.get("days_left") is not None else 10**9,
            (x.get("customer_name") or "").lower(),
        ),
    )
    return render_template(
        "billing_plans.html",
        clients=clients,
        payment_clients=payment_clients,
        payment_year=payment_year,
        payment_months=payment_months,
        payment_state_map=payment_state_map,
    )


@app.route("/system-config")
def system_configuration():
    if not require_session():
        return redirect(url_for("login"))
    
    creds, error = get_session_router_credentials()
    if error:
        return render_template("system_configuration.html", error=error)
    
    # Fetch current router information
    current_info = {}
    try:
        pool, api = get_router_api(creds)
        identity = api.get_resource("/system/identity").get()
        if identity:
            current_info["system_identity"] = identity[0].get("name", "")
        
        # Get WiFi SSID from wireless interfaces
        try:
            wireless = api.get_resource("/interface/wireless")
            interfaces = wireless.get()
            if interfaces:
                # Get the first wireless interface's SSID
                current_info["wifi_ssid"] = interfaces[0].get("ssid", "")
        except Exception:  # noqa: BLE001
            current_info["wifi_ssid"] = ""
        
        # Get management IP from session
        current_info["management_ip"] = creds.get("host", "")
        current_info["api_username"] = creds.get("username", "")
        
        pool.disconnect()
    except Exception as exc:  # noqa: BLE001
        logger.info("Error fetching router info: %s", sanitize_error_message(str(exc)))
        current_info = {
            "system_identity": "",
            "wifi_ssid": "",
            "management_ip": creds.get("host", "") if creds else "",
            "api_username": creds.get("username", "") if creds else "",
        }
    
    return render_template("system_configuration.html", current_info=current_info)


@app.route("/system-config/update", methods=["POST"])
def update_mikrotik_config():
    if not require_session():
        return redirect(url_for("login"))
    
    creds, error = get_session_router_credentials()
    if error:
        return render_template("system_configuration.html", error=error)
    
    system_identity = request.form.get("system_identity", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    wifi_ssid = request.form.get("wifi_ssid", "").strip()
    wifi_password = request.form.get("wifi_password", "").strip()
    confirm_wifi_password = request.form.get("confirm_wifi_password", "").strip()
    new_management_ip = request.form.get("management_ip", "").strip()
    
    # Validation
    error_msg = None
    if not system_identity:
        error_msg = "System identity is required."
    elif new_password and new_password != confirm_password:
        error_msg = "Password and confirmation do not match."
    elif new_password and len(new_password) < 8:
        error_msg = "Password must be at least 8 characters long."
    elif wifi_password and wifi_password != confirm_wifi_password:
        error_msg = "WiFi password and confirmation do not match."
    elif wifi_password and len(wifi_password) < 8:
        error_msg = "WiFi password must be at least 8 characters long."
    
    if error_msg:
        current_info = {
            "system_identity": system_identity,
            "wifi_ssid": wifi_ssid,
            "management_ip": new_management_ip,
            "api_username": creds.get("username", ""),
        }
        return render_template("system_configuration.html", error=error_msg, current_info=current_info)
    
    try:
        pool, api = get_router_api(creds)
        
        # 1. Update system identity
        if system_identity:
            identity_resource = api.get_resource("/system/identity")
            identity_resource.set(name=system_identity)
            logger.info("Updated system identity to: %s", system_identity)
        
        # 2. Update API password if provided
        if new_password:
            users = api.get_resource("/user")
            existing = users.get(name=creds["username"])
            if existing:
                users.set(id=existing[0]["id"], password=new_password)
                logger.info("Updated API password for user: %s", creds["username"])
                # Update session with new password
                session["user"]["password_enc"] = encrypt_password(new_password)
        
        # 3. Update WiFi SSID and password
        if wifi_ssid or wifi_password:
            try:
                wireless = api.get_resource("/interface/wireless")
                interfaces = wireless.get()
                for interface in interfaces:
                    update_data = {}
                    if wifi_ssid:
                        update_data["ssid"] = wifi_ssid
                    wireless.set(id=interface["id"], **update_data)
                
                # Update WiFi password in security profiles
                if wifi_password:
                    security_profiles = api.get_resource("/interface/wireless/security-profiles")
                    profiles = security_profiles.get()
                    for profile in profiles:
                        security_profiles.set(id=profile["id"], **{"wpa2-pre-shared-key": wifi_password})
                    logger.info("Updated WiFi password in security profiles")
                    # Store encrypted so we can show it on Users page
                    router_id = session.get("selected_router_id")
                    if router_id:
                        db_set_setting(f"router_wifi_password_{router_id}", encrypt_password(wifi_password))
                
                if wifi_ssid:
                    logger.info("Updated WiFi SSID to: %s", wifi_ssid)
            except Exception as wifi_exc:  # noqa: BLE001
                logger.info("Warning: Could not update WiFi settings: %s", sanitize_error_message(str(wifi_exc)))
        
        # 4. Update management IP address on router if changed
        if new_management_ip and new_management_ip != creds.get("host"):
            try:
                # Find the interface that has the current management IP
                current_ip = creds.get("host", "")
                ip_addresses = api.get_resource("/ip/address")
                addresses = ip_addresses.get()
                
                # Find address entry with current management IP
                target_address = None
                for addr in addresses:
                    addr_ip = addr.get("address", "").split("/")[0]  # Remove /24 suffix
                    if addr_ip == current_ip:
                        target_address = addr
                        break
                
                if target_address:
                    # Calculate network prefix (usually /24)
                    old_address = target_address.get("address", "")
                    if "/" in old_address:
                        network_prefix = old_address.split("/")[1]
                    else:
                        network_prefix = "24"  # Default to /24
                    
                    new_address = f"{new_management_ip}/{network_prefix}"
                    ip_addresses.set(id=target_address["id"], address=new_address)
                    logger.info("Updated management IP address on router from %s to %s", current_ip, new_management_ip)
                else:
                    # If we can't find the exact IP, try to update bridge or first interface
                    # This is a fallback - try to add/update IP on bridge interface
                    try:
                        bridge_interfaces = api.get_resource("/interface").get(name="bridge")
                        if not bridge_interfaces:
                            # Try to find any bridge
                            all_interfaces = api.get_resource("/interface").get()
                            bridge_interfaces = [i for i in all_interfaces if "bridge" in i.get("name", "").lower()]
                        
                        if bridge_interfaces:
                            bridge_name = bridge_interfaces[0].get("name")
                            # Check if address already exists on this interface
                            existing_addr = ip_addresses.get(interface=bridge_name)
                            if existing_addr:
                                # Update existing address
                                old_addr = existing_addr[0].get("address", "")
                                if "/" in old_addr:
                                    network_prefix = old_addr.split("/")[1]
                                else:
                                    network_prefix = "24"
                                new_address = f"{new_management_ip}/{network_prefix}"
                                ip_addresses.set(id=existing_addr[0]["id"], address=new_address)
                                logger.info("Updated IP address on bridge interface to %s", new_management_ip)
                            else:
                                # Add new address
                                new_address = f"{new_management_ip}/24"
                                ip_addresses.add(address=new_address, interface=bridge_name)
                                logger.info("Added new IP address %s on bridge interface", new_management_ip)
                    except Exception as bridge_exc:  # noqa: BLE001
                        logger.info("Warning: Could not update IP on bridge: %s", sanitize_error_message(str(bridge_exc)))
                
                # Update session with new IP
                session["user"]["host"] = new_management_ip
                logger.info("Updated management IP in session to: %s", new_management_ip)
            except Exception as ip_exc:  # noqa: BLE001
                logger.info("Warning: Could not update management IP: %s", sanitize_error_message(str(ip_exc)))
                # Continue - IP update is optional
        
        pool.disconnect()
        
        # Fetch updated info for display
        # Reconnect to get latest WiFi SSID
        updated_wifi_ssid = wifi_ssid
        try:
            # Use new password if it was changed
            refresh_creds = creds.copy()
            if new_password:
                refresh_creds["password"] = new_password
            # Use new IP if it was changed
            if new_management_ip:
                refresh_creds["host"] = new_management_ip
            
            pool_refresh, api_refresh = get_router_api(refresh_creds)
            if not updated_wifi_ssid:
                wireless_refresh = api_refresh.get_resource("/interface/wireless")
                interfaces_refresh = wireless_refresh.get()
                if interfaces_refresh:
                    updated_wifi_ssid = interfaces_refresh[0].get("ssid", "")
            pool_refresh.disconnect()
        except Exception:  # noqa: BLE001
            pass
        
        current_info = {
            "system_identity": system_identity,
            "wifi_ssid": updated_wifi_ssid,
            "management_ip": new_management_ip if new_management_ip else creds.get("host", ""),
            "api_username": creds.get("username", ""),
        }
        
        return render_template("system_configuration.html", success="Configuration updated successfully!", current_info=current_info)
        
    except Exception as exc:  # noqa: BLE001
        error_msg = f"Configuration failed: {sanitize_error_message(str(exc))}"
        logger.info("Configuration update failed: %s", error_msg)
        current_info = {
            "system_identity": system_identity,
            "wifi_ssid": wifi_ssid,
            "management_ip": new_management_ip if new_management_ip else creds.get("host", ""),
            "api_username": creds.get("username", ""),
        }
        return render_template("system_configuration.html", error=error_msg, current_info=current_info)


@app.route("/subscription-settings")
def subscription_settings():
    if not require_session():
        return redirect(url_for("login"))
    plans = db_list_subscription_plans()
    over_limit_action = db_get_setting("over_limit_action", "disable")
    downgrade_speed_kbps = db_get_setting("downgrade_speed_kbps", "256")
    success = request.args.get("success")
    return render_template(
        "subscription_settings.html",
        plans=plans,
        over_limit_action=over_limit_action,
        downgrade_speed_kbps=downgrade_speed_kbps,
        success=success,
    )


@app.route("/subscription-settings/data-cap-policy", methods=["POST"])
def save_data_cap_policy():
    if not require_session():
        return redirect(url_for("login"))
    over_limit_action = request.form.get("over_limit_action", "disable").strip().lower()
    if over_limit_action not in ("disable", "downgrade"):
        over_limit_action = "disable"
    downgrade_speed_kbps = request.form.get("downgrade_speed_kbps", "256").strip()
    try:
        kbps = int(downgrade_speed_kbps)
        if kbps < 64:
            kbps = 64
        elif kbps > 10000:
            kbps = 10000
        downgrade_speed_kbps = str(kbps)
    except ValueError:
        downgrade_speed_kbps = "256"
    db_set_setting("over_limit_action", over_limit_action)
    db_set_setting("downgrade_speed_kbps", downgrade_speed_kbps)
    plans = db_list_subscription_plans()
    return render_template(
        "subscription_settings.html",
        plans=plans,
        over_limit_action=over_limit_action,
        downgrade_speed_kbps=downgrade_speed_kbps,
        success="Data cap policy saved. When a user exceeds their data cap: "
        + ("internet will be disabled until the next day reset." if over_limit_action == "disable" else f"speed will be reduced to {downgrade_speed_kbps} kbps until next day reset."),
    )


@app.route("/subscription-settings/create", methods=["POST"])
def create_subscription_plan():
    if not require_session():
        return redirect(url_for("login"))
    plan_name = request.form.get("plan_name", "").strip()
    duration_days = request.form.get("duration_days", "").strip()
    download_speed_mbps = request.form.get("download_speed_mbps", "").strip()
    upload_speed_mbps = request.form.get("upload_speed_mbps", "").strip()
    cost = request.form.get("cost", "").strip()
    data_cap_gb_raw = request.form.get("data_cap_gb", "").strip()
    data_cap_gb = None
    cap_reset_days = None
    if data_cap_gb_raw:
        try:
            data_cap_gb = float(data_cap_gb_raw)
            if data_cap_gb <= 0:
                data_cap_gb = None
        except ValueError:
            pass
    if data_cap_gb and not cap_reset_days:
        cap_reset_days = 1
    error = None
    if not all([plan_name, duration_days, download_speed_mbps, upload_speed_mbps, cost]):
        error = "All fields are required."
    else:
        try:
            duration_days = int(duration_days)
            download_speed_mbps = float(download_speed_mbps)
            upload_speed_mbps = float(upload_speed_mbps)
            cost = float(cost)
            if duration_days <= 0:
                error = "Duration days must be greater than 0."
            elif download_speed_mbps <= 0:
                error = "Download speed must be greater than 0."
            elif upload_speed_mbps <= 0:
                error = "Upload speed must be greater than 0."
            elif cost < 0:
                error = "Cost cannot be negative."
        except ValueError:
            error = "Invalid number format. Please enter valid numbers."
    if error:
        plans = db_list_subscription_plans()
        over_limit_action = db_get_setting("over_limit_action", "disable")
        downgrade_speed_kbps = db_get_setting("downgrade_speed_kbps", "256")
        return render_template("subscription_settings.html", plans=plans, over_limit_action=over_limit_action, downgrade_speed_kbps=downgrade_speed_kbps, error=error)
    try:
        plan_id = db_insert_subscription_plan(
            plan_name, duration_days, download_speed_mbps, upload_speed_mbps, cost,
            data_cap_gb=data_cap_gb, cap_reset_days=cap_reset_days,
        )
        plans = db_list_subscription_plans()
        over_limit_action = db_get_setting("over_limit_action", "disable")
        downgrade_speed_kbps = db_get_setting("downgrade_speed_kbps", "256")
        return render_template("subscription_settings.html", plans=plans, over_limit_action=over_limit_action, downgrade_speed_kbps=downgrade_speed_kbps, success=f"Subscription plan '{plan_name}' created successfully!")
    except Exception as exc:  # noqa: BLE001
        error = f"Failed to create subscription plan: {sanitize_error_message(str(exc))}"
        plans = db_list_subscription_plans()
        over_limit_action = db_get_setting("over_limit_action", "disable")
        downgrade_speed_kbps = db_get_setting("downgrade_speed_kbps", "256")
        return render_template("subscription_settings.html", plans=plans, over_limit_action=over_limit_action, downgrade_speed_kbps=downgrade_speed_kbps, error=error)


@app.route("/subscription-settings/<int:plan_id>/edit")
def edit_subscription_plan(plan_id):
    """Show subscription settings with the given plan loaded for editing."""
    if not require_session():
        return redirect(url_for("login"))
    plan = db_get_subscription_plan_by_id(plan_id)
    if not plan:
        return redirect(url_for("subscription_settings"))
    plans = db_list_subscription_plans()
    over_limit_action = db_get_setting("over_limit_action", "disable")
    downgrade_speed_kbps = db_get_setting("downgrade_speed_kbps", "256")
    return render_template(
        "subscription_settings.html",
        plans=plans,
        over_limit_action=over_limit_action,
        downgrade_speed_kbps=downgrade_speed_kbps,
        edit_plan=plan,
    )


@app.route("/subscription-settings/<int:plan_id>/update", methods=["POST"])
def update_subscription_plan(plan_id):
    """Update an existing subscription plan from form data."""
    if not require_session():
        return redirect(url_for("login"))
    plan = db_get_subscription_plan_by_id(plan_id)
    if not plan:
        return redirect(url_for("subscription_settings"))
    plan_name = (request.form.get("plan_name") or "").strip()
    duration_days_raw = (request.form.get("duration_days") or "").strip()
    download_speed_mbps_raw = (request.form.get("download_speed_mbps") or "").strip()
    upload_speed_mbps_raw = (request.form.get("upload_speed_mbps") or "").strip()
    cost_raw = (request.form.get("cost") or "").strip()
    data_cap_gb_raw = (request.form.get("data_cap_gb") or "").strip()
    error = None
    if not plan_name:
        error = "Plan name is required."
    if not error and not duration_days_raw:
        error = "Duration (days) is required."
    if not error and not download_speed_mbps_raw:
        error = "Download speed is required."
    if not error and not upload_speed_mbps_raw:
        error = "Upload speed is required."
    if not error and not cost_raw:
        error = "Cost is required."
    data_cap_gb = None
    cap_reset_days = None
    if data_cap_gb_raw:
        try:
            data_cap_gb = float(data_cap_gb_raw)
            if data_cap_gb <= 0:
                data_cap_gb = None
        except ValueError:
            pass
    if data_cap_gb and not cap_reset_days:
        cap_reset_days = 1
    if not error:
        try:
            duration_days = int(duration_days_raw)
            download_speed_mbps = float(download_speed_mbps_raw)
            upload_speed_mbps = float(upload_speed_mbps_raw)
            cost = float(cost_raw)
            if duration_days <= 0:
                error = "Duration days must be greater than 0."
            elif download_speed_mbps <= 0:
                error = "Download speed must be greater than 0."
            elif upload_speed_mbps <= 0:
                error = "Upload speed must be greater than 0."
            elif cost < 0:
                error = "Cost cannot be negative."
            else:
                db_update_subscription_plan(plan_id, {
                    "plan_name": plan_name,
                    "duration_days": duration_days,
                    "download_speed_mbps": download_speed_mbps,
                    "upload_speed_mbps": upload_speed_mbps,
                    "cost": cost,
                    "data_cap_gb": data_cap_gb,
                    "cap_reset_days": cap_reset_days,
                })
                return redirect(url_for("subscription_settings") + "?success=Plan+updated+successfully")
        except ValueError:
            error = "Invalid number format. Please enter valid numbers."
    plans = db_list_subscription_plans()
    over_limit_action = db_get_setting("over_limit_action", "disable")
    downgrade_speed_kbps = db_get_setting("downgrade_speed_kbps", "256")
    edit_plan = dict(plan)
    edit_plan["plan_name"] = plan_name
    edit_plan["duration_days"] = duration_days_raw
    edit_plan["download_speed_mbps"] = download_speed_mbps_raw
    edit_plan["upload_speed_mbps"] = upload_speed_mbps_raw
    edit_plan["cost"] = cost_raw
    edit_plan["data_cap_gb"] = data_cap_gb_raw or (plan.get("data_cap_gb") if plan.get("data_cap_gb") is not None else "")
    return render_template(
        "subscription_settings.html",
        plans=plans,
        over_limit_action=over_limit_action,
        downgrade_speed_kbps=downgrade_speed_kbps,
        edit_plan=edit_plan,
        error=error,
    )


@app.route("/subscription-settings/<int:plan_id>/delete", methods=["POST"])
def delete_subscription_plan(plan_id):
    if not require_session():
        return redirect(url_for("login"))
    over_limit_action = db_get_setting("over_limit_action", "disable")
    downgrade_speed_kbps = db_get_setting("downgrade_speed_kbps", "256")
    try:
        db_delete_subscription_plan(plan_id)
        plans = db_list_subscription_plans()
        return render_template("subscription_settings.html", plans=plans, over_limit_action=over_limit_action, downgrade_speed_kbps=downgrade_speed_kbps, success="Subscription plan deleted successfully!")
    except Exception as exc:  # noqa: BLE001
        error = f"Failed to delete subscription plan: {sanitize_error_message(str(exc))}"
        plans = db_list_subscription_plans()
        return render_template("subscription_settings.html", plans=plans, over_limit_action=over_limit_action, downgrade_speed_kbps=downgrade_speed_kbps, error=error)


@app.route("/reports")
def reports_analytics():
    if not require_session():
        return redirect(url_for("login"))

    router_id = session.get("selected_router_id")
    over_limit_action = db_get_setting("over_limit_action", "disable")
    search_query = (request.args.get("q") or "").strip()
    fup_filter = (request.args.get("fup") or "all").strip().lower()
    action_filter = (request.args.get("action") or "all").strip().lower()
    if fup_filter not in {"all", "hit", "within", "no_cap"}:
        fup_filter = "all"
    if action_filter not in {"all", "suspended", "limited", "normal"}:
        action_filter = "all"

    if not router_id:
        return render_template(
            "reports_analytics.html",
            fup_rows=[],
            summary={
                "total_clients": 0,
                "with_data_cap": 0,
                "hitting_fup": 0,
                "total_overage_bytes": 0,
            },
            over_limit_action=over_limit_action,
            search_query=search_query,
            fup_filter=fup_filter,
            action_filter=action_filter,
            error="No router selected. Please select a router first.",
        )

    creds, creds_error = get_session_router_credentials()
    if not creds_error:
        maybe_enforce_pppoe_access_rules(creds, router_id)

    users = db_list_pppoe_routers(router_id=router_id)
    subscription_plans = db_list_subscription_plans()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    report_date = now.date().isoformat()

    # Refresh usage_daily with current live counters so report values are up to date.
    try:
        creds, creds_error = get_session_router_credentials()
        if not creds_error:
            active_connections, _ = fetch_active_pppoe_connections(creds, enforce_single_session=False)
            _record_usage_from_connections(router_id, users, active_connections)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Reports usage refresh failed: %s", sanitize_error_message(str(exc)))

    usage_today_map = _get_usage_aggregated(router_id, "day", filter_date=report_date)
    fup_rows = []
    for user in users:
        user_download = float(user.get("download_speed_mbps") or 0)
        user_upload = float(user.get("upload_speed_mbps") or 0)
        matched_plan = None
        for plan in subscription_plans:
            plan_download = float(plan.get("download_speed_mbps") or 0)
            plan_upload = float(plan.get("upload_speed_mbps") or 0)
            if user_download == plan_download and user_upload == plan_upload:
                matched_plan = plan
                break

        cap_gb = None
        cap_bytes = None
        reset_days = None
        if matched_plan is not None and matched_plan.get("data_cap_gb") is not None:
            try:
                cap_gb = float(matched_plan.get("data_cap_gb"))
            except (TypeError, ValueError):
                cap_gb = None
            if cap_gb is not None and cap_gb > 0:
                cap_bytes = int(cap_gb * 1e9)
                reset_days = 1
            else:
                cap_gb = None

        username = str(user.get("pppoe_username") or "")
        usage_info = usage_today_map.get(username, {"bytes_sent": 0, "bytes_received": 0})
        usage_bytes = int(usage_info.get("bytes_sent", 0) or 0) + int(usage_info.get("bytes_received", 0) or 0)

        is_hitting_fup = bool(cap_bytes is not None and usage_bytes >= cap_bytes)
        overage_bytes = max(0, usage_bytes - cap_bytes) if cap_bytes is not None else 0
        usage_pct = None
        if cap_bytes and cap_bytes > 0:
            usage_pct = round((usage_bytes / cap_bytes) * 100, 1)

        action_state = "normal"
        if is_hitting_fup and bool(user.get("over_cap_suspended")):
            action_state = "suspended"
        elif is_hitting_fup:
            action_state = "limited"

        fup_rows.append({
            "id": user.get("id"),
            "customer_name": user.get("customer_name", ""),
            "pppoe_username": username,
            "status": user.get("status", "active"),
            "plan_name": matched_plan.get("plan_name") if matched_plan else "—",
            "cap_gb": cap_gb,
            "cap_bytes": cap_bytes,
            "reset_days": reset_days,
            "usage_bytes": usage_bytes,
            "usage_pct": usage_pct,
            "is_hitting_fup": is_hitting_fup,
            "overage_bytes": overage_bytes,
            "over_cap_suspended": bool(user.get("over_cap_suspended")),
            "action_state": action_state,
        })

    filtered_rows = []
    query_lc = search_query.lower()
    for row in fup_rows:
        if query_lc:
            haystack = f"{row.get('customer_name', '')} {row.get('pppoe_username', '')} {row.get('plan_name', '')}".lower()
            if query_lc not in haystack:
                continue
        if fup_filter == "hit" and not row.get("is_hitting_fup"):
            continue
        if fup_filter == "within" and (row.get("cap_bytes") is None or row.get("is_hitting_fup")):
            continue
        if fup_filter == "no_cap" and row.get("cap_bytes") is not None:
            continue
        if action_filter != "all" and row.get("action_state") != action_filter:
            continue
        filtered_rows.append(row)

    fup_rows = filtered_rows
    fup_rows.sort(
        key=lambda row: (
            -(row["usage_bytes"] or 0),
            (row["customer_name"] or "").lower(),
        )
    )
    summary = {
        "total_clients": len(fup_rows),
        "with_data_cap": sum(1 for row in fup_rows if row.get("cap_bytes") is not None),
        "hitting_fup": sum(1 for row in fup_rows if row.get("is_hitting_fup")),
        "total_overage_bytes": sum(int(row.get("overage_bytes") or 0) for row in fup_rows if row.get("is_hitting_fup")),
    }

    return render_template(
        "reports_analytics.html",
        fup_rows=fup_rows,
        summary=summary,
        over_limit_action=over_limit_action,
        report_date=report_date,
        search_query=search_query,
        fup_filter=fup_filter,
        action_filter=action_filter,
        error=None,
    )


@app.route("/settings")
def settings():
    if not require_session():
        return redirect(url_for("login"))
    # Load saved interface settings so the form is pre-filled
    saved_wan = db_get_setting("wan_interface") or ""
    saved_pppoe = db_get_setting("pppoe_interface") or "pppoe-in"
    allow_wifi_access = (db_get_setting("allow_wifi_access", "0") or "0").strip() in {"1", "true", "yes", "on"}
    always_enforce_pppoe = (db_get_setting("always_enforce_pppoe", "1") or "1").strip() in {"1", "true", "yes", "on"}
    dual_wan_enabled = (db_get_setting("dual_wan_enabled", "0") or "0").strip() in {"1", "true", "yes", "on"}
    dual_wan_wan1 = (db_get_setting("dual_wan_wan1", "") or "").strip()
    dual_wan_wan2 = (db_get_setting("dual_wan_wan2", "") or "").strip()
    return render_template(
        "settings.html",
        saved_wan_interface=saved_wan,
        saved_pppoe_interface=saved_pppoe,
        allow_wifi_access=allow_wifi_access,
        always_enforce_pppoe=always_enforce_pppoe,
        dual_wan_enabled=dual_wan_enabled,
        dual_wan_wan1=dual_wan_wan1,
        dual_wan_wan2=dual_wan_wan2,
    )


@app.route("/mikrotik-webfig")
def mikrotik_webfig():
    webfig_url = os.getenv("MIKROTIK_WEBFIG_URL", "http://192.168.88.1/webfig/")
    return redirect(webfig_url)


@app.route("/register-router")
def register_router_page():
    return render_template("register_router.html")


@app.route("/routers")
def routers_page():
    return render_template("routers.html")


@app.route("/routers/<int:router_id>/print")
def print_instructions(router_id):
    router = db_get_pppoe_router_by_id(router_id)
    if not router:
        return redirect(url_for("routers_page"))
    try:
        password = decrypt_password(router["pppoe_password_encrypted"])
    except Exception:
        password = "********"
    return render_template(
        "print_instructions.html",
        router=router,
        password=password,
    )


@app.route("/mikrotik", methods=["GET"])
def mikrotik_page():
    # MikroTik registration is only available when user is not in session (not logged in)
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("mikrotik_register.html")


@app.route("/api/mikrotik/test-connection", methods=["POST"])
def test_mikrotik_connection():
    """Test connectivity to a MikroTik router without authentication.
    Useful for diagnosing connection issues before registration."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        host = data.get("host", "").strip()
        port = int(data.get("port", 8728))
        use_ssl = data.get("use_ssl", False)
        
        if not host:
            return jsonify({"error": "Host/IP address is required"}), 400
        
        if port not in [8728, 8729]:
            return jsonify({"error": "Port must be 8728 or 8729"}), 400
        
        # Get connection recommendations
        recommendation = get_connection_method_recommendation(host, port)
        
        # Test connection
        timeout_seconds = 5
        socket.setdefaulttimeout(timeout_seconds)
        ok, failure = preflight_connection(host, port, timeout_seconds)
        
        result = {
            "success": ok,
            "host": host,
            "port": port,
            "use_ssl": use_ssl,
            "is_private_ip": recommendation["is_private_ip"],
            "is_localhost": recommendation["is_localhost"],
            "recommendation": recommendation,
        }
        
        if ok:
            result["message"] = f"✅ Successfully connected to {host}:{port}"
            if recommendation["warnings"]:
                result["warnings"] = recommendation["warnings"]
        else:
            result["error"] = failure or "Connection failed"
            result["warnings"] = recommendation["warnings"]
            result["methods"] = recommendation["methods"]
            result["recommended_method"] = recommendation["recommended_method"]
        
        return jsonify(result), 200 if ok else 502
        
    except ValueError as e:
        return jsonify({"error": f"Invalid port number: {str(e)}"}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Test failed: {sanitize_error_message(str(exc))}"}), 500


@app.route("/api/server-info", methods=["GET"])
def get_server_info():
    """Get server information useful for remote access setup."""
    try:
        server_public_ip = get_server_public_ip()
        is_local = is_running_on_localhost()
        
        return jsonify({
            "public_ip": server_public_ip,
            "is_localhost": is_local,
            "message": "Use this IP address when configuring MikroTik firewall to allow API access from this server."
        }), 200
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Failed to get server info: {sanitize_error_message(str(exc))}"}), 500


@app.route("/mikrotik/register", methods=["POST"])
def register_mikrotik():
    details = {
        "router_name": request.form.get("router_name", "").strip(),
        "router_role": request.form.get("router_role", "").strip(),
        "management_ip": request.form.get("management_ip", "").strip(),
        "api_port": int(request.form.get("api_port", "8728")),
        "use_ssl": request.form.get("use_ssl", "false") == "true",
        "api_username": request.form.get("api_username", "").strip(),
        "api_password": request.form.get("api_password", ""),
    }

    allowed_roles = {"core", "access", "edge"}
    error = None
    if not all(
        [
            details["router_name"],
            details["router_role"],
            details["management_ip"],
            details["api_username"],
            details["api_password"],
        ]
    ):
        error = "All fields are required."
    elif details["router_role"] not in allowed_roles:
        error = "Router role must be core, access, or edge."
    elif details["api_port"] not in {8728, 8729}:
        error = "API port must be 8728 or 8729."

    if error:
        logger.info("Router registration validation failed: %s", error)
        return render_template("mikrotik_register.html", error=error, form=details)

    success, data, failure_reason = verify_mikrotik(details)
    status = "ACTIVE" if success else "ERROR"
    identity = data["identity"] if data else None
    resource = data["resource"] if data else None

    router_id = insert_router_record(details, status, failure_reason, identity, resource)

    if success:
        # Set this router as selected in session if user is logged in
        if session.get("user"):
            session["selected_router_id"] = router_id
        
        # After successful registration, show credentials setup form
        return render_template(
            "mikrotik_register.html",
            show_credentials_setup=True,
            router_details={
                "name": details["router_name"],
                "role": details["router_role"],
                "ip": details["management_ip"],
                "port": details["api_port"],
                "ssl": details["use_ssl"],
                "username": details["api_username"],
                "current_password": details["api_password"],  # Keep for authentication
            },
            identity=identity,
            resource=resource,
        )

    logger.info("Router verification failed: %s", failure_reason)
    return render_template(
        "mikrotik_register.html",
        error=f"Verification failed: {failure_reason}",
        form=details,
    )


@app.route("/mikrotik/change-password", methods=["POST"])
def change_mikrotik_password():
    """Change API password after router registration."""
    router_details = {
        "name": request.form.get("router_name", "").strip(),
        "role": request.form.get("router_role", "").strip(),
        "ip": request.form.get("management_ip", "").strip(),
        "port": int(request.form.get("api_port", "8728")),
        "ssl": request.form.get("use_ssl", "false") == "true",
        "username": request.form.get("current_username", "").strip(),
    }
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    error = None
    if not all([router_details["name"], router_details["ip"], router_details["username"], current_password, new_password]):
        error = "All fields are required."
    elif new_password != confirm_password:
        error = "New password and confirmation do not match."
    elif len(new_password) < 8:
        error = "New password must be at least 8 characters long."

    if error:
        router_details["current_password"] = current_password
        return render_template(
            "mikrotik_register.html",
            show_password_change=True,
            error=error,
            router_details=router_details,
        )

    # Connect to MikroTik and change password
    timeout_seconds = 5
    socket.setdefaulttimeout(timeout_seconds)

    ok, failure = preflight_connection(router_details["ip"], router_details["port"], timeout_seconds)
    if not ok:
        error = f"Unable to reach router: {failure}"
        router_details["current_password"] = current_password
        return render_template(
            "mikrotik_register.html",
            show_password_change=True,
            error=error,
            router_details=router_details,
        )

    try:
        pool = routeros_api.RouterOsApiPool(
            router_details["ip"],
            username=router_details["username"],
            password=current_password,
            port=router_details["port"],
            use_ssl=router_details["ssl"],
            plaintext_login=True,
        )
        api = pool.get_api()
        
        # Change password for the API user
        users = api.get_resource("/user")
        existing = users.get(name=router_details["username"])
        if not existing:
            pool.disconnect()
            error = "API user not found on router."
            router_details["current_password"] = current_password
            return render_template(
                "mikrotik_register.html",
                show_password_change=True,
                error=error,
                router_details=router_details,
            )
        
        # Update password
        users.set(id=existing[0]["id"], password=new_password)
        pool.disconnect()
        
        # Update database with new password
        cipher = get_cipher()
        encrypted_new_password = cipher.encrypt(new_password.encode()).decode()
        
        ensure_db_and_tables()
        sql = """
            UPDATE routers 
            SET api_password_encrypted = %s, updated_at = %s
            WHERE management_ip = %s AND api_username = %s
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (encrypted_new_password, now, router_details["ip"], router_details["username"]))
                conn.commit()
        
        # Show success and redirect to dashboard
        return render_template(
            "mikrotik_register.html",
            password_change_success=True,
            router_details=router_details,
        )
    except Exception as exc:  # noqa: BLE001
        error = sanitize_error_message(str(exc))
        logger.info("Password change failed: %s", error)
        router_details["current_password"] = current_password
        return render_template(
            "mikrotik_register.html",
            show_password_change=True,
            error=f"Password change failed: {error}",
            router_details=router_details,
        )


@app.route("/mikrotik/change-credentials", methods=["POST"])
def change_mikrotik_credentials():
    details = {
        "router_name": request.form.get("router_name", "").strip(),
        "router_role": request.form.get("router_role", "").strip(),
        "management_ip": request.form.get("management_ip", "").strip(),
        "api_port": int(request.form.get("api_port", "8728")),
        "use_ssl": request.form.get("use_ssl", "false") == "true",
        "api_username": request.form.get("current_username", "").strip(),
        "api_password": request.form.get("current_password", ""),
    }
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    wifi_password = request.form.get("wifi_password", "")
    confirm_wifi_password = request.form.get("confirm_wifi_password", "")

    allowed_roles = {"core", "access", "edge"}
    error = None
    if not all(
        [
            details["router_name"],
            details["router_role"],
            details["management_ip"],
            details["api_username"],
            details["api_password"],
            new_password,
            wifi_password,
        ]
    ):
        error = "All fields are required."
    elif new_password != confirm_password:
        error = "Login password and confirmation do not match."
    elif wifi_password != confirm_wifi_password:
        error = "WiFi password and confirmation do not match."
    elif len(new_password) < 8:
        error = "Login password must be at least 8 characters long."
    elif len(wifi_password) < 8:
        error = "WiFi password must be at least 8 characters long."
    elif details["router_role"] not in allowed_roles:
        error = "Router role must be core, access, or edge."
    elif details["api_port"] not in {8728, 8729}:
        error = "API port must be 8728 or 8729."

    if error:
        logger.info("Credential change validation failed: %s", error)
        router_details = {
            "name": details["router_name"],
            "role": details["router_role"],
            "ip": details["management_ip"],
            "port": details["api_port"],
            "ssl": details["use_ssl"],
            "username": details["api_username"],
            "current_password": details["api_password"],
        }
        return render_template(
            "mikrotik_register.html",
            show_credentials_setup=True,
            error=error,
            router_details=router_details,
        )

    timeout_seconds = 5
    socket.setdefaulttimeout(timeout_seconds)

    ok, failure = preflight_connection(details["management_ip"], details["api_port"], timeout_seconds)
    if not ok:
        failure_reason = f"Unable to reach router on {details['management_ip']}:{details['api_port']}. {failure}"
        logger.info("Credential change failed: %s", failure_reason)
        router_details = {
            "name": details["router_name"],
            "role": details["router_role"],
            "ip": details["management_ip"],
            "port": details["api_port"],
            "ssl": details["use_ssl"],
            "username": details["api_username"],
            "current_password": details["api_password"],
        }
        return render_template(
            "mikrotik_register.html",
            show_credentials_setup=True,
            error=f"Connection failed: {failure_reason}",
            router_details=router_details,
        )

    try:
        pool = routeros_api.RouterOsApiPool(
            details["management_ip"],
            username=details["api_username"],
            password=details["api_password"],
            port=details["api_port"],
            use_ssl=details["use_ssl"],
            plaintext_login=True,
        )
        api = pool.get_api()
        
        # Get identity and resource before changing password
        identity = api.get_resource("/system/identity").get()
        resource = api.get_resource("/system/resource").get()
        
        # 1. Change API password only (username cannot be changed)
        users = api.get_resource("/user")
        existing = users.get(name=details["api_username"])
        if not existing:
            pool.disconnect()
            raise RuntimeError("Admin user not found on router.")
        users.set(id=existing[0]["id"], password=new_password)
        logger.info("Changed API password for user: %s", details["api_username"])
        
        # Disconnect old connection
        pool.disconnect()
        
        # 2. Reconnect with new password to update WiFi
        try:
            pool_new = routeros_api.RouterOsApiPool(
                details["management_ip"],
                username=details["api_username"],
                password=new_password,
                port=details["api_port"],
                use_ssl=details["use_ssl"],
                plaintext_login=True,
            )
            api_new = pool_new.get_api()
            
            # Change WiFi password (update security profiles)
            try:
                security_profiles = api_new.get_resource("/interface/wireless/security-profiles")
                profiles = security_profiles.get()
                for profile in profiles:
                    # Update all security profiles with the new WiFi password
                    security_profiles.set(id=profile["id"], **{"wpa2-pre-shared-key": wifi_password})
                logger.info("Updated WiFi password in security profiles")
            except Exception as wifi_exc:  # noqa: BLE001
                logger.info("Warning: Could not update WiFi password: %s", sanitize_error_message(str(wifi_exc)))
                # Continue even if WiFi update fails
            
            pool_new.disconnect()
        except Exception as reconnect_exc:  # noqa: BLE001
            logger.info("Warning: Could not reconnect with new password for WiFi update: %s", sanitize_error_message(str(reconnect_exc)))
            # Continue even if reconnect fails - password was already changed
    except Exception as exc:  # noqa: BLE001 - want to capture API failures
        failure_reason = sanitize_error_message(str(exc))
        logger.info("Credential change failed: %s", failure_reason)
        router_details = {
            "name": details["router_name"],
            "role": details["router_role"],
            "ip": details["management_ip"],
            "port": details["api_port"],
            "ssl": details["use_ssl"],
            "username": details["api_username"],
            "current_password": details["api_password"],
        }
        return render_template(
            "mikrotik_register.html",
            show_credentials_setup=True,
            error=f"Configuration failed: {failure_reason}",
            router_details=router_details,
        )

    # Update database with new password (username stays the same)
    updated_details = details.copy()
    updated_details["api_password"] = new_password
    router_id = insert_router_record(updated_details, "ACTIVE", None, identity, resource)
    update_router_credentials_by_id(router_id, details["api_username"], new_password)

    # Show success message
    return render_template(
        "mikrotik_register.html",
        credentials_setup_success=True,
        router_details={
            "name": details["router_name"],
            "role": details["router_role"],
            "ip": details["management_ip"],
            "port": details["api_port"],
            "ssl": details["use_ssl"],
            "username": details["api_username"],
        },
    )


def mikrotik_ensure_pppoe_pool(api, pool_name="pppoe-pool", pool_range="192.168.1.2-192.168.1.254"):
    """Ensure IP pool exists for PPPoE clients."""
    pools = api.get_resource("/ip/pool")
    existing = pools.get(name=pool_name)
    if not existing:
        pools.add(name=pool_name, ranges=pool_range)
        logger.info("Created IP pool: %s (%s)", pool_name, pool_range)
    return pool_name


def mikrotik_ensure_pppoe_profile(
    api, profile_name="default", local_address="192.168.1.1", pool_name="pppoe-pool", dns="8.8.8.8,8.8.4.4"
):
    """Ensure PPP profile is configured with IP addresses, DNS, and single session limit."""
    profiles = api.get_resource("/ppp/profile")
    existing = profiles.get(name=profile_name)
    if existing:
        profile_id = existing[0].get("id")
        profiles.set(
            id=profile_id,
            local_address=local_address,
            remote_address=pool_name,
            dns_server=dns,
            only_one="yes",  # Limit to one session per username
        )
        logger.info("Updated PPP profile: %s (local=%s, remote=%s, dns=%s, only-one=yes)", profile_name, local_address, pool_name, dns)
    else:
        profiles.add(
            name=profile_name,
            local_address=local_address,
            remote_address=pool_name,
            dns_server=dns,
            only_one="yes",  # Limit to one session per username
        )
        logger.info("Created PPP profile: %s (local=%s, remote=%s, dns=%s, only-one=yes)", profile_name, local_address, pool_name, dns)


def mikrotik_ensure_pppoe_server(api, interface="bridgeLocal", service_name=""):
    """Ensure PPPoE server is enabled on the specified interface."""
    # First, verify the interface exists
    original_interface = interface
    try:
        interfaces = api.get_resource("/interface").get()
        interface_names = {entry.get("name") for entry in interfaces if entry.get("name")}
        if interface not in interface_names:
            # Try common alternatives
            alternatives = ["bridge", "ether1", "ether2", "ether3", "ether4", "ether5"]
            for alt in alternatives:
                if alt in interface_names:
                    interface = alt
                    logger.info("Interface '%s' not found, using '%s' instead", original_interface, alt)
                    break
            else:
                # If no valid interface found, check if server already exists
                servers = api.get_resource("/interface/pppoe-server/server")
                existing = servers.get()
                if existing:
                    logger.info("PPPoE server already exists, skipping creation")
                    return True
                raise ValueError(f"Interface '{interface}' not found. Available: {sorted(interface_names)}")
    except Exception as exc:  # noqa: BLE001
        logger.info("Could not verify interfaces: %s", sanitize_error_message(str(exc)))

    servers = api.get_resource("/interface/pppoe-server/server")
    existing = servers.get()
    if not existing:
        payload = {
            "interface": interface,
            "default-profile": "default",
            "disabled": "no",
        }
        if service_name:
            payload["service-name"] = service_name
        servers.add(**payload)
        logger.info("Created PPPoE server on interface: %s", interface)
    else:
        for server in existing:
            if server.get("interface") == interface:
                if server.get("disabled") == "true":
                    servers.set(id=server["id"], disabled="no")
                    logger.info("Enabled existing PPPoE server on interface: %s", interface)
                return True
        # Server exists but on different interface - that's okay, don't create duplicate
        logger.info("PPPoE server already exists on different interface, skipping")
    return True


def mikrotik_ensure_nat_masquerade(api, out_interface=None):
    """Ensure NAT masquerade rule exists for internet access."""
    nat = api.get_resource("/ip/firewall/nat")
    
    # Check for our specific PPPoE NAT rule
    our_rule = nat.get(chain="srcnat", comment="ISP MTAANI: NAT for PPPoE clients")
    
    if not our_rule:
        # Create masquerade rule that matches traffic from PPPoE interfaces
        # Use in-interface matching pattern for PPPoE interfaces (they start with "pppoe-")
        payload = {
            "chain": "srcnat",
            "action": "masquerade",
            "comment": "ISP MTAANI: NAT for PPPoE clients",
            "src-address": "192.168.1.0/24",  # Match PPPoE client IP range
        }
        # Only add out-interface if specified (otherwise masquerade all)
        if out_interface:
            payload["out-interface"] = out_interface
        nat.add(**payload)
        logger.info("Created NAT masquerade rule for PPPoE clients (src: 192.168.1.0/24)%s", f" (out: {out_interface})" if out_interface else "")
    else:
        # Rule exists - ensure it's enabled and has correct source
        rule_id = our_rule[0].get("id")
        if our_rule[0].get("disabled") == "true":
            nat.set(id=rule_id, disabled="no")
            logger.info("Enabled existing NAT masquerade rule for PPPoE clients")
        # Update source address to match PPPoE pool if not set
        current_src = our_rule[0].get("src-address")
        if not current_src or current_src != "192.168.1.0/24":
            nat.set(id=rule_id, **{"src-address": "192.168.1.0/24"})
            logger.info("Updated NAT masquerade rule source to 192.168.1.0/24")
        # Update out-interface if specified and different
        if out_interface:
            current_out = our_rule[0].get("out-interface")
            if current_out != out_interface:
                nat.set(id=rule_id, **{"out-interface": out_interface})
                logger.info("Updated NAT masquerade rule for PPPoE clients (out: %s)", out_interface)
        else:
            logger.info("NAT masquerade rule for PPPoE clients already exists")
    
    # Remove general masquerade rule if it exists - only registered PPPoE clients (192.168.1.0/24) should get internet
    general_rule = nat.get(chain="srcnat", comment="ISP MTAANI: General NAT masquerade")
    if general_rule:
        for rule in general_rule:
            rid = rule.get("id")
            if rid:
                nat.remove(id=rid)
                logger.info("Removed general NAT masquerade rule so only PPPoE clients get internet")
                break


def _get_router_pppoe_and_wifi_networks(api):
    """Return (pppoe_pool_network, wifi_network) from router. wifi_network is auto-detected from bridge/LAN."""
    pppoe_pool_network = "192.168.1.0/24"
    wifi_network = "192.168.88.0/24"
    try:
        pools = api.get_resource("/ip/pool")
        pppoe_pools = pools.get(name="pppoe-pool")
        if pppoe_pools and pppoe_pools[0].get("ranges"):
            first_ip = (pppoe_pools[0]["ranges"] or "").split("-")[0].strip()
            if first_ip:
                pppoe_pool_network = first_ip.rsplit(".", 1)[0] + ".0/24"
    except Exception:  # noqa: BLE001
        pass
    try:
        addresses = api.get_resource("/ip/address")
        all_addresses = addresses.get()
        for addr in all_addresses or []:
            addr_str = addr.get("address", "")
            if not addr_str or "/" not in addr_str:
                continue
            ip_address = addr_str.split("/")[0]
            cidr = addr_str.split("/")[1]
            parts = ip_address.split(".")
            if len(parts) != 4:
                continue
            network_base = ".".join(parts[:3])
            network_cidr = f"{network_base}.0/{cidr}" if cidr.isdigit() else f"{network_base}.0/24"
            if network_cidr != pppoe_pool_network and parts[0] in ("192", "10", "172"):
                wifi_network = network_cidr
                break
    except Exception:  # noqa: BLE001
        pass
    return pppoe_pool_network, wifi_network


def mikrotik_detect_wan_interface(api):
    """Best-effort WAN interface detection for firewall out-interface rules."""
    # 1) Existing masquerade with out-interface is the strongest signal.
    try:
        nat = api.get_resource("/ip/firewall/nat").get(chain="srcnat")
        for rule in nat or []:
            action = (rule.get("action") or "").lower()
            out_iface = (rule.get("out-interface") or "").strip()
            if action == "masquerade" and out_iface:
                return out_iface
    except Exception:  # noqa: BLE001
        pass

    # 2) Interface list "WAN" members.
    try:
        members = api.get_resource("/interface/list/member").get()
        for m in members or []:
            list_name = (m.get("list") or "").strip().upper()
            iface = (m.get("interface") or "").strip()
            if list_name == "WAN" and iface:
                return iface
    except Exception:  # noqa: BLE001
        pass

    # 3) Default route immediate-gw sometimes includes iface as ip%iface.
    try:
        routes = api.get_resource("/ip/route").get(dst_address="0.0.0.0/0")
        for r in routes or []:
            if (r.get("disabled") or "").lower() == "true":
                continue
            immediate_gw = (r.get("immediate-gw") or "").strip()
            if "%" in immediate_gw:
                iface = immediate_gw.split("%", 1)[1].strip()
                if iface:
                    return iface
    except Exception:  # noqa: BLE001
        pass
    return None


def _normalize_wan_interface_targets(wan_interface=None, wan_interfaces=None):
    targets = []
    if wan_interfaces:
        for iface in wan_interfaces:
            n = (iface or "").strip()
            if n and n not in targets:
                targets.append(n)
    elif wan_interface:
        raw = (wan_interface or "").strip()
        if "," in raw:
            for part in raw.split(","):
                n = (part or "").strip()
                if n and n not in targets:
                    targets.append(n)
        elif raw:
            targets.append(raw)
    primary = targets[0] if targets else None
    return primary, targets


def _get_enforcement_wan_targets(api, requested_wan_interface=None):
    """
    Resolve WAN targets for PPPoE enforcement.
    If dual_wan_enabled=true and dual WAN values are set, return both interfaces.
    Otherwise return requested/saved single WAN or auto-detected WAN.
    """
    dual_enabled = (db_get_setting("dual_wan_enabled", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}
    if dual_enabled:
        w1 = (db_get_setting("dual_wan_wan1", "") or "").strip()
        w2 = (db_get_setting("dual_wan_wan2", "") or "").strip()
        primary, targets = _normalize_wan_interface_targets(wan_interfaces=[w1, w2])
        if len(targets) >= 2:
            return primary, targets, f"Dual WAN enforcement active on {', '.join(targets)}."
    primary, targets = _normalize_wan_interface_targets(wan_interface=requested_wan_interface)
    if targets:
        return primary, targets, None
    detected = mikrotik_detect_wan_interface(api)
    if detected:
        return detected, [detected], f"WAN auto-detected as {detected}."
    return None, [], None


def mikrotik_ensure_interface_list_members(api, list_name, interfaces):
    """Ensure interface-list exists and contains all interfaces provided."""
    if not list_name or not interfaces:
        return
    list_res = api.get_resource("/interface/list")
    member_res = api.get_resource("/interface/list/member")
    existing_lists = list_res.get(name=list_name)
    if not existing_lists:
        list_res.add(name=list_name)
    members = member_res.get(list=list_name)
    existing_ifaces = {_ros_str(m.get("interface")) for m in (members or [])}
    for iface in interfaces:
        n = (iface or "").strip()
        if n and n not in existing_ifaces:
            member_res.add(list=list_name, interface=n)


def mikrotik_fix_firewall_rule(api, pppoe_pool="192.168.1.0/24", wan_interface=None, wan_interfaces=None, allow_wifi=False, wifi_network=None):
    """
    Fix firewall rule to allow PPPoE traffic instead of blocking it.
    IMPORTANT: wan_interface must be set. Without it, a drop rule would match return traffic
    (source = internet) and break connectivity. We only add the drop rule when out-interface=WAN
    so we only drop outbound LAN traffic that is not from the allowed pool.
    """
    filters = api.get_resource("/ip/firewall/filter")
    
    # Remove old rules (fixes broken state if WAN was previously unset)
    existing_block = filters.get(comment="ISP MTAANI: block non-PPPoE forward")
    if existing_block:
        filters.remove(id=existing_block[0]["id"])
        logger.info("Removed old firewall blocking rule")
    
    existing_wifi_block = filters.get(comment="ISP MTAANI: block non-PPPoE/WiFi forward")
    if existing_wifi_block:
        filters.remove(id=existing_wifi_block[0]["id"])
        logger.info("Removed old WiFi firewall blocking rule")
    
    existing_wifi_allow = filters.get(comment="ISP MTAANI: allow WiFi network")
    if existing_wifi_allow:
        filters.remove(id=existing_wifi_allow[0]["id"])
        logger.info("Removed old WiFi allow rule")
    
    primary_wan, wan_targets = _normalize_wan_interface_targets(wan_interface=wan_interface, wan_interfaces=wan_interfaces)

    # Only add drop rules when WAN interface is set. Otherwise we would drop return traffic
    # (packets from internet, src not in pool) and break internet for everyone.
    if not wan_targets:
        logger.warning("WAN interface not set: skipping firewall drop rule to avoid breaking internet (return traffic would be dropped)")
        return
    wan_match = {}
    if len(wan_targets) > 1:
        try:
            mikrotik_ensure_interface_list_members(api, "WAN", wan_targets)
            wan_match["out-interface-list"] = "WAN"
        except Exception as exc:  # noqa: BLE001
            logger.info("Could not ensure WAN interface list, falling back to primary WAN: %s", sanitize_error_message(str(exc)))
            wan_match["out-interface"] = primary_wan
    else:
        wan_match["out-interface"] = primary_wan
    
    if allow_wifi and wifi_network:
        # Allow both PPPoE pool AND WiFi network. Add WiFi allow first so it is evaluated before the drop rule.
        wifi_allow_rule = {
            "chain": "forward",
            "action": "accept",
            "comment": "ISP MTAANI: allow WiFi network",
            "src-address": wifi_network,
            **wan_match,
        }
        filters.add(**wifi_allow_rule)

        rule_payload = {
            "chain": "forward",
            "action": "drop",
            "comment": "ISP MTAANI: block non-PPPoE/WiFi forward",
            "src-address": f"!{pppoe_pool}",  # Block everything except PPPoE pool
            **wan_match,  # Only outbound to WAN; do not match return traffic
        }
        filters.add(**rule_payload)
        logger.info("Created firewall rules allowing PPPoE pool %s and WiFi network %s (WAN targets=%s)", pppoe_pool, wifi_network, ",".join(wan_targets))
        return
    else:
        # Block outbound-to-WAN traffic NOT from PPPoE pool (out-interface=WAN prevents dropping return traffic)
        rule_payload = {
            "chain": "forward",
            "action": "drop",
            "comment": "ISP MTAANI: block non-PPPoE forward",
            "src-address": f"!{pppoe_pool}",
            **wan_match,
        }
        filters.add(**rule_payload)
        logger.info("Created firewall rule allowing PPPoE pool %s (WAN targets=%s)", pppoe_pool, ",".join(wan_targets))


def mikrotik_auto_configure_pppoe(api, interface="bridgeLocal", local_address="192.168.1.1", pool_range="192.168.1.2-192.168.1.254", dns="8.8.8.8,8.8.4.4", wan_interface=None):
    """Automatically configure MikroTik for PPPoE: pool, profile, server, NAT, and firewall."""
    try:
        pool_name = mikrotik_ensure_pppoe_pool(api, "pppoe-pool", pool_range)
        mikrotik_ensure_pppoe_profile(api, "default", local_address, pool_name, dns)
        # PPPoE server creation is optional - it might already exist
        try:
            mikrotik_ensure_pppoe_server(api, interface)
        except Exception as server_exc:  # noqa: BLE001
            logger.info("PPPoE server setup warning (may already exist): %s", sanitize_error_message(str(server_exc)))
            # Continue anyway - server might already be configured
        
        # Ensure NAT masquerade is configured for internet access
        try:
            mikrotik_ensure_nat_masquerade(api, wan_interface)
        except Exception as nat_exc:  # noqa: BLE001
            logger.info("NAT setup warning: %s", sanitize_error_message(str(nat_exc)))
            # Continue anyway - NAT might already be configured
        
        # Fix firewall rule to allow PPPoE traffic
        try:
            # Extract network from pool range (e.g., "192.168.1.2-192.168.1.254" -> "192.168.1.0/24")
            pool_network = pool_range.split("-")[0].rsplit(".", 1)[0] + ".0/24"
            mikrotik_fix_firewall_rule(api, pool_network, wan_interface)
        except Exception as fw_exc:  # noqa: BLE001
            logger.info("Firewall rule fix warning: %s", sanitize_error_message(str(fw_exc)))
            # Continue anyway
        
        return True, None
    except Exception as exc:  # noqa: BLE001
        error_msg = sanitize_error_message(str(exc))
        logger.info("Auto-configuration failed: %s", error_msg)
        return False, error_msg


def mikrotik_add_pppoe_secret(api, customer_name, username, password):
    """Add a PPPoE secret to MikroTik router with error handling and single session enforcement."""
    try:
        secrets = api.get_resource("/ppp/secret")
        # Check if secret already exists
        existing = secrets.get(name=username)
        if existing:
            logger.warning("PPPoE secret already exists for username: %s", username)
            secret_id = existing[0].get(".id") if existing else None
            # Ensure profile is set to default (which has only-one=yes)
            if secret_id:
                try:
                    secrets.set(id=secret_id, profile="default")
                    logger.info("Updated existing PPPoE secret to use default profile (single session limit)")
                except Exception:  # noqa: BLE001
                    pass
            return secret_id
        
        result = secrets.add(
            name=username,
            password=password,
            service="pppoe",
            comment=customer_name,
            profile="default",  # Use default profile which has only-one=yes
        )
        secret_id = None
        if isinstance(result, dict):
            secret_id = result.get("ret")
        if not secret_id:
            found = secrets.get(name=username)
            if found:
                secret_id = found[0].get("id")
        
        return secret_id
    except Exception as exc:  # noqa: BLE001
        error_msg = sanitize_error_message(str(exc))
        if "already exists" in error_msg.lower() or "duplicate" in error_msg.lower():
            # Try to get existing secret ID
            try:
                found = api.get_resource("/ppp/secret").get(name=username)
                if found:
                    return found[0].get(".id") if found else None
            except Exception:  # noqa: BLE001
                pass
        raise RuntimeError(f"Failed to create PPPoE secret: {error_msg}") from exc


def mikrotik_update_pppoe_secret(api, secret_id, customer_name, username, password):
    """Update PPPoE secret and ensure single session limit."""
    secrets = api.get_resource("/ppp/secret")
    payload = {
        "id": secret_id,
        "name": username,
        "password": password,
        "comment": customer_name,
        "profile": "default",  # Ensure default profile (single session limit)
    }
    secrets.set(**payload)
    # Enforce single session after update
    mikrotik_enforce_single_session(api, username)


def mikrotik_set_pppoe_disabled(api, secret_id, disabled):
    secrets = api.get_resource("/ppp/secret")
    secrets.set(id=secret_id, disabled="yes" if disabled else "no")


def mikrotik_disconnect_pppoe_session(api, username):
    """Disconnect an active PPPoE session by username."""
    try:
        active = api.get_resource("/ppp/active")
        connections = active.get(name=username)
        if connections:
            for conn in connections:
                active.remove(id=conn.get("id"))
            logger.info("Disconnected PPPoE session for user: %s", username)
            return True
        return False
    except Exception as exc:  # noqa: BLE001
        logger.info("Error disconnecting PPPoE session: %s", sanitize_error_message(str(exc)))
        return False


def mikrotik_block_duplicate_session_traffic(api, duplicate_ip):
    """Immediately block internet traffic from a duplicate session IP using firewall rules."""
    try:
        # Ensure IP is a string
        if not isinstance(duplicate_ip, str):
            duplicate_ip = str(duplicate_ip)
        
        filters = api.get_resource("/ip/firewall/filter")
        
        # Check if blocking rule already exists by searching for rules with matching source address and comment
        all_rules = filters.get()
        existing_rule = None
        for rule in all_rules:
            rule_comment = rule.get("comment", "")
            rule_src = rule.get("src-address", "")
            if duplicate_ip in rule_src and "ISP MTAANI: Block duplicate PPPoE" in rule_comment:
                existing_rule = rule
                break
        
        if existing_rule:
            logger.info("Firewall block already exists for duplicate IP: %s", duplicate_ip)
            return  # Already blocked
        
        # Create firewall rule to immediately block all traffic from duplicate session
        # Place at the beginning of forward chain by getting first rule ID
        try:
            first_rule = filters.get(chain="forward")
            place_before_id = first_rule[0].get(".id") if first_rule else None
        except Exception:  # noqa: BLE001
            place_before_id = None
        
        rule_payload = {
            "chain": "forward",
            "action": "drop",
            "src-address": duplicate_ip,
            "comment": f"ISP MTAANI: Block duplicate PPPoE session {duplicate_ip}",
        }
        
        # Only add place-before if we found a first rule
        if place_before_id:
            rule_payload["place-before"] = place_before_id
        
        filters.add(**rule_payload)
        logger.warning("FIREWALL BLOCKED: Immediately blocked all internet traffic from duplicate session IP: %s", duplicate_ip)
    except Exception as exc:  # noqa: BLE001
        logger.error("Error creating firewall block for duplicate IP %s: %s", duplicate_ip, sanitize_error_message(str(exc)))


def mikrotik_enforce_single_session(api, username):
    """Enforce single session per username by immediately blocking and disconnecting duplicate sessions.
    
    This function:
    1. Immediately blocks internet access for duplicate sessions using firewall rules
    2. Temporarily disables the PPPoE secret to prevent new connections
    3. Disconnects all duplicate sessions
    4. Re-enables the secret after cleanup
    
    This prevents multiple devices from using the same PPPoE account simultaneously.
    """
    try:
        active = api.get_resource("/ppp/active")
        connections = active.get(name=username)
        
        if not connections:
            return True
        
        # If more than one connection exists, block and disconnect all but the FIRST (oldest) connection
        if len(connections) > 1:
            logger.warning("SECURITY ALERT: Multiple sessions detected for user %s. Immediately blocking internet access and disconnecting %d duplicate sessions.", username, len(connections) - 1)
            
            # Get PPPoE secret ID to temporarily disable it
            secrets = api.get_resource("/ppp/secret")
            secret_info = secrets.get(name=username)
            secret_id = None
            secret_was_enabled = True
            if secret_info:
                secret_id = secret_info[0].get(".id")
                secret_was_enabled = secret_info[0].get("disabled") != "yes"
            
            # STEP 1: Immediately block internet access for duplicate sessions using firewall
            first_conn_id = connections[0].get("id")
            first_conn_address = connections[0].get("address", "unknown")
            
            # Block all duplicate session IPs immediately
            for conn in connections[1:]:
                duplicate_ip = conn.get("address", "")
                if duplicate_ip:
                    mikrotik_block_duplicate_session_traffic(api, duplicate_ip)
            
            # STEP 2: Temporarily disable PPPoE secret to prevent new connections
            if secret_id and secret_was_enabled:
                try:
                    secrets.set(id=secret_id, disabled="yes")
                    logger.warning("TEMPORARILY DISABLED: PPPoE secret for user %s disabled to prevent new duplicate connections", username)
                except Exception as disable_exc:  # noqa: BLE001
                    logger.error("Error disabling PPPoE secret: %s", sanitize_error_message(str(disable_exc)))
            
            # STEP 3: Disconnect ALL duplicate sessions (all except the first)
            disconnected_count = 0
            for conn in connections[1:]:
                try:
                    conn_id = conn.get("id")
                    conn_address = conn.get("address", "unknown")
                    # Disconnect the duplicate session
                    active.remove(id=conn_id)
                    disconnected_count += 1
                    logger.warning("BLOCKED: Disconnected duplicate PPPoE session for user: %s (ID: %s, IP: %s) - Internet access denied", username, conn_id, conn_address)
                except Exception as conn_exc:  # noqa: BLE001
                    logger.error("Error disconnecting duplicate session %s: %s", conn.get("id"), sanitize_error_message(str(conn_exc)))
            
            # STEP 4: Wait a moment for router to process disconnections, then verify
            import time
            time.sleep(0.5)  # Brief pause to allow router to process
            
            # Re-fetch and verify only one session remains (with retry mechanism)
            import time
            max_retries = 3
            for retry in range(max_retries):
                remaining = active.get(name=username)
                if not remaining or len(remaining) <= 1:
                    logger.info("Successfully enforced single session for user %s. Kept session ID: %s (IP: %s), disconnected %d duplicates.", username, first_conn_id, first_conn_address, disconnected_count)
                    break  # Success - only one session remains
                
                if retry == 0:
                    logger.error("CRITICAL: Multiple sessions still exist for user %s after cleanup (%d remaining). Force disconnecting with retries.", username, len(remaining))
                
                # Force disconnect all except the first (oldest) connection
                for conn in remaining[1:]:
                    try:
                        conn_id = conn.get("id")
                        conn_address = conn.get("address", "unknown")
                        # Block traffic first, then disconnect
                        if conn_address:
                            mikrotik_block_duplicate_session_traffic(api, conn_address)
                        active.remove(id=conn_id)
                        logger.warning("FORCE BLOCKED (retry %d/%d): Disconnected remaining duplicate session for user: %s (ID: %s, IP: %s)", retry + 1, max_retries, username, conn_id, conn_address)
                    except Exception as force_exc:  # noqa: BLE001
                        logger.error("Error force disconnecting session %s (retry %d/%d): %s", conn.get("id"), retry + 1, max_retries, sanitize_error_message(str(force_exc)))
                
                if retry < max_retries - 1:
                    time.sleep(0.3)  # Brief pause before retry to allow router to process
            
            # STEP 5: Re-enable PPPoE secret after cleanup (if it was enabled before)
            if secret_id and secret_was_enabled:
                try:
                    secrets.set(id=secret_id, disabled="no")
                    logger.info("RE-ENABLED: PPPoE secret for user %s re-enabled after duplicate session cleanup", username)
                except Exception as enable_exc:  # noqa: BLE001
                    logger.error("Error re-enabling PPPoE secret: %s", sanitize_error_message(str(enable_exc)))
            
            # Final verification
            final_check = active.get(name=username)
            if final_check and len(final_check) > 1:
                logger.error("CRITICAL FAILURE: Still %d sessions exist for user %s after %d retries. Router may be creating new sessions faster than we can disconnect. Consider checking router configuration and PPP profile 'only-one' setting.", len(final_check), username, max_retries)
            elif final_check and len(final_check) == 1:
                logger.info("Successfully enforced single session for user %s after retries. Kept session ID: %s (IP: %s), disconnected %d duplicates.", username, first_conn_id, first_conn_address, disconnected_count)
            
            return True
        
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("CRITICAL ERROR enforcing single session for user %s: %s", username, sanitize_error_message(str(exc)))
        return False


def mikrotik_ensure_pppoe_not_fasttracked(api, pppoe_pool_network="192.168.1.0/24"):
    """Ensure PPPoE pool traffic (both directions) is accepted before FastTrack so simple queues can limit it.
    FastTrack bypasses the queue system. We need two rules: upload (src=pool) and download (dst=pool)."""
    try:
        filters = api.get_resource("/ip/firewall/filter")
        for comment in (
            "ISP MTAANI: PPPoE no fasttrack (queue limits)",
            "ISP MTAANI: PPPoE no fasttrack upload",
            "ISP MTAANI: PPPoE no fasttrack download",
        ):
            existing = filters.get(comment=comment)
            if existing:
                for rule in existing:
                    filters.remove(id=rule.get("id") or rule.get(".id"))
        # Find first fasttrack rule in forward chain
        all_rules = filters.get(chain="forward")
        place_before_id = None
        for r in all_rules:
            action = (r.get("action") or "").lower()
            if "fasttrack" in action:
                place_before_id = r.get(".id") or r.get("id")
                break
        # Upload: packets FROM PPPoE clients (src=pool) - accept before fasttrack
        rule_up = {
            "chain": "forward",
            "action": "accept",
            "src-address": pppoe_pool_network,
            "comment": "ISP MTAANI: PPPoE no fasttrack upload",
        }
        if place_before_id:
            rule_up["place-before"] = place_before_id
        filters.add(**rule_up)
        # Download: packets TO PPPoE clients (dst=pool) - accept before fasttrack so queues apply
        rule_down = {
            "chain": "forward",
            "action": "accept",
            "dst-address": pppoe_pool_network,
            "comment": "ISP MTAANI: PPPoE no fasttrack download",
        }
        if place_before_id:
            rule_down["place-before"] = place_before_id
        filters.add(**rule_down)
        logger.info("Firewall: PPPoE pool %s upload+download accepted before FastTrack so queues apply", pppoe_pool_network)
    except Exception as exc:  # noqa: BLE001
        logger.info("Could not add PPPoE no-fasttrack rules: %s", sanitize_error_message(str(exc)))


def _build_queue_target(client_ip, pppoe_interface):
    """Build queue target for strict limit on both wired (PPPoE) and wireless traffic.
    Uses client IP so all traffic to/from that IP is limited, and PPPoE interface
    so traffic on that session is limited regardless of path. Dual target ensures
    the speed cap applies to the customer on both wired and wireless connections."""
    parts = []
    if client_ip and (str(client_ip) or "").strip():
        ip_str = str(client_ip).strip()
        if "/" not in ip_str:
            ip_str = f"{ip_str}/32"
        parts.append(ip_str)
    if pppoe_interface and (str(pppoe_interface) or "").strip():
        iface = str(pppoe_interface).strip()
        if iface and iface not in parts:
            parts.append(iface)
    return ",".join(parts) if parts else None


def mikrotik_create_or_update_queue(api, username, target, upload_mbps, download_mbps, queue_id=None):
    """Create or update a simple queue for bandwidth limiting.
    Target can be a single value or comma-separated (e.g. "192.168.1.100/32,pppoe-in1")
    for strict limit on both wired and wireless. No burst is set so max-limit is strict.
    
    Args:
        api: MikroTik API object
        username: PPPoE username
        target: IP address and/or interface (e.g. "192.168.1.100/32,pppoe-in1")
        upload_mbps: Upload speed limit in Mbps (0 or None = unlimited)
        download_mbps: Download speed limit in Mbps (0 or None = unlimited)
        queue_id: Existing queue ID to update (None to create new)
    
    Returns:
        Queue ID if successful, None otherwise
    """
    queues = api.get_resource("/queue/simple")
    
    queue_name = f"ISP-MTAANI-{username}"
    # Convert Mbps to MikroTik format (use M for Mbps)
    upload_limit = f"{upload_mbps}M" if upload_mbps and upload_mbps > 0 else None
    download_limit = f"{download_mbps}M" if download_mbps and download_mbps > 0 else None
    
    # MikroTik simple queue uses format "download/upload" for max-limit
    # If both are set, use "download/upload" format
    # If only one is set, use that value alone
    if download_limit and upload_limit:
        max_limit = f"{download_limit}/{upload_limit}"
        limit_at = f"{download_limit}/{upload_limit}"
    elif download_limit:
        max_limit = download_limit
        limit_at = download_limit
    elif upload_limit:
        max_limit = upload_limit
        limit_at = upload_limit
    else:
        max_limit = None
        limit_at = None
    
    if queue_id:
        # Update existing queue
        try:
            queue_params = {
                "id": queue_id,
                "name": queue_name,
                "target": target,
            }
            if max_limit:
                queue_params["max-limit"] = max_limit
                queue_params["limit-at"] = limit_at
            else:
                # Remove limits if both are 0
                queue_params["max-limit"] = ""
                queue_params["limit-at"] = ""
            
            queues.set(**queue_params)
            logger.info("Updated queue for %s: target=%s, upload=%s, download=%s, max-limit=%s", username, target, upload_limit, download_limit, max_limit)
            return queue_id
        except Exception as exc:  # noqa: BLE001
            logger.info("Error updating queue: %s", sanitize_error_message(str(exc)))
            # Try to create new one if update fails
            queue_id = None
    
    if not queue_id:
        # Create new queue
        try:
            # Remove existing queue with same name if exists
            existing = queues.get(name=queue_name)
            if existing:
                queues.remove(id=existing[0].get("id"))
            
            queue_params = {
                "name": queue_name,
                "target": target,
                "comment": f"ISP MTAANI: {username}",
            }
            if max_limit:
                queue_params["max-limit"] = max_limit
                queue_params["limit-at"] = limit_at
            
            result = queues.add(**queue_params)
            new_queue_id = result.get("ret") if isinstance(result, dict) else None
            if not new_queue_id:
                # Try to get the ID by name
                found = queues.get(name=queue_name)
                if found:
                    new_queue_id = found[0].get("id")
            logger.info("Created queue for %s: target=%s, upload=%s, download=%s, max-limit=%s, id=%s", username, target, upload_limit, download_limit, max_limit, new_queue_id)
            return new_queue_id
        except Exception as exc:  # noqa: BLE001
            logger.info("Error creating queue: %s", sanitize_error_message(str(exc)))
            return None
    
    return queue_id


def mikrotik_remove_queue(api, queue_id):
    """Remove a simple queue."""
    if not queue_id:
        return
    try:
        queues = api.get_resource("/queue/simple")
        queues.remove(id=queue_id)
        logger.info("Removed queue: %s", queue_id)
    except Exception as exc:  # noqa: BLE001
        logger.info("Error removing queue: %s", sanitize_error_message(str(exc)))


def enforce_data_caps(creds, users_with_status, active_connections):
    """Update per-user data usage from router stats; reset period if needed; disable or mark over_cap when cap exceeded."""
    over_limit_action = db_get_setting("over_limit_action", "disable")
    try:
        downgrade_kbps = int(db_get_setting("downgrade_speed_kbps", "256"))
    except (TypeError, ValueError):
        downgrade_kbps = 256
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    pool = None
    try:
        pool, api = get_router_api(creds)
        for u in users_with_status:
            if not u.get("is_connected"):
                continue
            plan = u.get("matched_plan")
            if not plan:
                continue
            cap_gb = plan.get("data_cap_gb")
            # Daily data cap period (reset each day), regardless of legacy plan values.
            reset_days = 1
            if cap_gb is None or (isinstance(cap_gb, (int, float)) and cap_gb <= 0):
                continue
            try:
                cap_gb = float(cap_gb)
            except (TypeError, ValueError):
                continue
            if reset_days < 1:
                continue
            cap_bytes = int(cap_gb * 1e9)
            username = u.get("pppoe_username", "")
            conn_info = active_connections.get(username, {})
            try:
                current_cumulative = int(conn_info.get("bytes_sent", "0") or 0) + int(conn_info.get("bytes_received", "0") or 0)
            except (TypeError, ValueError):
                current_cumulative = 0
            data_usage = u.get("data_usage_bytes_this_period") or 0
            cap_reset_at = u.get("cap_reset_at")
            last_seen = u.get("last_seen_cumulative_bytes") or 0
            over_cap_suspended = u.get("over_cap_suspended")

            # Parse cap_reset_at for date comparison
            reset_dt = None
            if cap_reset_at:
                if hasattr(cap_reset_at, "replace"):
                    reset_dt = cap_reset_at.replace(tzinfo=None) if getattr(cap_reset_at, "tzinfo", None) else cap_reset_at
                else:
                    try:
                        reset_dt = datetime.strptime(str(cap_reset_at)[:19], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        try:
                            reset_dt = datetime.strptime(str(cap_reset_at)[:10], "%Y-%m-%d")
                        except ValueError:
                            reset_dt = None

            if reset_dt is None or (now - reset_dt).days >= reset_days:
                # New period: reset usage; re-enable if was suspended for over-cap
                data_usage = 0
                cap_reset_at = now
                last_seen = current_cumulative
                updates = {
                    "data_usage_bytes_this_period": data_usage,
                    "cap_reset_at": cap_reset_at,
                    "last_seen_cumulative_bytes": last_seen,
                }
                if over_cap_suspended:
                    updates["status"] = "active"
                    updates["over_cap_suspended"] = 0
                    secret_id = u.get("mikrotik_secret_id")
                    if secret_id:
                        try:
                            mikrotik_set_pppoe_disabled(api, secret_id, False)
                        except Exception:  # noqa: BLE001
                            pass
                db_update_pppoe_router(u["id"], updates)
                u["data_usage_bytes_this_period"] = data_usage
                u["cap_reset_at"] = cap_reset_at
                u["last_seen_cumulative_bytes"] = last_seen
                if over_cap_suspended:
                    u["over_cap_suspended"] = False
                    u["status"] = "active"
                continue

            delta = current_cumulative - last_seen
            if delta < 0:
                delta = 0
            data_usage += delta
            last_seen = current_cumulative
            db_update_pppoe_router(u["id"], {
                "data_usage_bytes_this_period": data_usage,
                "cap_reset_at": cap_reset_at,
                "last_seen_cumulative_bytes": last_seen,
            })
            u["data_usage_bytes_this_period"] = data_usage
            u["last_seen_cumulative_bytes"] = last_seen

            if data_usage >= cap_bytes:
                if over_limit_action == "disable":
                    secret_id = u.get("mikrotik_secret_id")
                    if secret_id:
                        try:
                            mikrotik_set_pppoe_disabled(api, secret_id, True)
                        except Exception:  # noqa: BLE001
                            pass
                    # Disconnect active session so user loses internet immediately (not just on next login)
                    try:
                        mikrotik_disconnect_pppoe_session(api, username)
                    except Exception:  # noqa: BLE001
                        pass
                    db_update_pppoe_router(u["id"], {"status": "suspended", "over_cap_suspended": 1})
                    u["status"] = "suspended"
                    u["over_cap_suspended"] = True
                    u["is_connected"] = False
                else:
                    u["over_cap"] = True
        if pool:
            pool.disconnect()
    except Exception as exc:  # noqa: BLE001
        logger.info("Enforce data caps: %s", sanitize_error_message(str(exc)))
        if pool:
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass


def ensure_queues_for_connected_users(creds, users_with_status, router_id=None):
    """Ensure only registered PPPoE customers get internet; ensure queues for connected users with speed limits."""
    over_limit_action = db_get_setting("over_limit_action", "disable")
    try:
        downgrade_kbps = int(db_get_setting("downgrade_speed_kbps", "256"))
    except (TypeError, ValueError):
        downgrade_kbps = 256
    downgrade_mbps = downgrade_kbps / 1000.0
    # Include all connected users so every session gets a queue (prevents "connected but no internet")
    to_process = [
        u for u in users_with_status
        if u.get("is_connected")
    ]
    try:
        pool, api = get_router_api(creds)
        try:
            # PPPoE pool network for firewall and no-fasttrack
            pppoe_pool_network = "192.168.1.0/24"
            try:
                pools = api.get_resource("/ip/pool").get(name="pppoe-pool")
                if pools and pools[0].get("ranges"):
                    first_ip = (pools[0]["ranges"] or "").split("-")[0].strip()
                    if first_ip:
                        pppoe_pool_network = first_ip.rsplit(".", 1)[0] + ".0/24"
            except Exception:  # noqa: BLE001
                pass
            # Enforce policy from settings.
            allow_wifi = (db_get_setting("allow_wifi_access", "0") or "0").strip() in {"1", "true", "yes", "on"}
            wifi_network = None
            if allow_wifi:
                _pppoe_net, detected_wifi = _get_router_pppoe_and_wifi_networks(api)
                wifi_network = detected_wifi
            # Enforce: only PPPoE pool (or optional WiFi subnet) can forward to internet.
            wan_interface = (db_get_setting("wan_interface", "") or "").strip() or None
            if not wan_interface:
                wan_interface = mikrotik_detect_wan_interface(api)
                if wan_interface:
                    db_set_setting("wan_interface", wan_interface)
                    logger.info("Auto-detected WAN interface for enforcement: %s", wan_interface)
            mikrotik_fix_firewall_rule(
                api,
                pppoe_pool_network,
                wan_interface=wan_interface,
                allow_wifi=allow_wifi,
                wifi_network=wifi_network if allow_wifi else None,
            )
            # Remove PPPoE secrets on router that are not registered in our system
            if router_id is None and users_with_status:
                router_id = users_with_status[0].get("mikrotik_router_id")
            mikrotik_remove_unknown_pppoe_secrets(api, router_id)
            # So simple queues apply: accept PPPoE pool before FastTrack (FastTrack bypasses queues)
            mikrotik_ensure_pppoe_not_fasttracked(api, pppoe_pool_network)
            if to_process:
                # Build username -> interface and username -> address from /ppp/active (one call)
                active_list = api.get_resource("/ppp/active").get()
                interface_by_user = {}
                address_by_user = {}
                for conn in active_list:
                    name = conn.get("name")
                    if name is None and conn:
                        name = conn.get(b"name")
                    if not name:
                        continue
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    name = (name or "").strip()
                    if not name:
                        continue
                    addr = conn.get("address")
                    if addr is None and conn:
                        addr = conn.get(b"address")
                    if addr:
                        if isinstance(addr, bytes):
                            addr = addr.decode("utf-8", errors="replace")
                        address_by_user[name] = (addr or "").strip()
                    for key in ("interface", "session", "link"):
                        val = conn.get(key)
                        if val is None and conn:
                            val = conn.get(key.encode("utf-8"))
                        if val:
                            if isinstance(val, bytes):
                                val = val.decode("utf-8", errors="replace")
                            val = (val or "").strip()
                            if val:
                                interface_by_user[name] = val
                                break
                for u in to_process:
                    username = u.get("pppoe_username", "")
                    client_ip = address_by_user.get(username) or u.get("connection_address")
                    pppoe_interface = interface_by_user.get(username)
                    target = _build_queue_target(client_ip, pppoe_interface)
                    if not target:
                        logger.warning(
                            "Queue skipped for connected user %s: no IP or interface (address=%s, interface=%s). User may have session but no internet until next sync.",
                            username, client_ip or "(none)", pppoe_interface or "(none)"
                        )
                        continue
                    if u.get("over_cap") and over_limit_action == "downgrade":
                        upload_mbps = download_mbps = downgrade_mbps
                    else:
                        upload_mbps = float(u.get("upload_speed_mbps") or 0) or None
                        download_mbps = float(u.get("download_speed_mbps") or 0) or None
                    queue_id = u.get("mikrotik_queue_id")
                    new_queue_id = mikrotik_create_or_update_queue(
                        api, username, target, upload_mbps, download_mbps, queue_id
                    )
                    if new_queue_id and new_queue_id != queue_id:
                        db_update_pppoe_router(u["id"], {"mikrotik_queue_id": new_queue_id})
        finally:
            pool.disconnect()
    except Exception as exc:  # noqa: BLE001
        logger.info("Ensure queues for connected users: %s", sanitize_error_message(str(exc)))


def mikrotik_get_pppoe_client_ip(api, username):
    """Get the current IP address of a PPPoE client."""
    try:
        active = api.get_resource("/ppp/active")
        connections = active.get(name=username)
        if connections and len(connections) > 0:
            return connections[0].get("address", "")
        return None
    except Exception as exc:  # noqa: BLE001
        logger.info("Error getting PPPoE client IP: %s", sanitize_error_message(str(exc)))
        return None


def mikrotik_get_pppoe_interface(api, username):
    """Get the PPPoE interface name for a client (e.g. pppoe-in1, <pppoe-07049>). Used as queue target."""
    try:
        active = api.get_resource("/ppp/active")
        connections = active.get(name=username)
        if not connections or len(connections) == 0:
            return None
        conn = connections[0]
        # RouterOS may use "interface", "session", or "link"; keys may be str or bytes
        for key in ("interface", "session", "link"):
            val = conn.get(key)
            if val is None and conn:
                try:
                    val = conn.get(key.encode("utf-8"))
                except Exception:  # noqa: BLE001
                    pass
            if val:
                if isinstance(val, bytes):
                    val = val.decode("utf-8", errors="replace")
                val = (val or "").strip()
                if val:
                    return val
        return None
    except Exception as exc:  # noqa: BLE001
        logger.info("Error getting PPPoE interface: %s", sanitize_error_message(str(exc)))
        return None


def mikrotik_remove_pppoe_secret(api, secret_id):
    secrets = api.get_resource("/ppp/secret")
    secrets.remove(id=secret_id)


def mikrotik_remove_unknown_pppoe_secrets(api, router_id):
    """Remove PPPoE secrets on the router that are not registered in our system for this router.
    Only customers registered in the billing system (pppoe_routers) should be able to authenticate."""
    if not router_id:
        return
    try:
        registered = db_list_pppoe_routers(router_id=router_id)
        allowed_usernames = {str(u.get("pppoe_username", "")).strip() for u in registered if u.get("pppoe_username")}
        secrets = api.get_resource("/ppp/secret")
        all_secrets = secrets.get()
        if not all_secrets:
            return
        # Only consider PPPoE secrets (exclude pptp, l2tp, etc.)
        pppoe_secrets = []
        for s in all_secrets:
            svc = s.get("service") or s.get(b"service")
            if svc is None:
                pppoe_secrets.append(s)
                continue
            if isinstance(svc, bytes):
                svc = svc.decode("utf-8", errors="replace")
            if (svc or "").strip().lower() == "pppoe":
                pppoe_secrets.append(s)
        if not pppoe_secrets:
            # Even if no secrets exist, still disconnect unknown active sessions.
            pppoe_secrets = []
        for entry in pppoe_secrets:
            name = entry.get("name")
            if name is None:
                name = entry.get(b"name")
            if name is None:
                continue
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            name = (name or "").strip()
            if name and name not in allowed_usernames:
                sid = entry.get(".id") or entry.get("id")
                if sid:
                    try:
                        secrets.remove(id=sid)
                        logger.info("Removed PPPoE secret '%s' from router (not in billing system)", name)
                    except Exception as exc:  # noqa: BLE001
                        logger.info("Could not remove unknown secret %s: %s", name, sanitize_error_message(str(exc)))
        # Also disconnect active PPPoE sessions for unknown usernames immediately.
        try:
            active = api.get_resource("/ppp/active")
            active_sessions = active.get()
            for conn in active_sessions or []:
                name = conn.get("name")
                if name is None and conn:
                    name = conn.get(b"name")
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                name = (name or "").strip()
                if not name or name in allowed_usernames:
                    continue
                cid = conn.get("id") or conn.get(".id")
                if cid:
                    try:
                        active.remove(id=cid)
                        logger.info("Disconnected unknown active PPPoE session '%s' (not in billing system)", name)
                    except Exception as exc:  # noqa: BLE001
                        logger.info("Could not disconnect unknown active session %s: %s", name, sanitize_error_message(str(exc)))
        except Exception as exc:  # noqa: BLE001
            logger.info("Could not scan/disconnect unknown active PPPoE sessions: %s", sanitize_error_message(str(exc)))
    except Exception as exc:  # noqa: BLE001
        logger.info("Remove unknown PPPoE secrets: %s", sanitize_error_message(str(exc)))


# --- Dual WAN (50/50 PCC) helpers: monitoring + optional idempotent apply ---

DUAL_WAN_R_TABLE_1 = "ismtaani-w1"
DUAL_WAN_R_TABLE_2 = "ismtaani-w2"
DUAL_WAN_C_MARK_1 = "ismtaani-c1"
DUAL_WAN_C_MARK_2 = "ismtaani-c2"
DUAL_WAN_COMMENT_PREFIX = "ISP MTAANI DUAL-WAN"


def _ros_str(val):
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val).strip()


def _normalize_gateway_value(raw):
    """
    Normalize RouterOS gateway-like values such as:
    - "192.168.100.1"
    - "192.168.100.1%ether1"
    - "192.168.100.1%ether1,192.168.100.1"
    """
    text = _ros_str(raw)
    if not text:
        return ""
    first = text.split(",", 1)[0].strip()
    if "%" in first:
        first = first.split("%", 1)[0].strip()
    return first


def _gw_from_default_routes_for_iface(api, iface):
    """Read gateway IP for iface from main table default routes (immediate-gw ...%iface)."""
    try:
        routes = api.get_resource("/ip/route").get(dst_address="0.0.0.0/0")
    except Exception:  # noqa: BLE001
        return None
    iface = (iface or "").strip()
    for r in routes or []:
        if (_ros_str(r.get("disabled"))).lower() == "true":
            continue
        ig_raw = _ros_str(r.get("immediate-gw") or r.get("immediate_gw") or "")
        gw_raw = _ros_str(r.get("gateway") or "")
        ig = ig_raw or gw_raw
        if not ig and r.get("gateway"):
            ig = _ros_str(r.get("gateway"))
        if "%" in ig:
            gwip, ifpart = ig.rsplit("%", 1)
            if_clean = ifpart.split(",", 1)[0].strip()
            if if_clean == iface or if_clean.startswith(iface):
                return _normalize_gateway_value(gwip)
        gonly = _normalize_gateway_value(r.get("gateway"))
        rif = _ros_str(r.get("interface") or r.get("immediate-gw"))
        if gonly and not ig and (rif == iface or (iface in rif and "%" in rif)):
            return gonly
    return None


def _dhcp_client_for_interface(api, iface):
    try:
        rows = api.get_resource("/ip/dhcp-client").get()
    except Exception:  # noqa: BLE001
        return None
    iface = (iface or "").strip()
    for r in rows or []:
        if _ros_str(r.get("interface")) == iface:
            return r
    return None


def _gw_from_dhcp_client(api, iface):
    """Best-effort gateway extraction from DHCP client row for an interface."""
    dc = _dhcp_client_for_interface(api, iface)
    if not dc:
        return None
    for key in ("gateway", "gateway-address", "gateway_address"):
        val = _normalize_gateway_value(dc.get(key))
        if val:
            return val
    return None


def mikrotik_probe_interface_internet(api, iface, target="1.1.1.1", count=2):
    """Best-effort internet probe via interface using RouterOS ping."""
    iface = (iface or "").strip()
    if not iface:
        return False
    try:
        ping = api.get_resource("/ping")
        rows = ping.get(address=target, interface=iface, count=str(count), interval="500ms")
        if not rows:
            return False
        received = 0
        for r in rows:
            rv = _ros_str(r.get("received"))
            if rv:
                try:
                    received = max(received, int(rv))
                except Exception:  # noqa: BLE001
                    pass
            if _ros_str(r.get("status")) in {"timeout", "host unreachable"}:
                continue
            # Some RouterOS responses provide seq/time for successful probes
            if _ros_str(r.get("time")) and _ros_str(r.get("status")) != "timeout":
                return True
        return received > 0
    except Exception:  # noqa: BLE001
        return False


def mikrotik_wan_link_snapshot(api, iface):
    """Return a dict for one WAN: interface + DHCP + gateway hint for the UI."""
    iface = (iface or "").strip()
    out = {
        "interface": iface,
        "ok": False,
        "interface_running": None,
        "interface_disabled": None,
        "rx_byte": None,
        "tx_byte": None,
        "dhcp_status": None,
        "dhcp_add_default": None,
        "bound_address": None,
        "gateway": None,
        "internet_ok": None,
        "error": None,
    }
    if not iface:
        out["error"] = "No interface name."
        return out
    try:
        ifs = api.get_resource("/interface").get()
        row = next((x for x in (ifs or []) if _ros_str(x.get("name")) == iface), None)
        if row:
            out["interface_running"] = _ros_str(row.get("running")).lower() in {"true", "yes", "1"}
            out["interface_disabled"] = _ros_str(row.get("disabled")).lower() in {"true", "yes", "1"}
            out["rx_byte"] = _ros_str(row.get("rx-byte") or row.get("rx_byte"))
            out["tx_byte"] = _ros_str(row.get("tx-byte") or row.get("tx_byte"))
    except Exception as exc:  # noqa: BLE001
        out["error"] = sanitize_error_message(str(exc))
        return out
    dc = _dhcp_client_for_interface(api, iface)
    if dc:
        out["dhcp_status"] = _ros_str(dc.get("status"))
        out["dhcp_add_default"] = _ros_str(dc.get("add-default-route") or dc.get("add_default_route"))
        out["bound_address"] = _ros_str(dc.get("address"))
    else:
        out["dhcp_status"] = "not configured"
    out["gateway"] = _gw_from_default_routes_for_iface(api, iface) or _gw_from_dhcp_client(api, iface)
    out["ok"] = bool(
        (out.get("interface_running") is not False)
        and out.get("dhcp_status")
        and out["dhcp_status"] in ("bound", "searching", "connecting", "rebinding", "selecting", "requesting", "rebooting", "restarting")
    )
    if out["dhcp_status"] == "bound":
        out["ok"] = True
    if out["dhcp_status"] == "not configured":
        out["ok"] = out.get("interface_running") and bool(out.get("interface_running") is not False)
    # Real internet probe (helps detect "bound but no upstream internet")
    # Probe internet best-effort. Do not hard-require DHCP here because some setups use static/default routes.
    if out.get("interface_running") is not False and not out.get("interface_disabled"):
        out["internet_ok"] = mikrotik_probe_interface_internet(api, iface)
    else:
        out["internet_ok"] = False
    return out


def mikrotik_is_wan_usable(snapshot):
    """
    Conservative WAN usability check for dual-WAN decisions.
    Do NOT require ICMP probe success because some ISPs/rules block ping while internet works.
    """
    s = snapshot or {}
    dhcp_ok = _ros_str(s.get("dhcp_status")).lower() == "bound"
    has_gateway = bool(_ros_str(s.get("gateway")))
    running_ok = s.get("interface_running") is not False
    not_disabled = not bool(s.get("interface_disabled"))
    return bool(dhcp_ok and has_gateway and running_ok and not_disabled)


def mikrotik_fetch_gateways_for_apply(api, wan1, wan2):
    """
    Read ISP gateways for two WANs. If DHCP is set to not add a default route, temporarily
    enable one interface at a time so a gateway can be read from /ip/route.
    """
    dc_res = api.get_resource("/ip/dhcp-client")
    c1, c2 = _dhcp_client_for_interface(api, wan1), _dhcp_client_for_interface(api, wan2)
    if not c1 or not c2:
        return None, None, "Add a DHCP client on each WAN interface in MikroTik (IP → DHCP Client)."
    id1, id2 = c1.get(".id") or c1.get("id"), c2.get(".id") or c2.get("id")
    old1 = _ros_str(c1.get("add-default-route") or c1.get("add_default_route") or "yes")
    old2 = _ros_str(c2.get("add-default-route") or c2.get("add_default_route") or "yes")

    g1 = _gw_from_default_routes_for_iface(api, wan1) or _gw_from_dhcp_client(api, wan1)
    g2 = _gw_from_default_routes_for_iface(api, wan2) or _gw_from_dhcp_client(api, wan2)
    if g1 and g2:
        return g1, g2, None

    try:
        if not g1 and id1:
            dc_res.set(id=id1, **{"add-default-route": "yes"})
            g1 = _gw_from_default_routes_for_iface(api, wan1) or _gw_from_dhcp_client(api, wan1) or g1
            dc_res.set(id=id1, **{"add-default-route": old1 or "no"})
        if not g2 and id2:
            dc_res.set(id=id2, **{"add-default-route": "yes"})
            g2 = _gw_from_default_routes_for_iface(api, wan2) or _gw_from_dhcp_client(api, wan2) or g2
            dc_res.set(id=id2, **{"add-default-route": old2 or "no"})
    except Exception as exc:  # noqa: BLE001
        try:
            if id1:
                dc_res.set(id=id1, **{"add-default-route": old1 or "no"})
        except Exception:  # noqa: BLE001
            pass
        try:
            if id2:
                dc_res.set(id=id2, **{"add-default-route": old2 or "no"})
        except Exception:  # noqa: BLE001
            pass
        return None, None, sanitize_error_message(str(exc))

    if not g1 or not g2:
        return None, None, "Could not read WAN gateways. Ensure both DHCP clients are bound and exposing gateway values, then renew each WAN DHCP lease and try again."
    return g1, g2, None


def mikrotik_fetch_single_wan_gateway(api, wan):
    """Fetch gateway for one WAN interface; temporarily enables add-default-route if needed."""
    wan = (wan or "").strip()
    if not wan:
        return None, "WAN interface is required."
    g = _gw_from_default_routes_for_iface(api, wan) or _gw_from_dhcp_client(api, wan)
    if g:
        return g, None
    c = _dhcp_client_for_interface(api, wan)
    if not c:
        return None, f"No DHCP client configured on {wan}."
    cid = c.get(".id") or c.get("id")
    old = _ros_str(c.get("add-default-route") or c.get("add_default_route") or "yes")
    if not cid:
        return None, f"Could not read DHCP client id on {wan}."
    try:
        dc_res = api.get_resource("/ip/dhcp-client")
        dc_res.set(id=cid, **{"add-default-route": "yes"})
        g = _gw_from_default_routes_for_iface(api, wan) or _gw_from_dhcp_client(api, wan)
        dc_res.set(id=cid, **{"add-default-route": old or "no"})
    except Exception as exc:  # noqa: BLE001
        try:
            dc_res = api.get_resource("/ip/dhcp-client")
            dc_res.set(id=cid, **{"add-default-route": old or "no"})
        except Exception:  # noqa: BLE001
            pass
        return None, sanitize_error_message(str(exc))
    if not g:
        return None, f"Could not read gateway from {wan}. Ensure DHCP is bound and route exists."
    return g, None


def mikrotik_dual_wan_cleanup(api):
    """Remove previous ISP MTAANI DUAL-WAN mangle, NAT, routes, and routing tables."""
    try:
        mangle = api.get_resource("/ip/firewall/mangle")
        for rule in mangle.get() or []:
            c = _ros_str(rule.get("comment") or "")
            if DUAL_WAN_COMMENT_PREFIX in c and rule.get("id"):
                try:
                    mangle.remove(id=rule["id"])
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass
    try:
        natr = api.get_resource("/ip/firewall/nat")
        for rule in natr.get() or []:
            c = _ros_str(rule.get("comment") or "")
            if DUAL_WAN_COMMENT_PREFIX in c and rule.get("id"):
                try:
                    natr.remove(id=rule["id"])
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass
    try:
        routes = api.get_resource("/ip/route")
        for r in routes.get() or []:
            rtb = _ros_str(r.get("routing-table") or r.get("routing_table") or "")
            c = _ros_str(r.get("comment") or "")
            if (rtb in (DUAL_WAN_R_TABLE_1, DUAL_WAN_R_TABLE_2) or DUAL_WAN_COMMENT_PREFIX in c) and (r.get("id") or r.get(".id")):
                rid = r.get("id") or r.get(".id")
                try:
                    routes.remove(id=rid)
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass
    try:
        rtb = api.get_resource("/routing/table")
        for name in (DUAL_WAN_R_TABLE_1, DUAL_WAN_R_TABLE_2):
            for t in rtb.get() or []:
                if _ros_str(t.get("name")) == name and t.get("id"):
                    try:
                        rtb.remove(id=t["id"])
                    except Exception:  # noqa: BLE001
                        pass
    except Exception:  # noqa: BLE001
        pass


def mikrotik_apply_dual_wan_pcc(api, lan_iface, wan1, wan2):
    """
    50/50 Per Connection Classifier (PCC) load balancing. Safe to re-run: cleans same-named rules first.
    """
    lan_iface = (lan_iface or "").strip()
    wan1, wan2 = (wan1 or "").strip(), (wan2 or "").strip()
    if not lan_iface or not wan1 or not wan2 or wan1 == wan2:
        return False, "LAN and two distinct WAN interface names are required."
    g1, g2, gerr = mikrotik_fetch_gateways_for_apply(api, wan1, wan2)
    if gerr or not g1 or not g2:
        return False, gerr or "Missing gateway(s)."

    ifs = api.get_resource("/interface").get()
    names = {_ros_str(x.get("name")) for x in (ifs or [])}
    for i in (lan_iface, wan1, wan2):
        if i not in names:
            return False, f"Interface not found: {i}"

    mikrotik_dual_wan_cleanup(api)

    # Routing tables
    rtab = api.get_resource("/routing/table")
    try:
        existing_rt = rtab.get() or []
    except Exception:  # noqa: BLE001
        existing_rt = []
    ext_names = {_ros_str(t.get("name")) for t in existing_rt}
    for nm in (DUAL_WAN_R_TABLE_1, DUAL_WAN_R_TABLE_2):
        if nm not in ext_names:
            try:
                rtab.add(name=nm, **{"fib": "yes"})
            except Exception as r_exc:  # noqa: BLE001
                logger.info("Could not add routing table %s: %s", nm, sanitize_error_message(str(r_exc)))

    routes = api.get_resource("/ip/route")
    routes.add(
        **{
            "dst-address": "0.0.0.0/0",
            "gateway": g1,
            "routing-table": DUAL_WAN_R_TABLE_1,
            "check-gateway": "ping",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: table {DUAL_WAN_R_TABLE_1}",
        }
    )
    routes.add(
        **{
            "dst-address": "0.0.0.0/0",
            "gateway": g2,
            "routing-table": DUAL_WAN_R_TABLE_2,
            "check-gateway": "ping",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: table {DUAL_WAN_R_TABLE_2}",
        }
    )
    # Also keep main-table defaults so traffic that is not PCC-marked (e.g. certain PPPoE paths)
    # still has internet instead of blackholing when DHCP add-default-route is off.
    routes.add(
        **{
            "dst-address": "0.0.0.0/0",
            "gateway": g1,
            "distance": "1",
            "check-gateway": "ping",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: main {wan1}",
        }
    )
    routes.add(
        **{
            "dst-address": "0.0.0.0/0",
            "gateway": g2,
            "distance": "1",
            "check-gateway": "ping",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: main {wan2}",
        }
    )

    mangle = api.get_resource("/ip/firewall/mangle")
    mangle.add(
        **{
            "chain": "prerouting",
            "in-interface": lan_iface,
            "dst-address-type": "!local",
            "per-connection-classifier": "both-addresses-and-ports:2/0",
            "action": "mark-connection",
            "new-connection-mark": DUAL_WAN_C_MARK_1,
            "passthrough": "yes",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: PCC 2/0",
        }
    )
    mangle.add(
        **{
            "chain": "prerouting",
            "in-interface": lan_iface,
            "dst-address-type": "!local",
            "per-connection-classifier": "both-addresses-and-ports:2/1",
            "action": "mark-connection",
            "new-connection-mark": DUAL_WAN_C_MARK_2,
            "passthrough": "yes",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: PCC 2/1",
        }
    )
    mangle.add(
        **{
            "chain": "prerouting",
            "connection-mark": DUAL_WAN_C_MARK_1,
            "action": "mark-routing",
            "new-routing-mark": DUAL_WAN_R_TABLE_1,
            "passthrough": "no",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: route to {wan1}",
        }
    )
    mangle.add(
        **{
            "chain": "prerouting",
            "connection-mark": DUAL_WAN_C_MARK_2,
            "action": "mark-routing",
            "new-routing-mark": DUAL_WAN_R_TABLE_2,
            "passthrough": "no",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: route to {wan2}",
        }
    )

    natr = api.get_resource("/ip/firewall/nat")
    natr.add(
        **{
            "chain": "srcnat",
            "out-interface": wan1,
            "action": "masquerade",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: NAT {wan1}",
        }
    )
    natr.add(
        **{
            "chain": "srcnat",
            "out-interface": wan2,
            "action": "masquerade",
            "comment": f"{DUAL_WAN_COMMENT_PREFIX}: NAT {wan2}",
        }
    )
    return True, None


def mikrotik_generate_dual_wan_rsc(lan_iface, wan1, wan2, gw1, gw2):
    """RouterOS script for copy/paste; gw values must be your ISP gateway IPs."""
    if not all([lan_iface, wan1, wan2, gw1, gw2]):
        return ""
    return f"""/routing table
add name={DUAL_WAN_R_TABLE_1} fib
add name={DUAL_WAN_R_TABLE_2} fib
/ip route
add dst-address=0.0.0.0/0 gateway={gw1} routing-table={DUAL_WAN_R_TABLE_1} check-gateway=ping
add dst-address=0.0.0.0/0 gateway={gw2} routing-table={DUAL_WAN_R_TABLE_2} check-gateway=ping
/ip firewall mangle
add chain=prerouting in-interface={lan_iface} dst-address-type=!local per-connection-classifier=both-addresses-and-ports:2/0 action=mark-connection new-connection-mark={DUAL_WAN_C_MARK_1} passthrough=yes comment="{DUAL_WAN_COMMENT_PREFIX}: PCC 2/0"
add chain=prerouting in-interface={lan_iface} dst-address-type=!local per-connection-classifier=both-addresses-and-ports:2/1 action=mark-connection new-connection-mark={DUAL_WAN_C_MARK_2} passthrough=yes comment="{DUAL_WAN_COMMENT_PREFIX}: PCC 2/1"
add chain=prerouting connection-mark={DUAL_WAN_C_MARK_1} action=mark-routing new-routing-mark={DUAL_WAN_R_TABLE_1} passthrough=no comment="{DUAL_WAN_COMMENT_PREFIX}: r1"
add chain=prerouting connection-mark={DUAL_WAN_C_MARK_2} action=mark-routing new-routing-mark={DUAL_WAN_R_TABLE_2} passthrough=no comment="{DUAL_WAN_COMMENT_PREFIX}: r2"
/ip firewall nat
add chain=srcnat out-interface={wan1} action=masquerade comment="{DUAL_WAN_COMMENT_PREFIX}: NAT {wan1}"
add chain=srcnat out-interface={wan2} action=masquerade comment="{DUAL_WAN_COMMENT_PREFIX}: NAT {wan2}"
"""


def mikrotik_autodetect_dual_wan_interfaces(api):
    """
    Detect likely uplinks for dual-WAN setup.
    Priority:
      1) Interfaces with bound DHCP clients.
      2) Members of interface list WAN.
      3) Interfaces seen in active default routes (immediate-gw ...%iface).
      4) Fallback to ethernet ports (prefer ether1, ether2 when available).
    """
    candidates = []
    reasons = {}
    lan_iface = "bridge"
    try:
        bridges = api.get_resource("/interface/bridge").get()
        if bridges:
            lan_iface = _ros_str(bridges[0].get("name")) or lan_iface
    except Exception:  # noqa: BLE001
        pass

    def add_candidate(name, reason):
        n = _ros_str(name)
        if not n:
            return
        if n not in reasons:
            reasons[n] = []
        if reason not in reasons[n]:
            reasons[n].append(reason)
        if n not in candidates:
            candidates.append(n)

    try:
        dcs = api.get_resource("/ip/dhcp-client").get()
        for dc in dcs or []:
            iface = _ros_str(dc.get("interface"))
            status = _ros_str(dc.get("status")).lower()
            if iface and status == "bound":
                add_candidate(iface, "dhcp-bound")
        for dc in dcs or []:
            iface = _ros_str(dc.get("interface"))
            if iface and iface not in candidates:
                add_candidate(iface, "dhcp-client")
    except Exception:  # noqa: BLE001
        pass

    try:
        members = api.get_resource("/interface/list/member").get()
        for m in members or []:
            if _ros_str(m.get("list")).upper() == "WAN":
                add_candidate(_ros_str(m.get("interface")), "list-WAN")
    except Exception:  # noqa: BLE001
        pass

    # Existing masquerade out-interfaces are strong WAN hints.
    try:
        nats = api.get_resource("/ip/firewall/nat").get(chain="srcnat")
        for n in nats or []:
            if _ros_str(n.get("disabled")).lower() == "true":
                continue
            if _ros_str(n.get("action")).lower() != "masquerade":
                continue
            outi = _ros_str(n.get("out-interface"))
            if outi:
                add_candidate(outi, "srcnat-out-interface")
    except Exception:  # noqa: BLE001
        pass

    try:
        routes = api.get_resource("/ip/route").get(dst_address="0.0.0.0/0")
        for r in routes or []:
            if _ros_str(r.get("disabled")).lower() == "true":
                continue
            ig = _ros_str(r.get("immediate-gw"))
            if "%" in ig:
                add_candidate(ig.split("%", 1)[1], "default-route")
    except Exception:  # noqa: BLE001
        pass

    try:
        interfaces = api.get_resource("/interface").get()
        ethernet = [_ros_str(i.get("name")) for i in (interfaces or []) if _ros_str(i.get("type")) == "ether"]
    except Exception:  # noqa: BLE001
        ethernet = []

    if not candidates:
        for p in ("ether1", "ether2"):
            if p in ethernet:
                add_candidate(p, "ether-fallback")
        for e in ethernet:
            add_candidate(e, "ether-fallback")

    # Exclude bridge/LAN member interfaces from WAN candidates.
    bridge_members = set()
    try:
        bports = api.get_resource("/interface/bridge/port").get()
        for bp in bports or []:
            iface = _ros_str(bp.get("interface"))
            if iface:
                bridge_members.add(iface)
    except Exception:  # noqa: BLE001
        pass

    if lan_iface in candidates:
        candidates = [c for c in candidates if c != lan_iface]
    candidates = [c for c in candidates if c not in bridge_members]

    unique = []
    for c in candidates:
        if c not in unique:
            unique.append(c)

    # Rank by real WAN usability first, then by candidate source quality.
    ranked = []
    for c in unique:
        snap = mikrotik_wan_link_snapshot(api, c)
        score = 0
        dhcp = _ros_str(snap.get("dhcp_status")).lower()
        if dhcp == "bound":
            score += 50
        if _ros_str(snap.get("gateway")):
            score += 30
        if snap.get("interface_running") is not False:
            score += 10
        if not snap.get("interface_disabled"):
            score += 5
        if snap.get("internet_ok"):
            score += 5
        # Small tie-breaker favoring ether1/ether2 only when equally usable.
        if c == "ether1":
            score += 2
        elif c == "ether2":
            score += 1
        ranked.append((score, c))
    ranked.sort(key=lambda x: x[0], reverse=True)
    preferred = [name for _score, name in ranked]
    reasons["__ranked__"] = [f"{name}:{score}" for score, name in ranked]

    wan1 = preferred[0] if len(preferred) > 0 else "ether1"
    wan2 = preferred[1] if len(preferred) > 1 else ("ether2" if wan1 != "ether2" else "ether3")
    return {
        "lan_iface": lan_iface or "bridge",
        "wan1": wan1,
        "wan2": wan2,
        "candidates": preferred,
        "reasons": reasons,
    }


def _safe_int(value):
    try:
        return int(str(value).strip())
    except Exception:  # noqa: BLE001
        return 0


def dual_wan_distribution_analytics(link1, link2):
    """Compute WAN traffic share from interface byte counters."""
    w1_tx = _safe_int((link1 or {}).get("tx_byte"))
    w1_rx = _safe_int((link1 or {}).get("rx_byte"))
    w2_tx = _safe_int((link2 or {}).get("tx_byte"))
    w2_rx = _safe_int((link2 or {}).get("rx_byte"))
    w1_total = w1_tx + w1_rx
    w2_total = w2_tx + w2_rx
    total = w1_total + w2_total
    if total <= 0:
        return {
            "status": "insufficient_data",
            "message": "No interface traffic counters yet.",
            "wan1_share_pct": 0.0,
            "wan2_share_pct": 0.0,
            "imbalance_pct": 0.0,
            "wan1_total_bytes": w1_total,
            "wan2_total_bytes": w2_total,
            "total_bytes": total,
            "wan1_total_formatted": format_bytes(str(w1_total)),
            "wan2_total_formatted": format_bytes(str(w2_total)),
            "total_formatted": format_bytes(str(total)),
        }
    p1 = (w1_total / total) * 100.0
    p2 = 100.0 - p1
    imbalance = abs(p1 - p2)
    if imbalance <= 10:
        status = "balanced"
        message = "Good balance (~50/50)."
    elif imbalance <= 25:
        status = "moderate_skew"
        message = "Moderate skew; still usable."
    else:
        status = "high_skew"
        message = "High skew. Check link health/routing marks."
    return {
        "status": status,
        "message": message,
        "wan1_share_pct": round(p1, 1),
        "wan2_share_pct": round(p2, 1),
        "imbalance_pct": round(imbalance, 1),
        "wan1_total_bytes": w1_total,
        "wan2_total_bytes": w2_total,
        "total_bytes": total,
        "wan1_total_formatted": format_bytes(str(w1_total)),
        "wan2_total_formatted": format_bytes(str(w2_total)),
        "total_formatted": format_bytes(str(total)),
    }


def mikrotik_detect_active_link_mode(api, wan1, wan2):
    """
    Detect current effective link mode from router rules:
    - dual_active: PCC mangle rules present
    - wan1_fallback: fallback/main route + NAT on WAN1 only
    - wan2_fallback: fallback/main route + NAT on WAN2 only
    - unknown: unable to infer
    """
    mode = "unknown"
    using_links = []
    details = []
    try:
        mangle = api.get_resource("/ip/firewall/mangle").get() or []
        dual_pcc = any(
            DUAL_WAN_COMMENT_PREFIX in _ros_str(r.get("comment"))
            and "PCC" in _ros_str(r.get("comment")).upper()
            for r in mangle
        )
    except Exception:  # noqa: BLE001
        dual_pcc = False
    # Secondary signal: policy-table default routes for both WAN tables exist.
    dual_tables = False
    try:
        routes = api.get_resource("/ip/route").get(dst_address="0.0.0.0/0") or []
        table_names = {_ros_str(r.get("routing-table") or r.get("routing_table")) for r in routes}
        dual_tables = DUAL_WAN_R_TABLE_1 in table_names and DUAL_WAN_R_TABLE_2 in table_names
    except Exception:  # noqa: BLE001
        dual_tables = False
    try:
        nats = api.get_resource("/ip/firewall/nat").get(chain="srcnat") or []
    except Exception:  # noqa: BLE001
        nats = []
    nat_wans = set()
    for n in nats:
        c = _ros_str(n.get("comment"))
        outi = _ros_str(n.get("out-interface"))
        if DUAL_WAN_COMMENT_PREFIX in c and outi:
            nat_wans.add(outi)
        if c == "ISP MTAANI: NAT for PPPoE clients" and outi:
            nat_wans.add(outi)

    if dual_pcc or dual_tables:
        mode = "dual_active"
        using_links = [w for w in [wan1, wan2] if w]
        details.append("Dual-WAN policy rules detected on router.")
    elif wan1 in nat_wans and wan2 not in nat_wans:
        mode = "wan1_fallback"
        using_links = [wan1]
        details.append("Single-WAN NAT detected on WAN1.")
    elif wan2 in nat_wans and wan1 not in nat_wans:
        mode = "wan2_fallback"
        using_links = [wan2]
        details.append("Single-WAN NAT detected on WAN2.")
    elif nat_wans:
        mode = "partial"
        using_links = sorted(nat_wans)
        details.append("NAT rules detected but dual-WAN PCC not fully active.")
    return {
        "mode": mode,
        "using_links": using_links,
        "details": details,
    }


def mikrotik_activate_single_wan_fallback(api, wan_primary):
    """Force single-WAN mode quickly to keep clients online."""
    wan_primary = (wan_primary or "").strip()
    if not wan_primary:
        return False, "Primary WAN is not set."
    mikrotik_dual_wan_cleanup(api)
    gw, gerr = mikrotik_fetch_single_wan_gateway(api, wan_primary)
    if gerr:
        return False, gerr
    try:
        routes = api.get_resource("/ip/route")
        routes.add(
            **{
                "dst-address": "0.0.0.0/0",
                "gateway": gw,
                "distance": "1",
                "check-gateway": "ping",
                "comment": f"{DUAL_WAN_COMMENT_PREFIX}: fallback {wan_primary}",
            }
        )
    except Exception:  # noqa: BLE001
        pass
    mikrotik_ensure_nat_masquerade(api, wan_primary)
    return True, None


def serialize_pppoe_router(row):
    return {
        "id": row["id"],
        "customer_name": row["customer_name"],
        "phone_number": row["phone_number"],
        "pppoe_username": row["pppoe_username"],
        "status": row["status"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        "mikrotik_secret_id": row.get("mikrotik_secret_id"),
        "upload_speed_mbps": float(row.get("upload_speed_mbps")) if row.get("upload_speed_mbps") else None,
        "download_speed_mbps": float(row.get("download_speed_mbps")) if row.get("download_speed_mbps") else None,
        "max_devices": row.get("max_devices", 1),
        "mikrotik_queue_id": row.get("mikrotik_queue_id"),
        "expiration_date": row.get("expiration_date").isoformat() if row.get("expiration_date") else None,
    }


@app.route("/api/routers", methods=["GET", "POST"])
def api_routers():
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    if request.method == "GET":
        # Get selected router_id
        router_id = session.get("selected_router_id")
        if not router_id:
            return jsonify({"error": "No router selected. Please select a router."}), 400
        
        rows = db_list_pppoe_routers(router_id=router_id)
        routers = [serialize_pppoe_router(row) for row in rows]
        
        # Fetch active PPPoE connections to add connection status (with timeout handling)
        creds, error = get_session_router_credentials()
        if not error:
            try:
                active_connections, conn_error = fetch_active_pppoe_connections(creds)
                if conn_error:
                    logger.warning("Connection status fetch error: %s", conn_error)
                for router in routers:
                    username = router.get("pppoe_username", "")
                    router["is_connected"] = username in active_connections if not conn_error else False
                    if router["is_connected"]:
                        conn_info = active_connections.get(username, {})
                        router["connection_address"] = conn_info.get("address", "")
                        router["connection_uptime"] = conn_info.get("uptime", "")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to fetch connection status: %s", sanitize_error_message(str(exc)))
                # Mark all as not connected if fetch fails
                for router in routers:
                    router["is_connected"] = False
        else:
            # If we can't fetch connections, mark all as not connected
            for router in routers:
                router["is_connected"] = False
        
        return jsonify(routers)

    data = request.get_json(force=True, silent=True) or {}
    customer_name = (data.get("customer_name") or "").strip()
    phone_number = (data.get("phone_number") or "").strip()
    pppoe_username = (data.get("pppoe_username") or "").strip()
    pppoe_password = data.get("pppoe_password") or ""

    if not all([customer_name, phone_number, pppoe_username, pppoe_password]):
        return jsonify({"error": "All fields are required."}), 400

    # Check if PPPoE username is already registered to prevent duplication
    # Get selected router_id
    router_id = session.get("selected_router_id")
    if not router_id:
        return jsonify({"error": "No router selected. Please select a router."}), 400
    
    # Check if username already exists for this router
    existing_router = db_get_pppoe_router_by_username(pppoe_username, router_id=router_id)
    if existing_router:
        return jsonify({"error": f"PPPoE username '{pppoe_username}' is already registered on this router."}), 409

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    # Get optional configuration from request or use defaults
    pppoe_interface = (data.get("pppoe_interface") or "bridgeLocal").strip()
    local_address = (data.get("local_address") or "192.168.1.1").strip()
    pool_range = (data.get("pool_range") or "192.168.1.2-192.168.1.254").strip()
    dns_servers = (data.get("dns_servers") or "8.8.8.8,8.8.4.4").strip()
    wan_interface = (data.get("wan_interface") or "").strip() or None

    try:
        # Test connection first with explicit timeout
        timeout_seconds = 10
        socket.setdefaulttimeout(timeout_seconds)
        ok, failure = preflight_connection(creds["host"], creds["port"], timeout_seconds)
        if not ok:
            return jsonify({
                "error": f"Cannot reach MikroTik router at {creds['host']}:{creds['port']}. {failure}. Please verify: 1) Router is powered on and accessible, 2) IP address is correct, 3) API service is enabled on router, 4) Firewall allows connections on port {creds['port']}."
            }), 502
        
        pool, api = get_router_api(creds)
        
        # Test API connection by getting router identity (verifies authentication)
        try:
            identity = api.get_resource("/system/identity").get()
            router_name = identity[0].get("name", "Unknown") if identity else "Unknown"
            logger.info("Successfully connected to MikroTik router: %s", router_name)
        except Exception as test_exc:  # noqa: BLE001
            pool.disconnect()
            error_msg = sanitize_error_message(str(test_exc))
            if "invalid user name or password" in error_msg.lower() or "authentication" in error_msg.lower():
                return jsonify({
                    "error": f"API authentication failed. Please verify the username and password are correct for router {creds['host']}."
                }), 401
            return jsonify({
                "error": f"API connection test failed: {error_msg}. Please check router API settings."
            }), 502
        
        # Auto-configure MikroTik: IP pool, PPP profile, PPPoE server, and NAT
        config_ok, config_error = mikrotik_auto_configure_pppoe(
            api, pppoe_interface, local_address, pool_range, dns_servers, wan_interface
        )
        if not config_ok:
            logger.warning("Auto-configuration warning: %s (continuing anyway)", config_error)
        else:
            logger.info("MikroTik auto-configuration completed successfully")

        # Create the PPPoE secret for this customer
        try:
            secret_id = mikrotik_add_pppoe_secret(api, customer_name, pppoe_username, pppoe_password)
            logger.info("PPPoE secret created successfully for user: %s", pppoe_username)
        except Exception as secret_exc:  # noqa: BLE001
            pool.disconnect()
            error_msg = sanitize_error_message(str(secret_exc))
            if "already exists" in error_msg.lower() or "duplicate" in error_msg.lower():
                return jsonify({
                    "error": f"PPPoE username '{pppoe_username}' already exists on the router. Please use a different username or remove the existing entry from MikroTik."
                }), 409
            return jsonify({
                "error": f"Failed to create PPPoE secret on router: {error_msg}. Please check router configuration and try again."
            }), 502
        
        pool.disconnect()
    except socket.timeout:
        return jsonify({
            "error": f"Connection timeout. The router at {creds['host']}:{creds['port']} did not respond within 10 seconds. Please check: 1) Router is accessible and not overloaded, 2) Network connectivity is stable, 3) Router API is enabled and responding."
        }), 504
    except Exception as exc:  # noqa: BLE001
        error_msg = sanitize_error_message(str(exc))
        if "no response from remote server" in error_msg.lower():
            return jsonify({
                "error": f"No response from MikroTik router at {creds['host']}:{creds['port']}. Please verify: 1) Router IP address is correct, 2) API port is correct (8728 for non-SSL, 8729 for SSL), 3) API service is enabled on router (IP > Services > API), 4) Firewall allows API connections, 5) Router is not overloaded or restarting, 6) SSL setting matches the port (SSL for 8729, non-SSL for 8728)."
            }), 502
        return jsonify({
            "error": f"Cannot connect to MikroTik router: {error_msg}. Please check router connectivity and API settings."
        }), 502

    try:
        router_id = db_insert_pppoe_router(
            {
                "customer_name": customer_name,
                "phone_number": phone_number,
                "pppoe_username": pppoe_username,
                "pppoe_password_encrypted": encrypt_password(pppoe_password),
                "mikrotik_secret_id": secret_id,
                "status": "active",
            }
        )
    except ValueError as ve:
        # Handle duplicate username error from database constraint
        return jsonify({"error": str(ve)}), 409
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Database error: {sanitize_error_message(str(exc))}"}), 500

    return jsonify(
        {
            "message": "Router registered successfully.",
            "router": serialize_pppoe_router(db_get_pppoe_router_by_id(router_id)),
            "pppoe_password": pppoe_password,
        }
    )


@app.route("/api/routers/<int:router_id>", methods=["GET", "PUT", "DELETE"])
def api_router_detail(router_id):
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    router = db_get_pppoe_router_by_id(router_id)
    if not router:
        return jsonify({"error": "Router not found."}), 404

    if request.method == "GET":
        payload = serialize_pppoe_router(router)
        payload["pppoe_password"] = decrypt_password(router["pppoe_password_encrypted"])
        return jsonify(payload)

    if request.method == "DELETE":
        # Verify user belongs to selected router
        selected_router_id = session.get("selected_router_id")
        if not selected_router_id:
            return jsonify({"error": "No router selected. Please select a router."}), 400
        
        user_router_id = router.get("mikrotik_router_id")
        if user_router_id != selected_router_id:
            return jsonify({"error": "User does not belong to selected router. Please select the correct router."}), 403
        
        # Get router credentials for the router that owns this user
        creds, error = get_session_router_credentials()
        if error:
            return jsonify({"error": error}), 401
        
        try:
            pool, api = get_router_api(creds)
            # Remove PPPoE secret from MikroTik if it exists
            if router.get("mikrotik_secret_id"):
                try:
                    mikrotik_remove_pppoe_secret(api, router["mikrotik_secret_id"])
                except Exception as secret_exc:  # noqa: BLE001
                    # Log but continue - secret might already be deleted
                    logger.info("Could not remove PPPoE secret (may already be deleted): %s", sanitize_error_message(str(secret_exc)))
            
            # Remove queue if it exists
            if router.get("mikrotik_queue_id"):
                try:
                    mikrotik_remove_queue(api, router["mikrotik_queue_id"])
                except Exception as queue_exc:  # noqa: BLE001
                    # Log but continue - queue might already be deleted
                    logger.info("Could not remove queue (may already be deleted): %s", sanitize_error_message(str(queue_exc)))
            
            pool.disconnect()
        except Exception as exc:  # noqa: BLE001
            error_msg = sanitize_error_message(str(exc))
            logger.error("Error connecting to MikroTik router during deletion: %s", error_msg)
            # Continue with database deletion even if MikroTik operations fail
            # This allows cleanup of orphaned records
        
        # Delete from database
        try:
            db_delete_pppoe_router(router_id)
            return jsonify({"message": "User deleted successfully."})
        except Exception as db_exc:  # noqa: BLE001
            logger.error("Error deleting user from database: %s", sanitize_error_message(str(db_exc)))
            return jsonify({"error": f"Failed to delete user from database: {sanitize_error_message(str(db_exc))}"}), 500

    data = request.get_json(force=True, silent=True) or {}
    updates = {}
    if data.get("customer_name"):
        updates["customer_name"] = data["customer_name"].strip()
    if data.get("phone_number"):
        updates["phone_number"] = data["phone_number"].strip()
    if data.get("pppoe_username"):
        new_username = data["pppoe_username"].strip()
        if new_username != router.get("pppoe_username"):
            router_id_for_check = router.get("mikrotik_router_id") or session.get("selected_router_id")
            existing_router = db_get_pppoe_router_by_username(new_username, router_id=router_id_for_check)
            if existing_router and existing_router.get("id") != router_id:
                return jsonify({"error": f"PPPoE username '{new_username}' is already registered on this router."}), 409
        updates["pppoe_username"] = new_username
    if data.get("pppoe_password"):
        updates["pppoe_password_encrypted"] = encrypt_password(data["pppoe_password"])
    if "customer_wifi_ssid" in data:
        updates["customer_wifi_ssid"] = (data["customer_wifi_ssid"] or "").strip() or None
    if data.get("customer_wifi_password") is not None:
        updates["customer_wifi_password_encrypted"] = encrypt_password(data["customer_wifi_password"]) if data["customer_wifi_password"] else None

    if not updates:
        return jsonify({"error": "No updates provided."}), 400

    # Only call MikroTik when PPPoE-related fields changed
    pppoe_updates = {k for k in ("customer_name", "pppoe_username", "pppoe_password_encrypted") if k in updates}
    if pppoe_updates:
        creds, error = get_session_router_credentials()
        if error:
            return jsonify({"error": error}), 401
        try:
            pool, api = get_router_api(creds)
            mikrotik_update_pppoe_secret(
                api,
                router.get("mikrotik_secret_id"),
                updates.get("customer_name", router["customer_name"]),
                updates.get("pppoe_username", router["pppoe_username"]),
                data.get("pppoe_password") or decrypt_password(router["pppoe_password_encrypted"]),
            )
            pool.disconnect()
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": sanitize_error_message(str(exc))}), 502

    db_update_pppoe_router(router_id, updates)
    return jsonify({"message": "Router updated."})


@app.route("/api/routers/<int:router_id>/suspend", methods=["POST"])
def api_router_suspend(router_id):
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    router = db_get_pppoe_router_by_id(router_id)
    if not router:
        return jsonify({"error": "Router not found."}), 404

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    try:
        pool, api = get_router_api(creds)
        # Disable the PPPoE secret (prevents new connections)
        mikrotik_set_pppoe_disabled(api, router.get("mikrotik_secret_id"), True)
        
        # Disconnect any active session (immediately cuts off internet)
        username = router.get("pppoe_username", "")
        if username:
            mikrotik_disconnect_pppoe_session(api, username)
        
        pool.disconnect()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": sanitize_error_message(str(exc))}), 502

    db_update_pppoe_router(router_id, {"status": "suspended"})
    return jsonify({"message": "Internet disabled. Active session disconnected."})


@app.route("/api/users/<int:user_id>/toggle", methods=["POST"])
def api_user_toggle(user_id):
    """API endpoint to toggle internet on/off for a user."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    user = db_get_pppoe_router_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    
    # Verify user belongs to selected router
    valid, error_msg = verify_user_belongs_to_router(user)
    if not valid:
        return jsonify({"error": error_msg}), 403

    data = request.get_json(force=True, silent=True) or {}
    enable = data.get("enable", True)
    
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    try:
        pool, api = get_router_api(creds)
        secret_id = user.get("mikrotik_secret_id")
        username = user.get("pppoe_username", "")
        
        if enable:
            # Enable internet access
            if secret_id:
                mikrotik_set_pppoe_disabled(api, secret_id, False)
            db_update_pppoe_router(user_id, {"status": "active"})
            message = "Internet enabled successfully."
        else:
            # Disable internet access
            if secret_id:
                mikrotik_set_pppoe_disabled(api, secret_id, True)
                # Disconnect active session
                if username:
                    mikrotik_disconnect_pppoe_session(api, username)
            db_update_pppoe_router(user_id, {"status": "suspended"})
            message = "Internet disabled. Active session disconnected."
        
        pool.disconnect()
        return jsonify({"message": message, "status": "active" if enable else "suspended"})
    except Exception as exc:  # noqa: BLE001
        logger.info("Error toggling user internet: %s", sanitize_error_message(str(exc)))
        return jsonify({"error": sanitize_error_message(str(exc))}), 502


@app.route("/api/routers/<int:router_id>/activate", methods=["POST"])
def api_router_activate(router_id):
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    router = db_get_pppoe_router_by_id(router_id)
    if not router:
        return jsonify({"error": "Router not found."}), 404

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    try:
        pool, api = get_router_api(creds)
        # Enable the PPPoE secret (allows new connections and reconnections)
        mikrotik_set_pppoe_disabled(api, router.get("mikrotik_secret_id"), False)
        pool.disconnect()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": sanitize_error_message(str(exc))}), 502

    db_update_pppoe_router(router_id, {"status": "active"})
    return jsonify({"message": "Internet enabled. User can now connect."})


@app.route("/api/mikrotik/enforce-pppoe", methods=["POST"])
def api_enforce_pppoe_only():
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    data = request.get_json(force=True, silent=True) or {}
    pppoe_interface = (data.get("pppoe_interface") or "pppoe-in").strip()
    wan_interface = (data.get("wan_interface") or "").strip() or None
    allow_wifi = bool(data.get("allow_wifi", False))  # Default strict PPPoE-only
    always_enforce_pppoe = bool(data.get("always_enforce_pppoe", True))
    wifi_network = (data.get("wifi_network") or "").strip()  # WiFi network range (e.g., "192.168.88.0/24")
    warnings = []

    # Persist requested settings first so user changes are not lost in case router is unreachable.
    try:
        db_set_setting("wan_interface", wan_interface or "")
        db_set_setting("pppoe_interface", pppoe_interface)
        db_set_setting("allow_wifi_access", "1" if allow_wifi else "0")
        db_set_setting("always_enforce_pppoe", "1" if always_enforce_pppoe else "0")
    except Exception:  # noqa: BLE001
        pass

    try:
        pool, api = get_router_api(creds)
        try:
            interfaces = api.get_resource("/interface").get()
            interface_names = {entry.get("name") for entry in interfaces if entry.get("name")}
        except Exception as exc:  # noqa: BLE001
            interface_names = set()
            logger.info("Unable to read interface list: %s", sanitize_error_message(str(exc)))

        wan_interface, wan_interfaces, wan_note = _get_enforcement_wan_targets(api, wan_interface)
        if wan_note:
            warnings.append(wan_note)
        if not wan_interface and not wan_interfaces:
            pool.disconnect()
            return jsonify({
                "error": "WAN interface is required. Enter/select it, or ensure router has NAT/default route for auto-detect.",
                "available_interfaces": sorted(interface_names) if interface_names else [],
            }), 400

        # Accept exact match or any interface starting with pppoe_interface (e.g. pppoe-in matches pppoe-in1, pppoe-in2).
        # Do not hard-fail if not found; enforcement can still work via PPPoE pool network.
        pppoe_ok = (
            pppoe_interface in interface_names
            or any(n.startswith(pppoe_interface) for n in interface_names)
        )
        if interface_names and not pppoe_ok:
            warnings.append(
                f"PPPoE interface '{pppoe_interface}' not found; continuing using PPPoE pool network enforcement."
            )
        if interface_names:
            check_wans = wan_interfaces or ([wan_interface] if wan_interface else [])
            missing_wans = [w for w in check_wans if w and w not in interface_names]
            if missing_wans:
                pool.disconnect()
                return (
                    jsonify(
                        {
                            "error": f"WAN interface(s) not found on MikroTik: {', '.join(missing_wans)}",
                            "available_interfaces": sorted(interface_names),
                        }
                    ),
                    400,
                )

        # Disable DHCP servers to prevent non-PPPoE access (unless WiFi is allowed)
        if not allow_wifi:
            try:
                dhcp_servers = api.get_resource("/ip/dhcp-server")
                servers = dhcp_servers.get()
                for server in servers:
                    if server.get("disabled") != "true":
                        dhcp_servers.set(id=server["id"], disabled="yes")
            except Exception as exc:  # noqa: BLE001
                logger.info("Unable to disable DHCP servers: %s", sanitize_error_message(str(exc)))

        # Get PPPoE pool range to determine network
        pppoe_pool_network = "192.168.1.0/24"  # Default
        try:
            pools = api.get_resource("/ip/pool")
            pppoe_pools = pools.get(name="pppoe-pool")
            if pppoe_pools:
                ranges = pppoe_pools[0].get("ranges", "")
                if ranges:
                    # Extract network from range (e.g., "192.168.1.2-192.168.1.254" -> "192.168.1.0/24")
                    first_ip = ranges.split("-")[0].strip()
                    pppoe_pool_network = first_ip.rsplit(".", 1)[0] + ".0/24"
        except Exception as pool_exc:  # noqa: BLE001
            logger.info("Could not read PPPoE pool, using default: %s", sanitize_error_message(str(pool_exc)))
        
        # Auto-detect WiFi network if not provided and WiFi is allowed
        if allow_wifi and not wifi_network:
            try:
                # Try to get WiFi network from bridge or wireless interface
                addresses = api.get_resource("/ip/address")
                all_addresses = addresses.get()
                
                # Look for common WiFi/bridge networks (not PPPoE pool)
                for addr in all_addresses:
                    addr_str = addr.get("address", "")
                    if addr_str and "/" in addr_str:
                        parts = addr_str.split("/")
                        ip_address = parts[0]
                        cidr_or_mask = parts[1]
                        
                        # Extract network from IP address
                        ip_parts = ip_address.split(".")
                        if len(ip_parts) == 4:
                            # Get first 3 octets for network
                            network_base = ".".join(ip_parts[:3])
                            
                            # Handle CIDR notation (e.g., "192.168.88.1/24")
                            if cidr_or_mask.isdigit():
                                network_cidr = f"{network_base}.0/{cidr_or_mask}"
                            else:
                                # If it's a subnet mask, default to /24 for simplicity
                                network_cidr = f"{network_base}.0/24"
                            
                            # Check if this is different from PPPoE pool (likely WiFi/bridge)
                            if network_cidr != pppoe_pool_network:
                                # Check if it's a common private network
                                first_octet = ip_parts[0]
                                if first_octet in ["192", "10", "172"]:
                                    wifi_network = network_cidr
                                    logger.info("Auto-detected WiFi network: %s", wifi_network)
                                    break
                
                # If still not found, try to get from bridge interface
                if not wifi_network:
                    try:
                        bridges = api.get_resource("/interface/bridge")
                        bridge_list = bridges.get()
                        for bridge in bridge_list:
                            bridge_name = bridge.get("name", "")
                            if bridge_name:
                                # Get IP address for this bridge
                                bridge_addresses = addresses.get(interface=bridge_name)
                                if bridge_addresses:
                                    addr_str = bridge_addresses[0].get("address", "")
                                    if addr_str and "/" in addr_str:
                                        parts = addr_str.split("/")
                                        ip_address = parts[0]
                                        cidr_or_mask = parts[1]
                                        ip_parts = ip_address.split(".")
                                        if len(ip_parts) == 4:
                                            network_base = ".".join(ip_parts[:3])
                                            if cidr_or_mask.isdigit():
                                                network_cidr = f"{network_base}.0/{cidr_or_mask}"
                                            else:
                                                network_cidr = f"{network_base}.0/24"
                                            if network_cidr != pppoe_pool_network:
                                                wifi_network = network_cidr
                                                logger.info("Auto-detected WiFi network from bridge: %s", wifi_network)
                                                break
                    except Exception:  # noqa: BLE001
                        pass
                
                # Default to common MikroTik WiFi network if still not found
                if not wifi_network:
                    wifi_network = "192.168.88.0/24"  # Common MikroTik default
                    logger.info("Using default WiFi network: %s", wifi_network)
                    
            except Exception as wifi_exc:  # noqa: BLE001
                logger.info("Could not auto-detect WiFi network: %s", sanitize_error_message(str(wifi_exc)))
                wifi_network = "192.168.88.0/24"  # Fallback to default
        
        # Ensure NAT masquerade so both PPPoE and WiFi get internet
        try:
            nat_out = wan_interface or (wan_interfaces[0] if wan_interfaces else None)
            mikrotik_ensure_nat_masquerade(api, nat_out)
            if wan_interfaces and len(wan_interfaces) > 1:
                warnings.append(
                    "Dual WAN detected: single PPPoE NAT helper updated primary WAN only; Dual WAN NAT/PCC remains managed in Dual WAN page."
                )
        except Exception as nat_exc:  # noqa: BLE001
            logger.info("NAT setup during enforce-pppoe: %s", sanitize_error_message(str(nat_exc)))
            # Router may have closed the connection; get a fresh one before firewall step
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass
            try:
                pool, api = get_router_api(creds)
            except Exception as reconnect_exc:  # noqa: BLE001
                logger.info("Reconnect after NAT failure: %s", sanitize_error_message(str(reconnect_exc)))
                return jsonify({"error": "NAT update failed and could not reconnect to apply firewall. Try again."}), 502

        # Fix firewall rule to allow PPPoE traffic (and optionally WiFi)
        try:
            mikrotik_fix_firewall_rule(
                api,
                pppoe_pool_network,
                wan_interface or None,
                wan_interfaces=wan_interfaces,
                allow_wifi=allow_wifi,
                wifi_network=wifi_network if allow_wifi else None
            )
        finally:
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        logger.info("PPPoE-only enforcement failed: %s", sanitize_error_message(str(exc)))
        return jsonify({
            "message": "Settings saved, but enforcement could not be applied now because router is unreachable.",
            "applied": False,
            "warnings": warnings + [compact_router_error_message(str(exc))],
        })

    if allow_wifi:
        return jsonify({
            "message": f"MikroTik updated successfully. Both WiFi ({wifi_network}) and PPPoE ({pppoe_pool_network}) can access the internet.",
            "applied": True,
            "warnings": warnings,
        })
    else:
        return jsonify({
            "message": "MikroTik updated to allow internet only via PPPoE.",
            "applied": True,
            "warnings": warnings,
        })


@app.route("/api/mikrotik/interfaces", methods=["GET"])
def api_mikrotik_interfaces():
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    try:
        pool, api = get_router_api(creds)
        interfaces = api.get_resource("/interface").get()
        pool.disconnect()
        names = sorted({entry.get("name") for entry in interfaces if entry.get("name")})
        return jsonify({"interfaces": names})
    except Exception as exc:  # noqa: BLE001
        # Graceful fallback: return saved/manual interface values so Settings remains usable
        # even when live router API is temporarily unreachable.
        fallback = []
        saved_pppoe = (db_get_setting("pppoe_interface", "") or "").strip()
        saved_wan = (db_get_setting("wan_interface", "") or "").strip()
        if saved_pppoe:
            fallback.append(saved_pppoe)
        if saved_wan and saved_wan not in fallback:
            fallback.append(saved_wan)
        return jsonify({
            "interfaces": fallback,
            "warning": f"Could not fetch live interfaces: {compact_router_error_message(str(exc))} You can still type/select saved values and apply settings.",
        })


@app.route("/api/mikrotik/emergency-unblock", methods=["POST"])
def api_mikrotik_emergency_unblock():
    """
    Emergency recovery action for accidental lockout:
    - removes only ISP MTAANI forward-block rules
    - re-enables DHCP servers
    - toggles app defaults to allow WiFi and disable always-enforce
    """
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    removed_count = 0
    dhcp_enabled_count = 0
    target_comments = {
        "ISP MTAANI: block non-PPPoE forward",
        "ISP MTAANI: block non-PPPoE/WiFi forward",
    }
    warnings = []

    # Persist recovery-safe settings first, even if router is currently unreachable.
    try:
        db_set_setting("allow_wifi_access", "1")
        db_set_setting("always_enforce_pppoe", "0")
    except Exception:  # noqa: BLE001
        pass

    try:
        pool, api = get_router_api(creds)
        try:
            filters = api.get_resource("/ip/firewall/filter")
            all_rules = filters.get()
            for rule in all_rules:
                comment = (rule.get("comment") or "").strip()
                if comment in target_comments and rule.get("id"):
                    filters.remove(id=rule["id"])
                    removed_count += 1

            dhcp_servers = api.get_resource("/ip/dhcp-server")
            for server in dhcp_servers.get():
                if server.get("disabled") == "true" and server.get("id"):
                    dhcp_servers.set(id=server["id"], disabled="no")
                    dhcp_enabled_count += 1
        finally:
            try:
                pool.disconnect()
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        logger.info("Emergency unblock failed: %s", sanitize_error_message(str(exc)))
        warnings.append(compact_router_error_message(str(exc)))
        return jsonify({
            "message": "Recovery settings saved, but emergency router changes were not applied because router is unreachable.",
            "applied": False,
            "removed_firewall_rules": removed_count,
            "dhcp_servers_enabled": dhcp_enabled_count,
            "warnings": warnings,
            "settings_updated": {
                "allow_wifi_access": True,
                "always_enforce_pppoe": False,
            },
        })

    return jsonify({
        "message": "Emergency unblock completed. LAN/WiFi access rules have been relaxed.",
        "applied": True,
        "removed_firewall_rules": removed_count,
        "dhcp_servers_enabled": dhcp_enabled_count,
        "warnings": warnings,
        "settings_updated": {
            "allow_wifi_access": True,
            "always_enforce_pppoe": False,
        },
    })


@app.route("/api/mikrotik/fix-nat", methods=["POST"])
def api_fix_nat():
    """Manually fix NAT configuration for internet access."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401

    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401

    data = request.get_json(force=True, silent=True) or {}
    wan_interface = (data.get("wan_interface") or "").strip() or None

    try:
        pool, api = get_router_api(creds)
        
        # Check if router has default route (internet connectivity)
        routes = api.get_resource("/ip/route")
        default_routes = routes.get(dst_address="0.0.0.0/0")
        if not default_routes:
            logger.info("Warning: MikroTik router has no default route. Internet may not work.")
        
        wan_interface, wan_interfaces, _wan_note = _get_enforcement_wan_targets(api, wan_interface)

        # Fix NAT (single-rule helper uses primary WAN)
        mikrotik_ensure_nat_masquerade(api, wan_interface)
        
        # Get PPPoE pool range to determine network
        pppoe_pool_network = "192.168.1.0/24"  # Default
        try:
            pools = api.get_resource("/ip/pool")
            pppoe_pools = pools.get(name="pppoe-pool")
            if pppoe_pools:
                ranges = pppoe_pools[0].get("ranges", "")
                if ranges:
                    # Extract network from range (e.g., "192.168.1.2-192.168.1.254" -> "192.168.1.0/24")
                    first_ip = ranges.split("-")[0].strip()
                    pppoe_pool_network = first_ip.rsplit(".", 1)[0] + ".0/24"
        except Exception as pool_exc:  # noqa: BLE001
            logger.info("Could not read PPPoE pool, using default: %s", sanitize_error_message(str(pool_exc)))
        
        # Fix firewall rule to allow PPPoE traffic
        mikrotik_fix_firewall_rule(api, pppoe_pool_network, wan_interface, wan_interfaces=wan_interfaces)
        
        pool.disconnect()
        return jsonify({
            "message": "NAT and firewall configuration updated. PPPoE clients should now have internet access.",
            "warnings": (["Dual WAN firewall targets applied."] if wan_interfaces and len(wan_interfaces) > 1 else []),
            "warning": "No default route found on router" if not default_routes else None
        })
    except Exception as exc:  # noqa: BLE001
        logger.info("NAT fix failed: %s", sanitize_error_message(str(exc)))
        return jsonify({"error": sanitize_error_message(str(exc))}), 502


@app.route("/dual-wan")
def dual_wan_page():
    if not require_session():
        return redirect(url_for("login"))
    router_id = session.get("selected_router_id")
    if not router_id:
        return redirect(url_for("routers_page"))
    lan = (db_get_setting("dual_wan_lan", "") or "").strip() or "bridge"
    w1 = (db_get_setting("dual_wan_wan1", "") or "").strip() or "ether1"
    w2 = (db_get_setting("dual_wan_wan2", "") or "").strip() or "ether2"
    fallback_mode = (db_get_setting("dual_wan_fallback_mode", "auto") or "auto").strip().lower()
    if fallback_mode not in {"auto", "strict"}:
        fallback_mode = "auto"
    auto_pick = (db_get_setting("dual_wan_auto_pick", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
    return render_template(
        "dual_wan.html",
        lan_iface=lan,
        wan1=w1,
        wan2=w2,
        fallback_mode=fallback_mode,
        auto_pick=auto_pick,
    )


@app.route("/api/mikrotik/dual-wan/status", methods=["GET"])
def api_dual_wan_status():
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401
    try:
        pool, api = get_router_api(creds)
        try:
            w1 = (db_get_setting("dual_wan_wan1", "") or "").strip() or "ether1"
            w2 = (db_get_setting("dual_wan_wan2", "") or "").strip() or "ether2"
            fallback_mode = (db_get_setting("dual_wan_fallback_mode", "auto") or "auto").strip().lower()
            if fallback_mode not in {"auto", "strict"}:
                fallback_mode = "auto"
            auto_pick = (db_get_setting("dual_wan_auto_pick", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
            auto_updated = False
            detected = None
            if auto_pick:
                try:
                    detected = mikrotik_autodetect_dual_wan_interfaces(api)
                except Exception:  # noqa: BLE001
                    detected = None
                if detected:
                    dw1 = (detected.get("wan1") or "").strip()
                    dw2 = (detected.get("wan2") or "").strip()
                    dlan = (detected.get("lan_iface") or "").strip() or "bridge"
                    if dw1 and dw2 and (dw1 != w1 or dw2 != w2):
                        w1, w2 = dw1, dw2
                        try:
                            db_set_setting("dual_wan_lan", dlan)
                            db_set_setting("dual_wan_wan1", w1)
                            db_set_setting("dual_wan_wan2", w2)
                            auto_updated = True
                        except Exception:  # noqa: BLE001
                            pass
            link1 = mikrotik_wan_link_snapshot(api, w1)
            link2 = mikrotik_wan_link_snapshot(api, w2)
            dual_enabled = (db_get_setting("dual_wan_enabled", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}
            # Auto-adjust: if dual mode is enabled but WAN2 is not usable, switch to WAN1 fallback.
            if dual_enabled and fallback_mode == "auto" and (not mikrotik_is_wan_usable(link2)):
                ok_fb, fb_err = mikrotik_activate_single_wan_fallback(api, w1)
                if ok_fb:
                    try:
                        db_set_setting("dual_wan_enabled", "0")
                        db_set_setting("wan_interface", w1)
                    except Exception:  # noqa: BLE001
                        pass
                    # refresh snapshots after fallback
                    link1 = mikrotik_wan_link_snapshot(api, w1)
                    link2 = mikrotik_wan_link_snapshot(api, w2)
                elif fb_err:
                    logger.info("Dual-WAN auto-fallback skipped: %s", fb_err)
            analytics = dual_wan_distribution_analytics(link1, link2)
            link_mode = mikrotik_detect_active_link_mode(api, w1, w2)
            lan = (db_get_setting("dual_wan_lan", "") or "").strip() or "bridge"
            # Read-only gateway discovery (do not toggle DHCP on every poll)
            g1 = _gw_from_default_routes_for_iface(api, w1) or _gw_from_dhcp_client(api, w1)
            g2 = _gw_from_default_routes_for_iface(api, w2) or _gw_from_dhcp_client(api, w2)
            rsc = mikrotik_generate_dual_wan_rsc(lan, w1, w2, g1, g2) if g1 and g2 else ""
        finally:
            pool.disconnect()
        return jsonify(
            {
                "wan1": link1,
                "wan2": link2,
                "gateways": {"wan1": g1, "wan2": g2},
                "rsc": rsc,
                "analytics": analytics,
                "link_mode": link_mode,
                "active_config": {
                    "lan_iface": lan,
                    "wan1": w1,
                    "wan2": w2,
                    "fallback_mode": fallback_mode,
                    "auto_pick": auto_pick,
                },
                "auto_updated": auto_updated,
                "autodetect_debug": detected.get("reasons") if auto_pick and detected else None,
            }
        )
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": sanitize_error_message(str(exc))}), 502


@app.route("/api/mikrotik/dual-wan/settings", methods=["POST"])
def api_dual_wan_settings():
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    if not session.get("selected_router_id"):
        return jsonify({"error": "No router selected."}), 400
    data = request.get_json(force=True, silent=True) or {}
    lan = (data.get("lan_iface") or data.get("lan") or "").strip() or "bridge"
    w1 = (data.get("wan1") or data.get("wan1_interface") or "").strip() or "ether1"
    w2 = (data.get("wan2") or data.get("wan2_interface") or "").strip() or "ether2"
    fallback_mode = (data.get("fallback_mode") or "auto").strip().lower()
    if fallback_mode not in {"auto", "strict"}:
        fallback_mode = "auto"
    auto_pick = bool(data.get("auto_pick", True))
    try:
        db_set_setting("dual_wan_lan", lan)
        db_set_setting("dual_wan_wan1", w1)
        db_set_setting("dual_wan_wan2", w2)
        db_set_setting("dual_wan_fallback_mode", fallback_mode)
        db_set_setting("dual_wan_auto_pick", "1" if auto_pick else "0")
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": sanitize_error_message(str(exc))}), 500
    return jsonify(
        {
            "ok": True,
            "lan_iface": lan,
            "wan1": w1,
            "wan2": w2,
            "fallback_mode": fallback_mode,
            "auto_pick": auto_pick,
        }
    )


@app.route("/api/mikrotik/dual-wan/autodetect", methods=["POST"])
def api_dual_wan_autodetect():
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401
    try:
        pool, api = get_router_api(creds)
        try:
            detected = mikrotik_autodetect_dual_wan_interfaces(api)
        finally:
            pool.disconnect()
        db_set_setting("dual_wan_lan", detected["lan_iface"])
        db_set_setting("dual_wan_wan1", detected["wan1"])
        db_set_setting("dual_wan_wan2", detected["wan2"])
        return jsonify({"ok": True, **detected})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": sanitize_error_message(str(exc))}), 502


@app.route("/api/mikrotik/dual-wan/apply", methods=["POST"])
def api_dual_wan_apply():
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401
    data = request.get_json(force=True, silent=True) or {}
    lan = (data.get("lan_iface") or db_get_setting("dual_wan_lan", "") or "").strip() or "bridge"
    w1 = (data.get("wan1") or db_get_setting("dual_wan_wan1", "") or "").strip() or "ether1"
    w2 = (data.get("wan2") or db_get_setting("dual_wan_wan2", "") or "").strip() or "ether2"
    fallback_mode = (data.get("fallback_mode") or db_get_setting("dual_wan_fallback_mode", "auto") or "auto").strip().lower()
    if fallback_mode not in {"auto", "strict"}:
        fallback_mode = "auto"
    auto_pick = bool(data.get("auto_pick", (db_get_setting("dual_wan_auto_pick", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}))
    try:
        pool, api = get_router_api(creds)
        try:
            if auto_pick:
                try:
                    detected = mikrotik_autodetect_dual_wan_interfaces(api)
                except Exception:  # noqa: BLE001
                    detected = None
                if detected:
                    lan = (detected.get("lan_iface") or lan or "bridge").strip() or "bridge"
                    w1 = (detected.get("wan1") or w1).strip() or "ether1"
                    w2 = (detected.get("wan2") or w2).strip() or "ether2"
                    try:
                        db_set_setting("dual_wan_lan", lan)
                        db_set_setting("dual_wan_wan1", w1)
                        db_set_setting("dual_wan_wan2", w2)
                    except Exception:  # noqa: BLE001
                        pass
            # If WAN2 is unavailable, automatically fall back to WAN1-only to keep clients online.
            w2_snapshot = mikrotik_wan_link_snapshot(api, w2)
            w2_ready = mikrotik_is_wan_usable(w2_snapshot)
            if not w2_ready:
                if fallback_mode == "strict":
                    return jsonify(
                        {
                            "ok": False,
                            "error": "Strict dual mode is enabled, but WAN2 is not usable (need DHCP bound + gateway + running). Fix WAN2 or switch to Auto fallback mode.",
                        }
                    ), 400
                ok_fb, fb_err = mikrotik_activate_single_wan_fallback(api, w1)
                if not ok_fb:
                    return jsonify({"ok": False, "error": f"WAN2 is unavailable and WAN1 fallback failed: {fb_err or 'unknown error'}"}), 400
                try:
                    db_set_setting("dual_wan_enabled", "0")
                    db_set_setting("wan_interface", w1)
                    db_set_setting("dual_wan_fallback_mode", fallback_mode)
                    db_set_setting("dual_wan_auto_pick", "1" if auto_pick else "0")
                except Exception:  # noqa: BLE001
                    pass
                reason = []
                if _ros_str(w2_snapshot.get("dhcp_status")).lower() != "bound":
                    reason.append("DHCP not bound")
                if not _ros_str(w2_snapshot.get("gateway")):
                    reason.append("missing gateway")
                if w2_snapshot.get("interface_running") is False:
                    reason.append("interface not running")
                if w2_snapshot.get("interface_disabled"):
                    reason.append("interface disabled")
                reason_text = ", ".join(reason) if reason else "WAN2 unusable"
                return jsonify(
                    {
                        "ok": True,
                        "fallback": True,
                        "message": f"WAN2 is not available ({reason_text}). Automatically switched to WAN1 ({w1}) only.",
                    }
                )

            ok, err = mikrotik_apply_dual_wan_pcc(api, lan, w1, w2)
        finally:
            pool.disconnect()
        if not ok:
            return jsonify({"ok": False, "error": err or "Apply failed."}), 400
        try:
            db_set_setting("dual_wan_enabled", "1")
            db_set_setting("wan_interface", w1)
            db_set_setting("dual_wan_fallback_mode", fallback_mode)
            db_set_setting("dual_wan_auto_pick", "1" if auto_pick else "0")
        except Exception:  # noqa: BLE001
            pass
        return jsonify(
            {
                "ok": True,
                "message": "PCC load balancing, policy routes, and NAT for both WANs were applied on the router.",
                "active_config": {
                    "lan_iface": lan,
                    "wan1": w1,
                    "wan2": w2,
                    "fallback_mode": fallback_mode,
                    "auto_pick": auto_pick,
                },
            }
        )
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": sanitize_error_message(str(exc))}), 502


@app.route("/api/mikrotik/dual-wan/cleanup", methods=["POST"])
def api_dual_wan_cleanup():
    """Remove only ISP MTAANI DUAL-WAN rules (mangle, NAT, routes, tables)."""
    if not require_session():
        return jsonify({"error": "Login required."}), 401
    creds, error = get_session_router_credentials()
    if error:
        return jsonify({"error": error}), 401
    try:
        pool, api = get_router_api(creds)
        try:
            mikrotik_dual_wan_cleanup(api)
        finally:
            pool.disconnect()
        try:
            db_set_setting("dual_wan_enabled", "0")
        except Exception:  # noqa: BLE001
            pass
        return jsonify({"ok": True, "message": "Dual-WAN rules removed from the router."})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": sanitize_error_message(str(exc))}), 502


if __name__ == "__main__":
    ensure_db_and_tables()
    # Use a longer request timeout so slow MikroTik operations don't trigger "Request timed out"
    request_timeout = 120
    try:
        request_timeout = int(os.getenv("REQUEST_TIMEOUT", "120"))
    except (TypeError, ValueError):
        pass

    try:
        from werkzeug.serving import WSGIRequestHandler

        class LongTimeoutRequestHandler(WSGIRequestHandler):
            def handle(self):
                if hasattr(self, "connection") and self.connection:
                    try:
                        self.connection.settimeout(request_timeout)
                    except Exception:  # noqa: BLE001
                        pass
                super().handle()

        _request_handler = LongTimeoutRequestHandler
    except Exception:  # noqa: BLE001
        _request_handler = None

    run_kw = {
        "host": "0.0.0.0",
        "port": int(os.getenv("PORT", "5000")),
        "debug": True,
    }
    if _request_handler is not None:
        run_kw["request_handler"] = _request_handler
    app.run(**run_kw)

