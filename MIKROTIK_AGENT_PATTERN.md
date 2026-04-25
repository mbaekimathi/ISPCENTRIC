# MikroTik Router Access via Local Agent Pattern

## ✅ YES - You Can Use the Local Agent Pattern for MikroTik Access!

The Local Agent Pattern you used for printer discovery is **perfectly applicable** to MikroTik router access. In fact, it solves the exact same problem: **cPanel server cannot reach devices on private networks**.

---

## The Problem (Same as Printers)

### Current Limitation:
```
[Your Browser] → [cPanel Server] → ❌ Cannot reach → [MikroTik Router on 192.168.1.1]
```

**Why it fails:**
- cPanel server is on public internet
- MikroTik router is on private network (192.168.x.x, 10.x.x.x)
- Private IPs are not routable from internet
- cPanel blocks direct TCP connections to local networks

---

## The Solution: Local Agent for MikroTik

### Architecture:
```
[Local Network] → [Local Agent] → [Internet] → [cPanel Server] → [Web Client]
                      ↓
              [MikroTik Router]
              (192.168.1.1:8728)
```

### How It Works:

1. **Local Agent Discovery**
   - Agent runs on PC in same network as MikroTik
   - Scans local network for MikroTik routers
   - Tests RouterOS API port (8728/8729) on each IP
   - Discovers routers automatically

2. **Agent-to-Server Communication**
   - Agent sends discovered routers to `/api/agent/mikrotik-found`
   - Server stores router info in database
   - Includes: IP, port, credentials (encrypted), router identity

3. **Client Access**
   - Web client calls `/api/agent/mikrotik-routers` (GET)
   - Server returns routers discovered by agent
   - Client can select and use router

4. **Proxy Mode (Optional)**
   - For real-time operations, agent can proxy API requests
   - Client → Server → Agent → MikroTik → Agent → Server → Client
   - Agent acts as bridge between server and router

---

## Implementation Components

### 1. Local Agent Script (`scan_mikrotik_agent.py`)

**Features:**
- Network detection (gets local IP, extracts network prefix)
- Scans IP range (e.g., 192.168.1.1-254) for RouterOS API
- Tests ports 8728 (non-SSL) and 8729 (SSL)
- Attempts authentication with provided credentials
- Sends discovered routers to server

**Example:**
```python
# Agent discovers router at 192.168.1.1:8728
# Tests connection and authentication
# Sends to server:
POST /api/agent/mikrotik-found
{
    "ip": "192.168.1.1",
    "port": 8728,
    "use_ssl": false,
    "username": "admin",
    "password": "encrypted_password",
    "router_name": "RouterOS-ABC123",
    "identity": {...}
}
```

### 2. Server API Endpoints

**Receive Router Discoveries:**
```
POST /api/agent/mikrotik-found
Body: {
    "ip": "192.168.1.1",
    "port": 8728,
    "use_ssl": false,
    "username": "admin",
    "password": "encrypted",
    "router_name": "Main Router",
    "identity": {...}
}
Response: {"success": true, "router_id": 123}
```

**Get Discovered Routers:**
```
GET /api/agent/mikrotik-routers
Response: [
    {
        "id": 123,
        "name": "Main Router",
        "ip": "192.168.1.1",
        "port": 8728,
        "status": "active",
        "discovered_by_agent": true
    }
]
```

**Proxy API Request (Optional):**
```
POST /api/agent/mikrotik-proxy
Body: {
    "router_id": 123,
    "api_path": "/ppp/active",
    "method": "GET",
    "params": {}
}
Response: {...router response...}
```

### 3. Database Changes

**Add agent discovery tracking:**
```sql
ALTER TABLE routers ADD COLUMN discovered_by_agent BOOLEAN DEFAULT FALSE;
ALTER TABLE routers ADD COLUMN agent_discovered_at DATETIME NULL;
ALTER TABLE routers ADD COLUMN agent_ip VARCHAR(45) NULL;
```

---

## Use Cases

### Use Case 1: Automatic Router Discovery
**Scenario:** Router is on private network, you want to register it automatically.

**Flow:**
1. Run agent on PC in same network
2. Agent scans and discovers router
3. Agent sends router info to server
4. Router appears in web app automatically
5. You can use it immediately

### Use Case 2: Remote Access via Agent
**Scenario:** Router is registered but cPanel can't reach it directly.

**Flow:**
1. Router registered with private IP (192.168.1.1)
2. Agent runs on local network
3. Agent proxies API requests from server
4. Web app works as if server connected directly

### Use Case 3: Hybrid Mode
**Scenario:** Some routers have public IPs, others are private.

**Flow:**
1. Server tries direct connection first
2. If fails (private IP), check if agent discovered it
3. If agent available, use agent proxy
4. Seamless fallback for user

---

## Comparison: Printer Agent vs MikroTik Agent

| Feature | Printer Agent | MikroTik Agent |
|---------|--------------|----------------|
| **Discovery** | Scan ports 9100, 9101, 9102, 515, 631 | Scan ports 8728, 8729 |
| **Test Method** | TCP connection + ESC/POS command | RouterOS API connection + authentication |
| **Data Sent** | Printer IP, port, model | Router IP, port, credentials, identity |
| **Storage** | `printer_scan_results.json` | Database (`routers` table) |
| **Usage** | Print jobs | Full router management |
| **Proxy Mode** | Optional (print queue polling) | Recommended (real-time API) |

---

## Advantages of Agent Pattern for MikroTik

### ✅ Benefits:

1. **Works with Private IPs**
   - No need for public IPs or port forwarding
   - Router can stay on private network

2. **Automatic Discovery**
   - Agent finds routers automatically
   - No manual IP entry needed

3. **Secure**
   - Credentials encrypted before sending
   - Agent only runs when needed
   - No permanent exposure of router

4. **Flexible**
   - Can work alongside direct connections
   - Fallback mechanism for reliability

5. **No Network Changes Required**
   - No router configuration changes
   - No firewall rules on router
   - Works with existing setup

---

## Implementation Steps

### Step 1: Create Agent Script
- Network scanning logic
- RouterOS API connection testing
- Authentication verification
- Server communication

### Step 2: Add Server Endpoints
- `/api/agent/mikrotik-found` (POST)
- `/api/agent/mikrotik-routers` (GET)
- `/api/agent/mikrotik-proxy` (POST) - Optional

### Step 3: Update Router Connection Logic
- Check if router is agent-discovered
- Try direct connection first
- Fallback to agent proxy if needed

### Step 4: Update Web UI
- Show "Agent Discovered" badge
- Display agent status
- Option to refresh discovery

---

## Security Considerations

### ✅ Security Features:

1. **Encrypted Credentials**
   - Agent encrypts passwords before sending
   - Server stores encrypted credentials
   - Same encryption as current implementation

2. **Agent Authentication** (Optional)
   - Require API key for agent requests
   - Prevent unauthorized agents
   - Rate limiting

3. **Network Isolation**
   - Agent only accesses local network
   - No internet exposure of router
   - Router stays behind firewall

4. **Temporary Access**
   - Agent can run on-demand
   - No permanent connection required
   - Router not exposed when agent offline

---

## Example Agent Script Structure

```python
# scan_mikrotik_agent.py

import socket
import routeros_api
from requests import post
import json

def get_local_network():
    # Connect to 8.8.8.8 to get local IP
    # Extract network prefix (e.g., "192.168.1")
    pass

def scan_for_mikrotik(ip_range, ports=[8728, 8729]):
    # Scan IP range for RouterOS API
    # Test each IP:port combination
    # Return list of discovered routers
    pass

def test_router_connection(ip, port, use_ssl, username, password):
    # Connect to RouterOS API
    # Test authentication
    # Get router identity
    # Return router info
    pass

def send_to_server(router_info):
    # POST to /api/agent/mikrotik-found
    # Include encrypted credentials
    pass

if __name__ == "__main__":
    # Main discovery loop
    pass
```

---

## When to Use Agent vs Direct Connection

### Use Agent When:
- ✅ Router is on private network (192.168.x.x, 10.x.x.x)
- ✅ No public IP or port forwarding available
- ✅ Router is behind firewall/NAT
- ✅ You want automatic discovery

### Use Direct Connection When:
- ✅ Router has public IP
- ✅ Port forwarding is configured
- ✅ Router is on VPN accessible to server
- ✅ Better performance needed (no proxy overhead)

### Use Hybrid (Both):
- ✅ Best of both worlds
- ✅ Automatic fallback
- ✅ Works with any router setup

---

## Next Steps

1. **Review this document** - Understand the pattern
2. **Decide on implementation** - Agent discovery only, or also proxy mode?
3. **Create agent script** - Based on printer agent pattern
4. **Add server endpoints** - Handle agent communications
5. **Update connection logic** - Support agent-discovered routers
6. **Test thoroughly** - Verify with real routers

---

## Questions to Consider

1. **Discovery Only or Full Proxy?**
   - Discovery: Agent finds router, server uses stored credentials
   - Proxy: Agent forwards all API requests in real-time

2. **Agent Authentication?**
   - Should agents authenticate with server?
   - API key or user credentials?

3. **Multiple Agents?**
   - Can multiple agents discover same router?
   - How to handle conflicts?

4. **Agent Status?**
   - How to know if agent is online?
   - What if agent goes offline?

---

## Conclusion

**YES, the Local Agent Pattern is perfect for MikroTik router access!**

It solves the same problem you solved for printers:
- ✅ Works with private networks
- ✅ No network configuration changes
- ✅ Automatic discovery
- ✅ Secure credential handling

The implementation follows the same pattern:
1. Local agent discovers routers
2. Agent sends info to server
3. Server stores router details
4. Web app uses routers (via agent proxy if needed)

Would you like me to implement this? I can create:
- Agent script (`scan_mikrotik_agent.py`)
- Server API endpoints
- Updated connection logic
- Database schema changes





