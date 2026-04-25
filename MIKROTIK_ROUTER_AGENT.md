# MikroTik Router-Based Agent Implementation

## ✅ YES - Agent Can Run Directly in MikroTik Router!

This is actually **BETTER** than a PC-based agent because:
- ✅ Router is always on (no separate PC needed)
- ✅ Router knows its own network configuration
- ✅ Always available when router is online
- ✅ Can push updates automatically
- ✅ No additional hardware required

---

## Architecture: Router as Agent

### Flow Diagram:
```
[Web Client] → [cPanel Server] ← HTTP ← [MikroTik Router Agent]
                                           ↓
                                    [Local Network Access]
                                    (192.168.1.1, etc.)
```

**Key Point:** The router **initiates** the connection to your server, so:
- ✅ No firewall issues (outbound HTTP from router)
- ✅ No port forwarding needed
- ✅ Works with private IPs
- ✅ Server never needs to reach router directly

---

## How It Works

### 1. Router Self-Registration
Router runs a script that:
- Gets its own identity and network info
- Makes HTTP POST to your server
- Registers itself automatically
- Sends credentials (encrypted) and network details

### 2. Periodic Heartbeat/Updates
Router periodically:
- Checks its own status
- Gets network information
- Sends updates to server
- Keeps connection alive

### 3. Server Queries Router
When web app needs router data:
- Server stores router's callback URL or uses polling
- Router can expose local API endpoints
- Or router pushes data when changes occur

### 4. Proxy Mode (Optional)
Router can proxy requests:
- Web app → Server → Router Agent → Local Network
- Router acts as bridge for local network access

---

## RouterOS Scripting Capabilities

### What RouterOS Can Do:

1. **HTTP Client**
   ```routeros
   /tool fetch url="https://yourserver.com/api/agent/register" \
       http-method=post \
       http-header-field="Content-Type: application/json" \
       http-data="{\"router_name\":\"Main Router\",\"ip\":\"192.168.1.1\"}"
   ```

2. **Scheduled Scripts**
   ```routeros
   /system scheduler add name="agent-heartbeat" \
       interval=5m \
       on-event="/system script run agent-heartbeat"
   ```

3. **System Information**
   ```routeros
   /system identity print
   /system resource print
   /ip address print
   /interface print
   ```

4. **JSON Parsing** (RouterOS v7+)
   - Can parse JSON responses
   - Can build JSON payloads

5. **Variables and Logic**
   - Store data in variables
   - Conditional logic
   - Loops and functions

---

## Implementation Options

### Option 1: RouterOS Script (Recommended)

**Pros:**
- ✅ Native to RouterOS
- ✅ No additional software
- ✅ Works on all RouterOS versions
- ✅ Lightweight

**Cons:**
- ⚠️ Limited scripting capabilities
- ⚠️ No complex libraries
- ⚠️ JSON handling can be tricky

**Example Script:**
```routeros
# RouterOS Script: agent-register.rsc
:local serverUrl "https://yourserver.com/api/agent/router-register"
:local routerName [/system identity get name]
:local routerIP [/ip address get [find interface="bridgeLocal"] address]
:local apiPort 8728
:local apiUser "admin"
:local apiPass "your-password"

# Build JSON payload
:local jsonData ("{\"router_name\":\"" . $routerName . "\",\"ip\":\"" . $routerIP . "\",\"port\":" . $apiPort . "}")

# Send to server
/tool fetch url=$serverUrl \
    http-method=post \
    http-header-field="Content-Type: application/json" \
    http-data=$jsonData \
    dst-path=register-response.txt

# Read response
:local response [/file get register-response.txt contents]
:put $response
```

### Option 2: RouterOS Package (Advanced)

**Pros:**
- ✅ Full programming capabilities
- ✅ Can use Python/Node.js if installed
- ✅ More powerful

**Cons:**
- ⚠️ Requires additional packages
- ⚠️ More complex setup
- ⚠️ May not work on all devices

### Option 3: Hybrid Approach

**RouterOS Script + Server-Side Processing:**
- Router sends basic info via script
- Server processes and stores
- Router polls server for commands
- Server sends commands via HTTP response

---

## Server API Endpoints

### 1. Router Self-Registration
```
POST /api/agent/router-register
Body: {
    "router_name": "Main Router",
    "ip": "192.168.1.1",
    "port": 8728,
    "use_ssl": false,
    "username": "admin",
    "password": "encrypted_password",
    "identity": {...},
    "network_info": {...}
}
Response: {
    "success": true,
    "router_id": 123,
    "agent_token": "abc123..."
}
```

### 2. Router Heartbeat/Status Update
```
POST /api/agent/router-heartbeat
Headers: {
    "X-Agent-Token": "abc123..."
}
Body: {
    "router_id": 123,
    "status": "online",
    "uptime": "5d 3h 2m",
    "network_info": {...}
}
Response: {
    "success": true,
    "commands": [...]  // Optional: commands for router to execute
}
```

### 3. Get Router Status (Server Query)
```
GET /api/agent/router-status/:router_id
Response: {
    "router_id": 123,
    "status": "online",
    "last_heartbeat": "2024-01-15T10:30:00Z",
    "network_info": {...}
}
```

### 4. Send Command to Router (Push Mode)
```
POST /api/agent/router-command
Body: {
    "router_id": 123,
    "command": "get_pppoe_active",
    "params": {}
}
Response: {
    "queued": true,
    "command_id": 456
}
```
*(Router polls for commands in heartbeat response)*

---

## RouterOS Script Examples

### Example 1: Initial Registration Script

```routeros
# File: /system script add name="agent-register" source={

:local serverUrl "https://yourserver.com/api/agent/router-register"
:local apiKey "your-api-key-here"

# Get router identity
:local routerName [/system identity get name]
:local routerModel [/system resource get board-name]
:local routerVersion [/system resource get version]

# Get management IP (first bridge or ethernet)
:local mgmtIP ""
:do {
    :local ipAddr [/ip address get [find interface~"bridge|ether"] address]
    :set mgmtIP [:pick $ipAddr 0 [:find $ipAddr "/"]]
} on-error={
    :set mgmtIP "unknown"
}

# Get API port (check if SSL enabled)
:local apiPort 8728
:local useSSL false
:if ([/ip service get api-ssl disabled] = false) do={
    :set apiPort 8729
    :set useSSL true
}

# Build JSON payload
:local jsonData ("{\"router_name\":\"" . $routerName . "\",\"ip\":\"" . $mgmtIP . "\",\"port\":" . $apiPort . ",\"use_ssl\":" . ($useSSL ? "true" : "false") . ",\"model\":\"" . $routerModel . "\",\"version\":\"" . $routerVersion . "\"}")

# Send registration
:do {
    /tool fetch url=($serverUrl . "?api_key=" . $apiKey) \
        http-method=post \
        http-header-field="Content-Type: application/json" \
        http-data=$jsonData \
        dst-path=register-response.txt
    
    :local response [/file get register-response.txt contents]
    :put "Registration response: $response"
} on-error={
    :put "Registration failed: $error"
}

#}
```

### Example 2: Heartbeat Script

```routeros
# File: /system script add name="agent-heartbeat" source={

:local serverUrl "https://yourserver.com/api/agent/router-heartbeat"
:local agentToken "your-agent-token-from-registration"
:local routerId 123

# Get router status
:local uptime [/system resource get uptime]
:local cpuLoad [/system resource get cpu-load]
:local freeMemory [/system resource get free-memory]
:local totalMemory [/system resource get total-memory]

# Get active PPPoE connections count
:local pppoeActive 0
:do {
    :set pppoeActive [/ppp active print count-only]
} on-error={
    :set pppoeActive 0
}

# Build JSON payload
:local jsonData ("{\"router_id\":" . $routerId . ",\"status\":\"online\",\"uptime\":\"" . $uptime . "\",\"cpu_load\":" . $cpuLoad . ",\"memory_free\":" . $freeMemory . ",\"memory_total\":" . $totalMemory . ",\"pppoe_active\":" . $pppoeActive . "}")

# Send heartbeat
:do {
    /tool fetch url=$serverUrl \
        http-method=post \
        http-header-field=("Content-Type: application/json") \
        http-header-field=("X-Agent-Token: " . $agentToken) \
        http-data=$jsonData \
        dst-path=heartbeat-response.txt
    
    # Check for commands in response
    :local response [/file get heartbeat-response.txt contents]
    :put "Heartbeat sent. Response: $response"
    
    # TODO: Parse response and execute commands if any
    
} on-error={
    :put "Heartbeat failed: $error"
}

#}
```

### Example 3: Scheduled Task Setup

```routeros
# Run registration once on startup
/system scheduler add name="agent-register-once" \
    start-time=startup \
    on-event="/system script run agent-register"

# Run heartbeat every 5 minutes
/system scheduler add name="agent-heartbeat" \
    interval=5m \
    on-event="/system script run agent-heartbeat"

# Run heartbeat on startup (after 30 seconds)
/system scheduler add name="agent-heartbeat-startup" \
    start-time=startup \
    start-date=jan/01/1970 \
    on-event={
        :delay 30s
        /system script run agent-heartbeat
    }
```

---

## Server Implementation

### 1. Registration Endpoint

```python
@app.route("/api/agent/router-register", methods=["POST"])
def agent_router_register():
    """Router self-registers via agent script."""
    data = request.get_json(force=True, silent=True) or {}
    api_key = request.args.get("api_key")
    
    # Verify API key (optional but recommended)
    if not verify_agent_api_key(api_key):
        return jsonify({"error": "Invalid API key"}), 401
    
    router_name = data.get("router_name", "Unknown")
    ip = data.get("ip")
    port = data.get("port", 8728)
    use_ssl = data.get("use_ssl", False)
    
    # Check if router already registered
    existing = db_get_mikrotik_router_by_ip(ip, port)
    
    if existing:
        # Update existing router
        router_id = existing["id"]
        db_update_mikrotik_router(router_id, {
            "status": "ACTIVE",
            "last_heartbeat": datetime.now(),
            "agent_registered": True
        })
    else:
        # Create new router entry
        router_id = db_insert_mikrotik_router({
            "router_name": router_name,
            "management_ip": ip,
            "api_port": port,
            "use_ssl": use_ssl,
            "api_username": data.get("username", ""),
            "api_password_encrypted": encrypt_password(data.get("password", "")),
            "status": "ACTIVE",
            "agent_registered": True,
            "agent_token": generate_agent_token()
        })
    
    router = db_get_mikrotik_router_by_id(router_id)
    
    return jsonify({
        "success": True,
        "router_id": router_id,
        "agent_token": router["agent_token"],
        "message": "Router registered successfully"
    })
```

### 2. Heartbeat Endpoint

```python
@app.route("/api/agent/router-heartbeat", methods=["POST"])
def agent_router_heartbeat():
    """Router sends periodic heartbeat."""
    agent_token = request.headers.get("X-Agent-Token")
    if not agent_token:
        return jsonify({"error": "Missing agent token"}), 401
    
    # Verify token and get router
    router = db_get_mikrotik_router_by_agent_token(agent_token)
    if not router:
        return jsonify({"error": "Invalid agent token"}), 401
    
    data = request.get_json(force=True, silent=True) or {}
    
    # Update router status
    db_update_mikrotik_router(router["id"], {
        "status": "ACTIVE",
        "last_heartbeat": datetime.now(),
        "uptime": data.get("uptime"),
        "cpu_load": data.get("cpu_load"),
        "memory_free": data.get("memory_free"),
        "memory_total": data.get("memory_total")
    })
    
    # Check for pending commands
    commands = db_get_pending_commands(router["id"])
    
    return jsonify({
        "success": True,
        "commands": commands  # Router will execute these
    })
```

### 3. Database Schema Updates

```sql
ALTER TABLE routers ADD COLUMN agent_registered BOOLEAN DEFAULT FALSE;
ALTER TABLE routers ADD COLUMN agent_token VARCHAR(255) NULL;
ALTER TABLE routers ADD COLUMN last_heartbeat DATETIME NULL;
ALTER TABLE routers ADD COLUMN uptime VARCHAR(50) NULL;
ALTER TABLE routers ADD COLUMN cpu_load DECIMAL(5,2) NULL;
ALTER TABLE routers ADD COLUMN memory_free BIGINT NULL;
ALTER TABLE routers ADD COLUMN memory_total BIGINT NULL;

-- Optional: Command queue table
CREATE TABLE IF NOT EXISTS router_commands (
    id INT AUTO_INCREMENT PRIMARY KEY,
    router_id INT NOT NULL,
    command VARCHAR(100) NOT NULL,
    params JSON NULL,
    status ENUM('pending', 'executed', 'failed') DEFAULT 'pending',
    result JSON NULL,
    created_at DATETIME NOT NULL,
    executed_at DATETIME NULL,
    FOREIGN KEY (router_id) REFERENCES routers(id)
);
```

---

## Advantages of Router-Based Agent

### ✅ Benefits:

1. **Always Available**
   - Router is always on
   - No separate PC needed
   - Automatic operation

2. **Self-Contained**
   - Router knows its own configuration
   - No network scanning needed
   - Direct access to local network

3. **Outbound Connection**
   - Router initiates connection to server
   - No firewall issues
   - No port forwarding needed
   - Works with private IPs

4. **Real-Time Updates**
   - Router can push status changes
   - Immediate notification of events
   - Better than polling

5. **Secure**
   - Agent token authentication
   - Encrypted credentials
   - No exposure of router to internet

6. **Scalable**
   - Each router is independent
   - No single point of failure
   - Easy to add more routers

---

## Comparison: PC Agent vs Router Agent

| Feature | PC Agent | Router Agent |
|---------|----------|--------------|
| **Availability** | PC must be on | Router always on |
| **Setup** | Install on PC | Script in router |
| **Network Access** | Scans network | Direct access |
| **Connection** | Agent → Server | Router → Server |
| **Maintenance** | Update PC software | Update router script |
| **Reliability** | Depends on PC | Depends on router |
| **Cost** | Requires PC | No extra hardware |

**Winner: Router Agent** ✅

---

## Implementation Steps

### Step 1: Create RouterOS Scripts
- Registration script
- Heartbeat script
- Command execution script (optional)

### Step 2: Add Server Endpoints
- `/api/agent/router-register`
- `/api/agent/router-heartbeat`
- `/api/agent/router-command` (optional)

### Step 3: Update Database
- Add agent-related columns
- Create command queue table (optional)

### Step 4: Update Connection Logic
- Check if router is agent-registered
- Use agent token for authentication
- Handle agent vs direct connection

### Step 5: Create Installation Guide
- RouterOS script installation steps
- Scheduler setup
- Testing procedures

---

## Security Considerations

### ✅ Security Features:

1. **API Key Authentication**
   - Router must provide API key for registration
   - Prevents unauthorized registrations

2. **Agent Token**
   - Unique token per router
   - Used for heartbeat authentication
   - Rotatable if compromised

3. **HTTPS Only**
   - All communication over HTTPS
   - Encrypts credentials in transit

4. **Encrypted Storage**
   - Credentials encrypted in database
   - Same encryption as current system

5. **Rate Limiting**
   - Limit heartbeat frequency
   - Prevent abuse

---

## Example: Complete Registration Flow

### 1. Router Executes Script
```routeros
/system script run agent-register
```

### 2. Script Sends Registration
```
POST https://yourserver.com/api/agent/router-register?api_key=xxx
{
    "router_name": "Main Router",
    "ip": "192.168.1.1",
    "port": 8728,
    "use_ssl": false
}
```

### 3. Server Responds
```json
{
    "success": true,
    "router_id": 123,
    "agent_token": "abc123def456..."
}
```

### 4. Router Stores Token
```routeros
:local agentToken "abc123def456..."
/system script environment set agent-token=$agentToken
```

### 5. Router Starts Heartbeat
```routeros
/system scheduler enable agent-heartbeat
```

### 6. Periodic Updates
```
Every 5 minutes:
POST /api/agent/router-heartbeat
Headers: X-Agent-Token: abc123def456...
```

---

## Testing

### Test 1: Registration
1. Run registration script on router
2. Check server logs for registration
3. Verify router appears in database
4. Check agent_token is generated

### Test 2: Heartbeat
1. Wait for scheduled heartbeat
2. Check server receives heartbeat
3. Verify last_heartbeat updated
4. Check router status is ACTIVE

### Test 3: Web App Access
1. Login to web app
2. Router should appear in list
3. Select router
4. Verify can access router data

---

## Troubleshooting

### Router Not Registering
- Check API key is correct
- Verify server URL is reachable from router
- Check router has internet access
- Review script syntax

### Heartbeat Not Working
- Verify scheduler is enabled
- Check agent_token is set
- Review server logs
- Test HTTP connectivity from router

### Web App Can't Access Router
- Check router is agent-registered
- Verify agent_token is valid
- Check last_heartbeat is recent
- Review connection logic

---

## Next Steps

1. **Create RouterOS Scripts** - Registration and heartbeat
2. **Add Server Endpoints** - Handle agent communications
3. **Update Database** - Add agent columns
4. **Test Registration** - Verify router can register
5. **Test Heartbeat** - Verify periodic updates work
6. **Update Web App** - Support agent-registered routers

---

## Conclusion

**YES, having the agent in the MikroTik router is the BEST solution!**

It's better than a PC-based agent because:
- ✅ Router is always on
- ✅ No additional hardware
- ✅ Self-contained
- ✅ More reliable
- ✅ Easier to maintain

The router initiates the connection, so:
- ✅ No firewall issues
- ✅ No port forwarding
- ✅ Works with private IPs
- ✅ Secure and scalable

Would you like me to implement this? I can create:
1. RouterOS scripts (registration, heartbeat)
2. Server API endpoints
3. Database schema updates
4. Installation guide





