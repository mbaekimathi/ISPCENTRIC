# Best Setup for HostPinnacle cPanel

## Recommended Option: **VPN Connection** (Most Secure & Reliable)

### Why VPN is Best for HostPinnacle cPanel:

1. **Security**: RouterOS API not exposed to internet
2. **Reliability**: Stable connection regardless of network changes
3. **Compatibility**: Works with shared hosting, VPS, or dedicated servers
4. **No Port Forwarding**: Don't need to configure complex firewall rules
5. **Private Network**: MikroTik stays on private network

## Setup Steps for HostPinnacle:

### Step 1: Check Your HostPinnacle Plan

**If you have VPS or Dedicated Server:**
- ✅ Full control over network configuration
- ✅ Can install VPN client/server
- ✅ Best option for this application

**If you have Shared Hosting:**
- ⚠️ Limited network control
- ⚠️ May need to use **Option 2: Port Forwarding** instead
- ⚠️ Contact HostPinnacle support to confirm outbound connection support

### Step 2: Set Up VPN (Recommended)

#### Option A: MikroTik as VPN Server (Best)

1. **Configure MikroTik as L2TP/IPsec or SSTP Server:**
   ```
   /interface l2tp-server server set enabled=yes
   /ip pool add name=VPN-Pool ranges=10.0.0.2-10.0.0.254
   /ppp profile add name=VPN-Profile local-address=10.0.0.1 remote-address=VPN-Pool
   /ppp secret add name=vpn-user password=strong-password profile=VPN-Profile
   ```

2. **On HostPinnacle Server (if VPS):**
   - Connect to MikroTik VPN
   - Use VPN IP (e.g., 10.0.0.1) as Management IP in your app

3. **Configure Application:**
   ```
   Management IP: 10.0.0.1 (VPN IP)
   API Port: 8728
   Use SSL: Yes (recommended)
   ```

#### Option B: Third-Party VPN Service

- Use services like ZeroTier, Tailscale, or WireGuard
- Create virtual network between HostPinnacle server and MikroTik
- Connect via virtual IP addresses

### Step 3: Alternative - Port Forwarding (If VPN Not Possible)

**If VPN setup is not possible, use Port Forwarding:**

1. **On Your Router/Upstream Device:**
   - Forward external port (e.g., 20828) → MikroTik IP:8728
   - Or forward 20829 → MikroTik IP:8729 (for SSL)

2. **Configure Application:**
   ```
   Management IP: [Your Public IP or Domain]
   API Port: 20828 (or 20829 for SSL)
   Use SSL: Yes (highly recommended)
   ```

3. **Security:**
   - Restrict access to HostPinnacle server IP only
   - Use strong passwords
   - Enable SSL (port 8729)

## HostPinnacle-Specific Considerations:

### 1. Python/Flask Support

**Check with HostPinnacle:**
- Do they support Python applications?
- Is Flask/Python available in cPanel?
- Do you need VPS for Python apps?

**If Python not available:**
- Consider converting to PHP (would require code rewrite)
- Or upgrade to VPS plan

### 2. Database Access

**MySQL/MariaDB:**
- Should be available in cPanel
- Create database via cPanel MySQL wizard
- Update connection settings in app

### 3. Network Connectivity

**Test from HostPinnacle Server:**
```bash
# SSH into your HostPinnacle server
telnet [mikrotik_ip] 8728
# or
nc -zv [mikrotik_ip] 8728
```

**If connection fails:**
- Check firewall rules
- Verify MikroTik IP is reachable
- May need VPN or port forwarding

### 4. File Permissions

**Ensure proper permissions:**
```bash
chmod 755 app.py
chmod 644 templates/*.html
chmod 600 data/fernet.key  # If using file-based encryption
```

## Quick Decision Guide:

### ✅ Use VPN If:
- You have VPS or dedicated server
- You want maximum security
- You have multiple MikroTik routers
- You want stable, reliable connection

### ✅ Use Port Forwarding If:
- You have shared hosting
- VPN setup is complex
- You have single MikroTik router
- You can configure firewall rules

### ✅ Use Public IP If:
- MikroTik has static public IP
- You have strong firewall rules
- You need simplest setup
- Security is less concern

## Recommended Configuration for HostPinnacle:

```
┌─────────────────────┐
│  HostPinnacle cPanel│
│  (Your Flask App)   │
└──────────┬──────────┘
           │ VPN Connection
           │ (10.0.0.1:8729)
           │
┌──────────▼──────────┐
│  MikroTik Router    │
│  (Private Network)  │
└─────────────────────┘
```

## Security Checklist:

- [ ] Use SSL for RouterOS API (port 8729)
- [ ] Strong passwords for API users
- [ ] Firewall rules restricting access
- [ ] VPN encryption enabled
- [ ] Regular security updates
- [ ] Monitor connection logs

## Testing After Deployment:

1. **Test Web Interface:**
   - Access from any location
   - Should load login page

2. **Test MikroTik Connection:**
   - Log into application
   - Try to view/register router
   - Check for connection errors

3. **Test Network Path:**
   - From HostPinnacle server: `ping [mikrotik_vpn_ip]`
   - From HostPinnacle server: `telnet [mikrotik_vpn_ip] 8729`

## Contact HostPinnacle Support:

**Ask them:**
1. Do you support Python/Flask applications?
2. Can I make outbound connections to port 8728/8729?
3. Do you allow VPN connections?
4. What are the network restrictions?
5. Do I need VPS for this application?

## Summary:

**BEST OPTION: VPN Connection**
- Most secure
- Works with any hosting type
- Stable and reliable
- No internet exposure

**FALLBACK: Port Forwarding with SSL**
- If VPN not possible
- Requires firewall configuration
- Less secure but functional

**LAST RESORT: Public IP**
- Only if MikroTik has public IP
- Requires strict firewall rules
- Less secure













