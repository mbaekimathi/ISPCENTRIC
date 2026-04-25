# Remote Access Setup Guide

## Problem: System Works Locally But Not When Hosted

When you run the system locally (connected to MikroTik WiFi), it works perfectly. But when you host it on cPanel or any remote server, you can't register or login to MikroTik routers.

**Root Cause:** The cPanel server cannot reach your MikroTik router because:
- The router is on a private network (192.168.x.x, 10.x.x.x)
- Private IPs are only accessible on the local network
- Remote servers cannot connect to private IPs over the internet

---

## Solution Options

### ✅ Option 1: Use Public IP Address (Recommended)

**Best for:** Routers with direct internet connection and public IP

**Steps:**
1. Find your MikroTik router's public IP address
   - Check on the router: `/ip address print` (look for WAN interface)
   - Or check from a device: Visit `https://whatismyipaddress.com/` while connected to the router
2. Configure MikroTik firewall to allow API access from your cPanel server:
   ```
   /ip firewall filter add chain=input protocol=tcp dst-port=8728 action=accept \
     src-address=<YOUR_CPANEL_SERVER_IP> comment="Allow API from cPanel"
   ```
3. Use the public IP when registering/login:
   - Management IP: `203.0.113.50` (your actual public IP)
   - Port: `8728` or `8729` (SSL)
   - Enable SSL (port 8729) for security when exposing API to internet

**Security Note:** ⚠️ Exposing RouterOS API to the internet is a security risk. Always:
- Use SSL (port 8729)
- Use strong passwords
- Restrict firewall to only allow your cPanel server IP
- Consider using Option 3 (VPN) for better security

---

### ✅ Option 2: Port Forwarding

**Best for:** Routers behind another router/gateway

**Steps:**
1. On your upstream router/gateway, configure port forwarding:
   - External Port: `20828` (or any available port)
   - Internal IP: `192.168.1.1` (your MikroTik's private IP)
   - Internal Port: `8728`
   - Protocol: `TCP`

2. Find your upstream router's public IP address

3. Configure MikroTik firewall to allow API:
   ```
   /ip firewall filter add chain=input protocol=tcp dst-port=8728 action=accept \
     src-address=<YOUR_CPANEL_SERVER_IP> comment="Allow API from cPanel"
   ```

4. Use the forwarded address when registering:
   - Management IP: `<UPSTREAM_ROUTER_PUBLIC_IP>`
   - Port: `20828` (the forwarded port, not 8728)
   - Use SSL: `False` (unless you forward 8729)

**Example:**
- Upstream router public IP: `203.0.113.50`
- Port forwarding: `20828 → 192.168.1.1:8728`
- In registration form: IP = `203.0.113.50`, Port = `20828`

---

### ✅ Option 3: VPN Connection (Most Secure)

**Best for:** Maximum security and routers on private networks

**Setup Steps:**

#### A. Configure MikroTik as VPN Server

1. Create VPN pool:
   ```
   /ip pool add name=VPN-Pool ranges=10.0.0.2-10.0.0.254
   ```

2. Create VPN profile:
   ```
   /ppp profile add name=VPN-Profile local-address=10.0.0.1 remote-address=VPN-Pool
   ```

3. Create VPN user for cPanel server:
   ```
   /ppp secret add name=cpanel-server password=<STRONG_PASSWORD> \
     profile=VPN-Profile service=pptp
   ```

4. Enable PPTP server:
   ```
   /interface pptp-server server set enabled=yes
   ```

5. Configure firewall to allow VPN:
   ```
   /ip firewall filter add chain=input protocol=tcp dst-port=1723 action=accept \
     comment="Allow PPTP VPN"
   /ip firewall filter add chain=input protocol=gre action=accept \
     comment="Allow GRE for PPTP"
   ```

#### B. Connect cPanel Server to VPN

**If cPanel is on VPS/Dedicated Server:**
1. Install VPN client (PPTP or OpenVPN)
2. Connect to MikroTik VPN using the credentials above
3. Once connected, use the VPN IP address:
   - Management IP: `10.0.0.1` (MikroTik's VPN IP)
   - Port: `8728` or `8729`
   - Use SSL: Recommended

**If cPanel is on Shared Hosting:**
- ⚠️ Most shared hosting providers don't allow VPN connections
- You'll need to upgrade to VPS or use Option 1/2

---

## Testing Connectivity

### Before Registration/Login

1. **Use the "Test Connection" button** in the registration/login form
   - Enter the IP and port
   - Click "Test Connection"
   - The system will tell you if the server can reach the router

2. **Test from cPanel Server (SSH):**
   ```bash
   # Test if port is reachable
   telnet <MIKROTIK_IP> 8728
   # or
   nc -zv <MIKROTIK_IP> 8728
   ```

3. **Check RouterOS API is enabled:**
   ```
   /ip service print
   # Should show "api" with port 8728 or 8729 enabled
   ```

### Common Issues

#### ❌ "Connection Timeout"
- **Cause:** Server cannot reach router
- **Solutions:**
  - Verify IP address is correct (public IP, not private)
  - Check firewall allows connections from cPanel server IP
  - Ensure RouterOS API is enabled
  - Test connectivity from server first

#### ❌ "Connection Refused"
- **Cause:** Port is blocked or API not enabled
- **Solutions:**
  - Enable RouterOS API: `/ip service enable api`
  - Check firewall rules
  - Verify port number (8728 or 8729)

#### ❌ "Private IP Warning"
- **Cause:** Using 192.168.x.x, 10.x.x.x, or 172.16-31.x.x
- **Solutions:**
  - Use public IP address
  - Set up port forwarding
  - Configure VPN connection

---

## Quick Checklist

Before registering a router on a remote server:

- [ ] Router has a way to be reached from the internet (public IP, port forwarding, or VPN)
- [ ] RouterOS API is enabled on the router
- [ ] Firewall allows connections from cPanel server IP
- [ ] Using correct IP address (public IP, not private)
- [ ] Port number matches SSL setting (8728=no SSL, 8729=SSL)
- [ ] Tested connectivity using "Test Connection" button
- [ ] Tested from server using `telnet` or `nc` command

---

## Security Best Practices

1. **Always use SSL** when exposing API to internet (port 8729)
2. **Restrict firewall** to only allow your cPanel server IP
3. **Use strong passwords** for API users
4. **Consider VPN** for maximum security
5. **Regularly update** RouterOS firmware
6. **Monitor access logs** for unauthorized attempts

---

## Network Architecture Examples

### Example 1: Direct Public IP
```
Internet → MikroTik Router (203.0.113.50:8729) ← cPanel Server
```
- Management IP: `203.0.113.50`
- Port: `8729` (SSL)
- Firewall: Allow only cPanel server IP

### Example 2: Port Forwarding
```
Internet → Upstream Router (203.0.113.50:20828) → Port Forward → MikroTik (192.168.1.1:8728) ← cPanel Server
```
- Management IP: `203.0.113.50`
- Port: `20828`
- Upstream router forwards to: `192.168.1.1:8728`

### Example 3: VPN
```
Internet → VPN Tunnel → MikroTik (10.0.0.1:8729) ← cPanel Server (via VPN)
```
- Management IP: `10.0.0.1` (VPN IP)
- Port: `8729` (SSL)
- cPanel server connects via VPN first

---

## Need Help?

If you're still having issues:

1. **Check the error message** - The system now provides detailed diagnostics
2. **Use "Test Connection"** - This will tell you exactly what's wrong
3. **Verify network setup** - Ensure router is reachable from server
4. **Check firewall rules** - Both on MikroTik and upstream router
5. **Contact hosting support** - Ask if outbound connections to ports 8728/8729 are allowed

---

## Summary

**The key to making this work remotely is ensuring your cPanel server can reach your MikroTik router.**

- ✅ **Works:** Public IP, port forwarding, or VPN
- ❌ **Doesn't work:** Private IPs (192.168.x.x) without port forwarding/VPN

The system now includes:
- ⚠️ Automatic detection of private IPs with warnings
- 🔍 Connection test utility
- 📝 Detailed error messages with troubleshooting guidance
- 🛡️ Better security recommendations

Use these features to diagnose and fix connectivity issues!




