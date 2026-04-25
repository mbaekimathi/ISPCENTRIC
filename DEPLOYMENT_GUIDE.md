# Deployment Guide: Hosting on cPanel

## Overview

This guide explains how to deploy the ISP MTAANI system on cPanel and ensure it can connect to MikroTik routers remotely.

## Key Question: Will It Work When Users Are Not on WiFi/LAN?

### ✅ YES - Users Can Access the Web Interface from Anywhere

- Users accessing the web interface (http://yourdomain.com) can do so from anywhere in the world
- They just need internet access and a web browser
- This is standard web application behavior

### ⚠️ CRITICAL - The cPanel Server Must Reach the MikroTik Router

The **web server** (on cPanel) needs network connectivity to your MikroTik router's IP address. This is the critical requirement.

## Network Connectivity Scenarios

### Scenario 1: MikroTik Has Public IP Address ✅ EASIEST

**Setup:**
- MikroTik router has a public IP address (e.g., 203.0.113.50)
- RouterOS API port (8728 or 8729) is accessible from the internet
- Firewall allows connections from cPanel server's IP

**Configuration:**
```
Management IP: 203.0.113.50
API Port: 8728 (or 8729 for SSL)
Use SSL: Yes/No (match your router config)
```

**Pros:**
- Simple setup
- Works immediately
- No additional infrastructure needed

**Cons:**
- Security risk (RouterOS API exposed to internet
- Must use strong passwords and firewall rules
- Consider using SSL (port 8729)

### Scenario 2: MikroTik on Private Network with Port Forwarding ✅ COMMON

**Setup:**
- MikroTik router has private IP (e.g., 192.168.1.1)
- Router has public IP on WAN interface
- Port forwarding configured on upstream router/firewall
- Forward external port → MikroTik IP:8728

**Configuration:**
```
Management IP: [Public IP of upstream router]
API Port: [External forwarded port, e.g., 20828]
Use SSL: Recommended (port 8729)
```

**Pros:**
- Router stays on private network
- More secure than direct public IP
- Common setup for ISPs

**Cons:**
- Requires port forwarding configuration
- Need to manage firewall rules

### Scenario 3: VPN Connection Between cPanel Server and MikroTik ✅ MOST SECURE

**Setup:**
- MikroTik router on private network
- VPN tunnel between cPanel server and MikroTik network
- cPanel server connects via VPN IP address

**Configuration:**
```
Management IP: [VPN IP of MikroTik, e.g., 10.0.0.1]
API Port: 8728
Use SSL: Recommended
```

**Pros:**
- Most secure option
- RouterOS API not exposed to internet
- Encrypted connection

**Cons:**
- Requires VPN setup and maintenance
- More complex configuration
- Additional infrastructure needed

### Scenario 4: Same Network (cPanel Server and MikroTik) ✅ LOCAL ONLY

**Setup:**
- Both cPanel server and MikroTik on same network
- Direct LAN connectivity

**Configuration:**
```
Management IP: [Local IP, e.g., 192.168.1.1]
API Port: 8728
Use SSL: Optional
```

**Pros:**
- Simple and fast
- No internet exposure

**Cons:**
- Only works if cPanel server is on same network
- Not suitable for remote hosting

## Security Recommendations

### 1. Use SSL for RouterOS API
- Enable SSL on MikroTik RouterOS API (port 8729)
- Set `use_ssl: true` in your configuration
- Encrypts all API communications

### 2. Firewall Rules
- Restrict RouterOS API access to specific IP addresses
- Only allow connections from your cPanel server's IP
- Block all other IPs

**MikroTik Firewall Rule Example:**
```
/ip/firewall/filter add chain=input protocol=tcp dst-port=8729 action=accept src-address=[cPanel Server IP] place-before=0
/ip/firewall/filter add chain=input protocol=tcp dst-port=8729 action=drop
```

### 3. Strong Passwords
- Use complex passwords for RouterOS API users
- Change default admin password
- Use different passwords for different routers

### 4. IP Whitelisting
- Configure MikroTik to only accept API connections from trusted IPs
- Use firewall rules to restrict access

## cPanel Deployment Steps

### 1. Upload Application Files
- Upload all files to your cPanel hosting directory
- Ensure Python/Flask is supported (may need VPS or dedicated server)

### 2. Configure Database
- Create MySQL database in cPanel
- Update `DB_CONFIG` in `app.py` or use environment variables:
  ```python
  DB_HOST = "localhost"  # or your MySQL host
  DB_USER = "your_db_user"
  DB_PASSWORD = "your_db_password"
  DB_NAME = "isp_mtaani"
  ```

### 3. Install Python Dependencies
- Install required packages via SSH or cPanel Python app:
  ```
  pip install flask pymysql routeros-api cryptography
  ```

### 4. Configure Environment Variables
Set these in cPanel or `.env` file:
```
DB_HOST=localhost
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=isp_mtaani
FLASK_SECRET_KEY=your-secret-key
MIKROTIK_CRED_KEY=your-encryption-key
```

### 5. Test Connectivity
- Test connection from cPanel server to MikroTik router
- Use SSH to test: `telnet [mikrotik_ip] 8728`
- Should connect successfully

### 6. Configure Web Server
- Set up Python application in cPanel
- Configure WSGI if needed
- Point domain to application directory

## Testing Remote Access

### Test 1: Can Users Access Web Interface?
- Open browser from any location
- Navigate to `http://yourdomain.com`
- Should load login page ✅

### Test 2: Can Server Connect to MikroTik?
- Log into the application
- Try to register/view a MikroTik router
- Check for connection errors
- If errors, verify network connectivity

### Test 3: Network Path Verification
From cPanel server (via SSH):
```bash
# Test if MikroTik IP is reachable
ping [mikrotik_ip]

# Test if API port is open
telnet [mikrotik_ip] 8728
# or
nc -zv [mikrotik_ip] 8728
```

## Troubleshooting

### Issue: "Unable to reach router"
**Causes:**
- Firewall blocking connection
- Router not accessible from cPanel server IP
- Wrong IP address or port
- Network routing issue

**Solutions:**
- Check firewall rules on MikroTik
- Verify IP address and port
- Test connectivity from cPanel server
- Check if router has public IP or needs VPN

### Issue: "Connection timeout"
**Causes:**
- RouterOS API not enabled
- Port blocked by firewall
- Network routing problem

**Solutions:**
- Enable RouterOS API on MikroTik
- Check firewall rules
- Verify port forwarding (if applicable)

### Issue: "Invalid credentials"
**Causes:**
- Wrong username/password
- User doesn't have API access
- SSL mismatch (using SSL on non-SSL port)

**Solutions:**
- Verify credentials
- Check user permissions in MikroTik
- Match SSL setting with port (8728=no SSL, 8729=SSL)

## Recommended Architecture

```
┌─────────────────┐
│  Users (Anywhere) │
│  (Web Browser)   │
└────────┬─────────┘
         │ HTTPS
         │
┌────────▼─────────┐
│  cPanel Server    │
│  (Your App)       │
└────────┬─────────┘
         │ RouterOS API
         │ (Port 8728/8729)
         │
┌────────▼─────────┐
│  MikroTik Router │
│  (Management IP) │
└──────────────────┘
```

## Summary

✅ **Users can access the web interface from anywhere** - standard web app behavior

⚠️ **The cPanel server MUST be able to reach the MikroTik router** - this is the critical requirement

🔒 **Use VPN or firewall restrictions** for security

📡 **Public IP, Port Forwarding, or VPN** - choose based on your network setup

## Quick Checklist

- [ ] cPanel server can reach MikroTik router IP
- [ ] RouterOS API is enabled on MikroTik
- [ ] Firewall allows connections from cPanel server IP
- [ ] Correct IP address and port configured
- [ ] SSL settings match (if using SSL)
- [ ] Database configured and accessible
- [ ] Python dependencies installed
- [ ] Application files uploaded
- [ ] Test connection from cPanel server to MikroTik













