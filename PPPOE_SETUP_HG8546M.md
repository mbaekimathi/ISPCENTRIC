# PPPoE Setup Guide for Huawei HG8546M Router

## Overview
This guide will help you configure your Huawei HG8546M router to connect to the internet using PPPoE (Point-to-Point Protocol over Ethernet).

## Prerequisites
- Your PPPoE username (provided by your ISP)
- Your PPPoE password (provided by your ISP)
- An Ethernet cable connected from your ISP's network to the HG8546M router
- Access to the router's web interface

---

## Step 1: Access Router Web Interface

1. **Connect to the router:**
   - Connect your computer to the router via Ethernet cable (LAN port) or Wi-Fi
   - Default IP: `192.168.1.1` or `192.168.100.1`
   - Open a web browser and navigate to: `http://192.168.1.1`

2. **Login:**
   - Default username: `root` or `admin`
   - Default password: `admin` or check the sticker on your router
   - If you've changed these, use your custom credentials

---

## Step 2: Navigate to WAN Settings

1. **Find Internet/WAN Settings:**
   - Look for menu items like:
     - **"Internet"** or **"WAN"**
     - **"Network"** → **"WAN"**
     - **"Advanced"** → **"WAN Settings"**
     - **"Broadband Settings"**

2. **Select WAN Connection:**
   - Find your current WAN connection (usually named "WAN" or "Internet")
   - Click **"Edit"** or **"Modify"**

---

## Step 3: Configure PPPoE Connection

1. **Connection Type:**
   - Change **Connection Type** to: **"PPPoE"** or **"PPPoE/Routed"**
   - If you see "Bridge" or "IPoE", change it to PPPoE

2. **Enter PPPoE Credentials:**
   - **Username:** Enter your PPPoE username (e.g., `0712345678`)
   - **Password:** Enter your PPPoE password
   - **Service Name:** Leave blank (or enter if provided by ISP)

3. **Connection Mode:**
   - Select **"Always On"** or **"Auto Connect"**
   - This ensures automatic reconnection if the connection drops

4. **Authentication:**
   - **Authentication Protocol:** Select **"PAP"** or **"PAP/CHAP"**
   - Most ISPs use PAP, but CHAP is also supported

---

## Step 4: Configure IP Settings (if needed)

1. **IP Address:**
   - Usually set to **"Obtain Automatically"** or **"DHCP"**
   - Some ISPs may require static IP (rare)

2. **DNS Settings:**
   - **Primary DNS:** `8.8.8.8` (Google) or use ISP's DNS
   - **Secondary DNS:** `8.8.4.4` (Google) or use ISP's DNS
   - Or select **"Obtain Automatically"**

---

## Step 5: Save and Apply Settings

1. **Save Configuration:**
   - Click **"Save"** or **"Apply"**
   - Wait for the router to save settings (10-30 seconds)

2. **Verify Connection:**
   - The router will attempt to connect automatically
   - Look for connection status indicators:
     - **Green light** or **"Connected"** status
     - **IP address** assigned (check WAN status page)

---

## Step 6: Verify Internet Access

1. **Check Connection Status:**
   - Go to **"Status"** or **"Device Info"** page
   - Look for **"WAN IP Address"** - should show a public IP
   - Connection status should show **"Connected"** or **"Up"**

2. **Test Internet:**
   - Open a web browser
   - Try accessing: `https://www.google.com`
   - If it loads, your PPPoE connection is working!

---

## Troubleshooting

### Problem: Cannot Access Router Web Interface

**Solutions:**
- Check if your computer is on the same network (192.168.1.x)
- Try resetting the router (hold reset button for 10 seconds)
- Use default IP: `192.168.1.1` or `192.168.100.1`
- Disable firewall temporarily

### Problem: "Authentication Failed" or "Invalid Username/Password"

**Solutions:**
- Double-check your PPPoE username and password
- Ensure no extra spaces before/after credentials
- Try typing password manually (don't copy-paste)
- Contact your ISP to verify credentials

### Problem: "Cannot Obtain IP Address" or "No Internet"

**Solutions:**
- Verify Ethernet cable is connected to WAN port (not LAN)
- Check if ISP's network is active
- Try changing authentication to "PAP" only
- Restart the router (unplug for 30 seconds, plug back in)
- Check if MAC address cloning is needed (rare)

### Problem: Connection Drops Frequently

**Solutions:**
- Check cable connections (ensure tight fit)
- Update router firmware (if available)
- Change connection mode to "Always On"
- Contact ISP to check line quality

### Problem: Slow Internet Speed

**Solutions:**
- Check if you're using the correct PPPoE profile (some ISPs have speed tiers)
- Verify cable quality (use Cat5e or Cat6)
- Check for interference on network cables
- Test speed directly connected to ISP's equipment (bypass router)

---

## Advanced Settings (Optional)

### MTU Size
- Default: `1492` (recommended for PPPoE)
- If experiencing issues, try: `1480` or `1500`
- Location: Advanced Settings → WAN → MTU

### VLAN Tagging
- Most ISPs don't require VLAN tagging
- If required, your ISP will provide VLAN ID (usually 100 or 200)
- Location: WAN Settings → VLAN ID

### MAC Address Cloning
- Rarely needed
- Only if ISP restricts by MAC address
- Location: Advanced Settings → MAC Address Clone

---

## Quick Reference

| Setting | Value |
|---------|-------|
| Connection Type | PPPoE |
| Username | [Your PPPoE Username] |
| Password | [Your PPPoE Password] |
| Connection Mode | Always On / Auto Connect |
| Authentication | PAP or PAP/CHAP |
| MTU | 1492 (default) |
| DNS | 8.8.8.8 / 8.8.4.4 (or Auto) |

---

## Support

If you continue to experience issues:
1. **Contact your ISP** - They can verify your PPPoE credentials and line status
2. **Router Support** - Check Huawei's support website for firmware updates
3. **Network Technician** - For physical line issues or advanced configuration

---

## Notes

- **Security:** Change your router's admin password after setup
- **Firmware:** Keep router firmware updated for security and performance
- **Backup:** Save your router configuration after successful setup
- **Wi-Fi:** Configure Wi-Fi settings separately after internet connection is established

---

**Last Updated:** January 2026
**Router Model:** Huawei HG8546M
**Connection Type:** PPPoE


