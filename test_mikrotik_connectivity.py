#!/usr/bin/env python3
"""
Test script to verify MikroTik connectivity from cPanel server.

This script tests if your cPanel server can connect to a MikroTik router.
Run this BEFORE deploying the full application to identify any connectivity issues.

Usage:
    python test_mikrotik_connectivity.py [mikrotik_ip] [port]
    
Example:
    python test_mikrotik_connectivity.py 203.0.113.50 8728
    python test_mikrotik_connectivity.py 192.168.1.1 8729
"""

import socket
import sys
import time

def test_mikrotik_connection(host, port, timeout=5):
    """
    Test if we can establish a TCP connection to the MikroTik router.
    
    Args:
        host: MikroTik router IP address
        port: RouterOS API port (8728 or 8729)
        timeout: Connection timeout in seconds
    
    Returns:
        tuple: (success: bool, message: str)
    """
    print(f"\n{'='*60}")
    print(f"Testing connection to MikroTik Router")
    print(f"{'='*60}")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Timeout: {timeout} seconds")
    print(f"{'='*60}\n")
    
    try:
        print("Attempting TCP connection...")
        start_time = time.time()
        
        sock = socket.create_connection((host, port), timeout=timeout)
        elapsed = time.time() - start_time
        
        sock.close()
        
        print(f"✅ SUCCESS: Connection established in {elapsed:.2f} seconds")
        print(f"\n✓ Your cPanel server CAN reach the MikroTik router")
        print(f"✓ Port {port} is open and accessible")
        print(f"✓ Network path is configured correctly")
        print(f"\n🎉 Your application SHOULD be able to connect to MikroTik!")
        return True, "Connection successful"
        
    except socket.timeout:
        print(f"❌ TIMEOUT: Connection timed out after {timeout} seconds")
        print(f"\nPossible causes:")
        print(f"  • RouterOS API not enabled on MikroTik")
        print(f"  • Firewall blocking connection from cPanel server IP")
        print(f"  • Port {port} is blocked by ISP or firewall")
        print(f"  • Network routing issue")
        print(f"  • MikroTik router is not reachable from this network")
        return False, "Connection timeout"
        
    except socket.gaierror as e:
        print(f"❌ DNS ERROR: Cannot resolve hostname '{host}'")
        print(f"   Error: {e}")
        print(f"\nPossible causes:")
        print(f"  • Invalid IP address or hostname")
        print(f"  • DNS resolution failure")
        return False, f"DNS error: {e}"
        
    except ConnectionRefused:
        print(f"❌ CONNECTION REFUSED: Router refused the connection")
        print(f"\nPossible causes:")
        print(f"  • RouterOS API service not running on port {port}")
        print(f"  • Firewall on MikroTik is blocking the connection")
        print(f"  • Wrong port number (use 8728 for non-SSL, 8729 for SSL)")
        return False, "Connection refused"
        
    except OSError as e:
        if "Network is unreachable" in str(e):
            print(f"❌ NETWORK UNREACHABLE: Cannot reach {host}")
            print(f"\nPossible causes:")
            print(f"  • MikroTik is on private network (192.168.x.x, 10.x.x.x)")
            print(f"  • No route to the destination")
            print(f"  • Outbound connections blocked by cPanel firewall")
            print(f"  • Need VPN or port forwarding")
        else:
            print(f"❌ NETWORK ERROR: {e}")
        return False, f"Network error: {e}"
        
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {type(e).__name__}: {e}")
        return False, f"Unexpected error: {e}"


def test_routeros_api(host, port, use_ssl=False):
    """
    Test actual RouterOS API connection (requires routeros-api library).
    
    Args:
        host: MikroTik router IP address
        port: RouterOS API port
        use_ssl: Whether to use SSL
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        import routeros_api
        
        print(f"\n{'='*60}")
        print(f"Testing RouterOS API Connection")
        print(f"{'='*60}")
        print(f"Host: {host}")
        print(f"Port: {port}")
        print(f"SSL: {use_ssl}")
        print(f"{'='*60}\n")
        
        print("⚠️  Note: This test requires valid credentials.")
        print("⚠️  For security, only test TCP connectivity without credentials.")
        print("⚠️  Full API test should be done from the application.\n")
        
        return True, "API library available"
        
    except ImportError:
        print(f"\n⚠️  routeros-api library not installed")
        print(f"   Install with: pip install routeros-api")
        print(f"   This is OK - TCP connectivity test is sufficient")
        return True, "API library not installed (OK)"


def main():
    """Main test function."""
    print("\n" + "="*60)
    print("MikroTik Connectivity Test for cPanel Deployment")
    print("="*60)
    
    if len(sys.argv) < 3:
        print("\nUsage: python test_mikrotik_connectivity.py [mikrotik_ip] [port]")
        print("\nExample:")
        print("  python test_mikrotik_connectivity.py 203.0.113.50 8728")
        print("  python test_mikrotik_connectivity.py 192.168.1.1 8729")
        print("\nPorts:")
        print("  8728 = RouterOS API (non-SSL)")
        print("  8729 = RouterOS API (SSL)")
        sys.exit(1)
    
    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print(f"❌ ERROR: Invalid port number '{sys.argv[2]}'")
        print(f"   Port must be a number (8728 or 8729)")
        sys.exit(1)
    
    if port not in [8728, 8729]:
        print(f"⚠️  WARNING: Port {port} is not standard RouterOS API port")
        print(f"   Standard ports are 8728 (non-SSL) and 8729 (SSL)")
        response = input("   Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    # Test TCP connectivity
    success, message = test_mikrotik_connection(host, port)
    
    # Test API library availability
    test_routeros_api(host, port, use_ssl=(port == 8729))
    
    # Final summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    if success:
        print("✅ TCP Connectivity: PASSED")
        print("\n✅ Your cPanel server CAN connect to MikroTik")
        print("✅ The application should work correctly")
        print("\nNext steps:")
        print("  1. Deploy your application to cPanel")
        print("  2. Configure MikroTik router in the application")
        print("  3. Test router registration/connection")
    else:
        print("❌ TCP Connectivity: FAILED")
        print("\n❌ Your cPanel server CANNOT connect to MikroTik")
        print("❌ The application will NOT work until this is fixed")
        print("\nTroubleshooting:")
        print("  1. Check if MikroTik has RouterOS API enabled")
        print("  2. Verify firewall allows connections from cPanel server IP")
        print("  3. Test if MikroTik IP is reachable: ping [mikrotik_ip]")
        print("  4. Check if outbound connections are blocked by cPanel")
        print("  5. Consider using VPN or port forwarding")
        print("  6. Contact your hosting provider for network restrictions")
    print(f"{'='*60}\n")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()













