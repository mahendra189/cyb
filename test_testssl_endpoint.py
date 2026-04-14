#!/usr/bin/env python3
"""
Test script for the testssl endpoint.
Run this to test SSL/TLS certificate analysis.
"""

import requests
import json

# API base URL
API_URL = "http://localhost:8000"

def test_testssl_endpoint():
    """Test the testssl endpoint"""
    
    print("[*] Testing /api/testssl endpoint\n")
    
    # Example hosts to scan
    test_hosts = [
        {"host": "google.com", "port": 443},
        {"host": "github.com", "port": 443},
        {"host": "example.com", "port": 443},
    ]
    
    for test in test_hosts:
        print(f"[+] Scanning {test['host']}:{test['port']}...")
        
        try:
            response = requests.post(
                f"{API_URL}/api/testssl",
                json=test,
                timeout=180
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"\n✅ Scan completed for {test['host']}")
                print(json.dumps(result, indent=2))
                print("\n" + "="*80 + "\n")
            else:
                print(f"❌ Error: {response.status_code} - {response.text}\n")
                
        except requests.exceptions.ConnectionError:
            print("❌ Connection error: Is the API running on localhost:8000?\n")
            break
        except requests.exceptions.Timeout:
            print(f"⏱️  Timeout scanning {test['host']}\n")
        except Exception as e:
            print(f"❌ Error: {e}\n")

def test_specific_host(host: str, port: int = 443):
    """Test a specific host"""
    
    print(f"[+] Running testssl scan on {host}:{port}...\n")
    
    try:
        response = requests.post(
            f"{API_URL}/api/testssl",
            json={"host": host, "port": port},
            timeout=180
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Scan completed!\n")
            print(json.dumps(result, indent=2))
            
            # Print summary
            print("\n" + "="*80)
            print("SUMMARY:")
            print(f"Overall Grade: {result['overallGrade']}")
            print(f"Final Score: {result['finalScore']}")
            print(f"Common Name: {result['certificate']['commonName']}")
            print(f"Issuer: {result['certificate']['issuer']}")
            print(f"Protocols: {len(result['protocols'])}")
            print(f"Vulnerabilities Detected: {sum(1 for v in result['vulnerabilities'] if v['vulnerable'])}")
            
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection error: Is the API running on localhost:8000?")
    except requests.exceptions.Timeout:
        print(f"⏱️  Timeout scanning {host}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    import sys
    
    print("=" * 80)
    print("testssl Endpoint Tester")
    print("=" * 80 + "\n")
    
    if len(sys.argv) > 1:
        # Test specific host
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
        test_specific_host(host, port)
    else:
        # Run all tests
        test_testssl_endpoint()
