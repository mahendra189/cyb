# testssl Endpoint Documentation

## Overview
The `/api/testssl` endpoint runs SSL/TLS certificate and vulnerability analysis on a specified host using `testssl.sh`.

## Prerequisites
- `testssl.sh` must be installed on your system
- Install from: https://github.com/drwetter/testssl.sh

```bash
# Clone and setup testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
chmod +x testssl.sh
sudo cp testssl.sh /usr/local/bin/
```

## Endpoint Details

### POST `/api/testssl`

**Description:** Runs testssl.sh on a host and returns SSL/TLS analysis in structured JSON format.

**Request Body:**
```json
{
  "host": "example.com",
  "port": 443
}
```

**Parameters:**
- `host` (string, required): Domain name or IP address to scan
- `port` (integer, optional): HTTPS port (default: 443)

**Response Format:**
```json
{
  "overallGrade": "B",
  "finalScore": 91,
  "metrics": {
    "Protocol Support": 95,
    "Key Exchange": 90,
    "Cipher Strength": 91
  },
  "protocols": [
    {
      "name": "TLS 1.3",
      "offered": true,
      "status": "OK"
    },
    {
      "name": "TLS 1.1",
      "offered": true,
      "status": "DEPRECATED"
    }
  ],
  "vulnerabilities": [
    {
      "id": "Heartbleed",
      "vulnerable": false,
      "cve": "CVE-2014-0160"
    },
    {
      "id": "SWEET32",
      "vulnerable": true,
      "cve": "CVE-2016-2183"
    }
  ],
  "certificate": {
    "commonName": "*.example.com",
    "issuer": "DigiCert / Google Trust",
    "notBefore": "2026-01-01",
    "notAfter": "2026-12-31",
    "keySize": "RSA 2048",
    "signatureAlgorithm": "SHA256",
    "subjectAltNames": ["*.example.com", "api.example.com"]
  }
}
```

## Response Fields

### Top Level
- **overallGrade**: SSL/TLS grade (A+, A, B, C, D, E, F, T)
- **finalScore**: Numerical score (0-100)

### Metrics
- **Protocol Support**: Score for supported protocols
- **Key Exchange**: Score for key exchange mechanisms
- **Cipher Strength**: Score for cipher strength

### Protocols Array
Each protocol includes:
- **name**: Protocol name (e.g., "TLS 1.3")
- **offered**: Whether protocol is offered (true/false)
- **status**: Status (OK, DEPRECATED, WEAK, etc.)

### Vulnerabilities Array
Each vulnerability includes:
- **id**: Vulnerability name (Heartbleed, SWEET32, etc.)
- **vulnerable**: Whether the host is vulnerable (true/false)
- **cve**: CVE identifier

### Certificate Object
- **commonName**: Certificate CN
- **issuer**: Certificate issuer
- **notBefore**: Certificate valid from date
- **notAfter**: Certificate expiration date
- **keySize**: Key size and type (e.g., "RSA 2048")
- **signatureAlgorithm**: Signature algorithm
- **subjectAltNames**: Array of alternative names

## Example Usage

### Using cURL
```bash
curl -X POST http://localhost:8000/api/testssl \
  -H "Content-Type: application/json" \
  -d '{"host": "google.com", "port": 443}'
```

### Using Python
```python
import requests
import json

response = requests.post(
    "http://localhost:8000/api/testssl",
    json={"host": "google.com", "port": 443},
    timeout=180
)

result = response.json()
print(json.dumps(result, indent=2))
```

### Using the Test Script
```bash
# Test default hosts
python3 test_testssl_endpoint.py

# Test specific host
python3 test_testssl_endpoint.py example.com 443
```

## Error Responses

### 400 - Bad Request
```json
{"detail": "Host cannot be empty."}
```

### 500 - Internal Server Error
```json
{"detail": "testssl.sh not found. Please install testssl.sh: https://github.com/drwetter/testssl.sh"}
```

### 504 - Gateway Timeout
```json
{"detail": "testssl.sh execution timed out (>120 seconds)"}
```

## Supported Vulnerabilities

The endpoint detects and reports on these vulnerabilities:
- **Heartbleed** (CVE-2014-0160)
- **CCS** (CVE-2014-0224)
- **Lucky13** (CVE-2013-0169)
- **CRIME** (CVE-2012-4929)
- **BREACH** (CVE-2013-3566)
- **SWEET32** (CVE-2016-2183)
- **LogJam** (CVE-2015-4000)
- **DROWN** (CVE-2016-0800)
- **POODLE** (CVE-2014-3566)

## Performance Notes

- **Default timeout**: 120 seconds per scan
- **Typical scan time**: 30-60 seconds depending on network
- **Best practices**:
  - Ensure proper network connectivity
  - Test with publicly available hosts first
  - Monitor system resources during scans

## Troubleshooting

### testssl.sh not found
```bash
# Install testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
sudo cp testssl.sh/testssl.sh /usr/local/bin/
chmod +x /usr/local/bin/testssl.sh
```

### Timeout errors
- Increase timeout if needed (currently 120 seconds)
- Check network connectivity to the target host

### JSON parsing errors
- Ensure testssl.sh is generating valid JSON output
- Check testssl.sh version compatibility
