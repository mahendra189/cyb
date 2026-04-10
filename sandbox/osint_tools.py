import socket
import urllib.request
import json
import subprocess
from langchain_core.tools import tool

# Basic Built-in Tools
@tool
def dns_lookup(domain: str) -> str:
    """Perform a simple DNS lookup to get the IP address of a domain."""
    try:
        ip = socket.gethostbyname(domain)
        return f"The IP address of {domain} is {ip}"
    except Exception as e:
        return f"DNS lookup failed: {e}"

@tool
def get_ip_info(ip_address: str) -> str:
    """Get geolocation and internet provider information for an IP address or domain."""
    try:
        try:
            ip_address = socket.gethostbyname(ip_address)
        except:
            pass
            
        url = f"http://ip-api.com/json/{ip_address}"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                return f"IP: {data.get('query')}\nLocation: {data.get('city')}, {data.get('regionName')}, {data.get('country')}\nISP: {data.get('isp')}\nOrg: {data.get('org')}"
            else:
                return f"Failed to get info for {ip_address}"
    except Exception as e:
        return f"Error fetching IP info: {e}"

@tool
def get_http_headers(url: str) -> str:
    """Get HTTP response headers for a URL to fingerprint the server."""
    if not url.startswith("http"):
        url = "http://" + url
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = dict(response.info())
            return json.dumps(headers, indent=2)
    except Exception as e:
        return f"Error fetching headers: {e}"

# Extended OSINT Tool Wrappers
# Note: These require the actual CLI tools to be installed on your system.

@tool
def nmap_scan(target: str) -> str:
    """Run Nmap for deep service fingerprinting on a target IP or domain."""
    try:
        result = subprocess.run(["nmap", "-sV", "-T4", target], capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        return "Error: nmap is not installed."
    except Exception as e:
        return f"Error running nmap: {e}"

@tool
def theharvester_scan(domain: str) -> str:
    """Run theHarvester to gather emails, subdomains, and names for a domain."""
    try:
        # Note: theHarvester needs to be in PATH or specify full path
        result = subprocess.run(["theHarvester", "-d", domain, "-l", "100", "-b", "all"], capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        return "Error: theHarvester is not installed or not in PATH."
    except Exception as e:
        return f"Error running theHarvester: {e}"

@tool
def masscan_scan(target: str) -> str:
    """Run Masscan for fast port scanning."""
    try:
        result = subprocess.run(["masscan", "-p1-65535", target, "--rate=1000"], capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        return "Error: masscan is not installed."
    except Exception as e:
        return f"Error running masscan: {e}"

@tool
def gitleaks_scan(repo_url: str) -> str:
    """Run Gitleaks to scan a git repository for hardcoded secrets and API keys."""
    try:
        result = subprocess.run(["gitleaks", "detect", "-v", "--source", repo_url], capture_output=True, text=True, timeout=60)
        return result.stdout
    except FileNotFoundError:
        return "Error: gitleaks is not installed."
    except Exception as e:
        return f"Error running gitleaks: {e}"

@tool
def nuclei_scan(target: str) -> str:
    """Run Nuclei to scan assets for vulnerabilities using templates."""
    if not target.startswith("http"):
        target = "http://" + target
    try:
        result = subprocess.run(["nuclei", "-u", target], capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        return "Error: nuclei is not installed."
    except Exception as e:
        return f"Error running nuclei: {e}"

@tool
def subfinder_scan(domain: str) -> str:
    """Run subfinder (alternative to Amass/Sublist3r) for subdomain enumeration."""
    try:
        result = subprocess.run(["subfinder", "-d", domain], capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        return "Error: subfinder is not installed."
    except Exception as e:
        return f"Error running subfinder: {e}"

@tool
def wafw00f_scan(target: str) -> str:
    """Run WafW00f to fingerprint and identify Web Application Firewalls."""
    if not target.startswith("http"):
        target = "http://" + target
    try:
        result = subprocess.run(["wafw00f", target], capture_output=True, text=True, timeout=60)
        return result.stdout
    except FileNotFoundError:
        return "Error: wafw00f is not installed."
    except Exception as e:
        return f"Error running wafw00f: {e}"

@tool
def feroxbuster_scan(target: str) -> str:
    """Run Feroxbuster for fast recursive content discovery (finding hidden directories)."""
    if not target.startswith("http"):
        target = "http://" + target
    try:
        result = subprocess.run(["feroxbuster", "-u", target, "--depth", "1", "--quiet"], capture_output=True, text=True, timeout=60)
        return result.stdout
    except FileNotFoundError:
        return "Error: feroxbuster is not installed."
    except Exception as e:
        return f"Error running feroxbuster: {e}"

@tool
def shodan_query(query: str) -> str:
    """Query Shodan for internet-facing devices (requires 'shodan' CLI and API key configured)."""
    try:
        result = subprocess.run(["shodan", "search", query], capture_output=True, text=True, timeout=60)
        return result.stdout
    except FileNotFoundError:
        return "Error: shodan CLI is not installed."
    except Exception as e:
        return f"Error running shodan: {e}"

@tool
def run_shell_command(command: str) -> str:
    """Execute an arbitrary shell command on the local system. Use this to run any tool not explicitly provided, write scripts, or interact with the OS."""
    try:
        # Security warning: In a real production system, you wouldn't expose raw shell access.
        # Since this is a local hacker agent, it provides maximum flexibility.
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        return output if output else "Command executed successfully with no output."
    except Exception as e:
        return f"Command execution failed: {e}"


# List of all tools to expose to the agent
tools = [
    dns_lookup, 
    get_ip_info, 
    get_http_headers,
    nmap_scan,
    theharvester_scan,
    masscan_scan,
    gitleaks_scan,
    nuclei_scan,
    subfinder_scan,
    wafw00f_scan,
    feroxbuster_scan,
    shodan_query,
    run_shell_command
]