import os
import socket
import netifaces
import ipaddress
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor
from fastapi.middleware.cors import CORSMiddleware

from fastapi import FastAPI, HTTPException

# Initialize FastAPI
api = FastAPI(
    title="💀 CyberSec Hacker Agent API",
    description="Backend API exposing the autonomous LangGraph security agent.",
    version="1.0.0"
)

# Enable CORS for all origins (optional, but matches your example)
api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Local Network Scan Endpoint ---
@api.get("/scan")
def scan_network():
    """
    Robust local network scanner.
    Automatically:
    - Detects subnet
    - Scans active hosts
    - Resolves hostname
    - Extracts MAC addresses
    """

    import platform
    import time
    import re
    import subprocess
    from concurrent.futures import ThreadPoolExecutor

    def get_local_network():
        """
        Get active interface + subnet automatically
        """

        gateways = netifaces.gateways()

        if "default" not in gateways:
            raise Exception("No default gateway found")

        default_gateway = gateways["default"][netifaces.AF_INET][1]

        iface_data = netifaces.ifaddresses(default_gateway)

        if netifaces.AF_INET not in iface_data:
            raise Exception("No IPv4 interface found")

        iface = iface_data[netifaces.AF_INET][0]

        ip = iface["addr"]
        netmask = iface["netmask"]

        network = ipaddress.IPv4Network(
            f"{ip}/{netmask}",
            strict=False
        )

        return {
            "interface": default_gateway,
            "ip": ip,
            "netmask": netmask,
            "network": network
        }

    def ping_host(ip):
        """
        Cross-platform ping
        """

        system = platform.system().lower()

        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

        try:
            start = time.time()

            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )

            latency = round((time.time() - start) * 1000, 2)

            return result.returncode == 0, latency

        except Exception:
            return False, None

    def get_hostname(ip):
        try:
            return socket.gethostbyaddr(str(ip))[0]
        except Exception:
            return None

    def get_mac(ip):
        """
        Read MAC from ARP table
        """

        try:

            if platform.system().lower() == "windows":
                output = subprocess.check_output(
                    ["arp", "-a", str(ip)]
                ).decode()

            else:
                output = subprocess.check_output(
                    ["arp", "-n", str(ip)]
                ).decode()

            mac_regex = r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})"

            match = re.search(mac_regex, output)

            if match:
                return match.group(0)

        except Exception:
            pass

        return None

    def scan_ip(ip):

        ip = str(ip)

        alive, latency = ping_host(ip)
        if not alive:
            return None
        hostname = get_hostname(ip)
        mac = get_mac(ip)
        fingerprint = fingerprint_device(ip)

        return {
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "latency_ms": latency,
            "alive": True,
            # Added info
            "os_guess": fingerprint["os_guess"],
            "device_type": fingerprint["device_type"],
            "open_ports": fingerprint["open_ports"]
        }

    


    def fingerprint_device(ip):
        """
        Lightweight device fingerprinting
        """

        common_ports = {
            22: "ssh",
            80: "http",
            443: "https",
            445: "smb",
            3389: "rdp",
            8080: "http-alt",
            62078: "iphone-sync",
            8009: "ajp13",
        }

        open_ports = []

        for port in common_ports.keys():

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)

            try:
                result = sock.connect_ex((str(ip), port))

                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": common_ports[port]
                    })

            except Exception:
                pass

            finally:
                sock.close()

        # OS Guess
        os_guess = "Unknown"

        ports = [p["port"] for p in open_ports]

        if 3389 in ports:
            os_guess = "Windows"

        elif 62078 in ports:
            os_guess = "iOS/macOS"

        elif 22 in ports:
            os_guess = "Linux/Unix"

        # Device Type Guess
        device_type = "Unknown"

        if 80 in ports or 443 in ports:
            device_type = "Web Server / Router"

        elif 445 in ports:
            device_type = "Windows Device"

        elif 62078 in ports:
            device_type = "Apple Device"

        elif 22 in ports:
            device_type = "Linux Device"

        return {
            "os_guess": os_guess,
            "device_type": device_type,
            "open_ports": open_ports
        }
    try:

        start_time = time.time()

        network_info = get_local_network()

        network = network_info["network"]

        devices = []

        # Prime ARP table for better MAC detection
        subprocess.run(
            ["ping", "-c", "1", str(network.network_address + 1)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=150) as executor:

            results = executor.map(
                scan_ip,
                network.hosts()
            )

            for result in results:
                if result:
                    devices.append(result)

        scan_time = round(time.time() - start_time, 2)

        return {
            "success": True,
            "interface": network_info["interface"],
            "local_ip": network_info["ip"],
            "subnet_mask": network_info["netmask"],
            "network": str(network),
            "total_devices": len(devices),
            "scan_time_seconds": scan_time,
            "devices": devices
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    





import uuid
import subprocess
import json
import re
from typing import Optional, Dict, Any

# Set environment variable before importing tools to bypass CLI interactive prompts
os.environ["STREAMLIT"] = "1"

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_ollama import ChatOllama


# Import your LangGraph compiled agent
from app import app as langgraph_agent

class PromptRequest(BaseModel):
    prompt: str
    thread_id: Optional[str] = None

class PromptResponse(BaseModel):
    response: str
    thread_id: str

class ScanRequest(BaseModel):
    domain: str
    mode: str = "fast"  # fast | medium | deep

class TestSSLRequest(BaseModel):
    host: str  # domain or IP address
    port: int = 443  # default HTTPS port

class ChatRequest(BaseModel):
    prompt: str
    target_id: Optional[str] = None  # optional target ID
    context: Optional[Dict[str, Any]] = None  # optional context (assets, ports, services)
    model: str = "qwen3:1.7b"  # default Ollama model

class ChatResponse(BaseModel):
    response: str
    model: str
    prompt: str
    target_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class GetIPRequest(BaseModel):
    host: str

@api.get("/")
def health_check():
    return {"status": "ok", "message": "CyberSec Hacker Agent API is running."}

@api.post("/api/chat", response_model=PromptResponse)
def run_agent(request: PromptRequest):
    """
    Accepts a user prompt as input. Sends it to the autonomous security agent,
    waits for the agent to process, execute tools, and finalize its report, 
    and then returns the final AI response directly.
    """
    try:
        # Maintain conversational memory by optionally passing a thread_id
        thread_id = request.thread_id
        if not thread_id:
            thread_id = str(uuid.uuid4())
            
        config = {"configurable": {"thread_id": thread_id}}
        inputs = {"messages": [HumanMessage(content=request.prompt)]}
        
        # Invoke the LangGraph agent synchronously
        # It handles tool calling automatically and returns the final state
        state = langgraph_agent.invoke(inputs, config=config)
        
        # Extract the last message from the agent's finalized state
        final_message = state["messages"][-1]
        
        if isinstance(final_message, AIMessage):
            return PromptResponse(
                response=final_message.content,
                thread_id=thread_id
            )
        else:
            return PromptResponse(
                response="The agent did not return a valid response.",
                thread_id=thread_id
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent execution failed: {str(e)}")


@api.post("/api/scan_domain_pipeline")
def scan_domain_pipeline(request: ScanRequest):
    """
    Executes a custom bash-based reconnaissance pipeline on the specified domain.
    Gathers raw output from subfinder, amass, httpx, nmap, and gau.
    Passes the output to an LLM to generate perfectly formatted structural JSON schemas
    required for the Next.js visual dashboard components.
    """
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
        
    # 1. Execute the Pipeline
    # Standard output redirection (2>/dev/null) is used to avoid hanging on missing tools. 
    bash_script = f"""#!/bin/bash
DOMAIN="{domain}"
MODE="{request.mode}"

OUT="data/recon-$DOMAIN"
mkdir -p $OUT
cd $OUT || exit

echo "[+] Target: $DOMAIN"
echo "[+] Mode: $MODE"

# -----------------------------
# FAST MODE (≤ 2 min)
# -----------------------------
if [ "$MODE" == "fast" ]; then
    echo "[FAST] Running quick recon..."
    subfinder -d $DOMAIN -silent > subs.txt 2>/dev/null || true
    assetfinder --subs-only $DOMAIN >> subs.txt 2>/dev/null || true
    sort -u subs.txt > final_subs.txt 2>/dev/null || true
    dnsx -l final_subs.txt -silent -o live.txt 2>/dev/null || true
    httpx -l live.txt -silent -o live_hosts.txt 2>/dev/null || true
    echo "[FAST] Done. Output: live_hosts.txt"
fi

# -----------------------------
# MEDIUM MODE (≤ 5 min)
# -----------------------------
if [ "$MODE" == "medium" ]; then
    echo "[MEDIUM] Running balanced recon..."
    subfinder -d $DOMAIN -silent > subs.txt 2>/dev/null || true
    assetfinder --subs-only $DOMAIN >> subs.txt 2>/dev/null || true
    # amass removed to prevent huge bottleneck in automated API, fallback to basic fast tools
    sort -u subs.txt > final_subs.txt 2>/dev/null || true
    dnsx -l final_subs.txt -silent -o live.txt 2>/dev/null || true
    httpx -l live.txt -silent -o live_hosts.txt 2>/dev/null || true
    echo "[+] Port scanning..."
    naabu -l live.txt -silent -top-ports 100 -o ports.txt 2>/dev/null || true
    echo "[MEDIUM] Done. Outputs: live_hosts.txt, ports.txt"
fi

# -----------------------------
# DEEP MODE (5+ min)
# -----------------------------
if [ "$MODE" == "deep" ]; then
    echo "[DEEP] Running full recon..."
    subfinder -d $DOMAIN -silent > subs.txt 2>/dev/null || true
    assetfinder --subs-only $DOMAIN >> subs.txt 2>/dev/null || true
    sort -u subs.txt > final_subs.txt 2>/dev/null || true
    dnsx -l final_subs.txt -silent -o live.txt 2>/dev/null || true
    httpx -l live.txt -silent -o live_hosts.txt 2>/dev/null || true
    echo "[+] Full port scan..."
    naabu -l live.txt -silent -o ports.txt 2>/dev/null || true
    echo "[+] Service detection..."
    cut -d: -f1 ports.txt | sort -u > hosts.txt 2>/dev/null || true
    nmap -sV -iL hosts.txt -oN nmap.txt 2>/dev/null || true
    echo "[+] URL collection..."
    timeout 60 gau $DOMAIN > gau.txt 2>/dev/null || true
    timeout 60 waybackurls $DOMAIN > wayback.txt 2>/dev/null || true
    cat gau.txt wayback.txt | sort -u > urls.txt 2>/dev/null || true
    echo "[+] Extracting sensitive endpoints..."
    grep -E "api|admin|login|\\.json|\\.php|\\.aspx|\\.jsp" urls.txt > interesting.txt 2>/dev/null || true
    echo "[DEEP] Done. Full recon completed."
fi

# -----------------------------
# DONE
# -----------------------------
echo "[+] Recon Completed!"
echo "Results saved in: $OUT"

echo "--- RAW OUTPUT START ---"
echo "[SUBDOMAINS]"
cat final_subs.txt 2>/dev/null || echo "No subdomains found."
echo "[LIVE HOSTS & TECH]"
cat live_hosts.txt 2>/dev/null || echo "No live hosts found."
echo "[PORTS]"
cat ports.txt 2>/dev/null || echo "No ports found."
echo "[NMAP SERVICES]"
cat nmap.txt 2>/dev/null || echo "Nmap failed or found no open services."
echo "[DISCOVERED URLS]"
head -n 25 interesting.txt 2>/dev/null || echo "No URLs found."
echo "--- RAW OUTPUT END ---"
    """
    
    raw_recon_data = ""
    try:
        print(f"\n[🚀] Executing raw recon pipeline for {domain}...")
        print("[⏳] This may take several minutes. Streaming verbose output:\n" + "-"*50)
        
        process = subprocess.Popen(bash_script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # Stream the output line-by-line to the uvicorn console
        for line in process.stdout:
            print(f"  | {line}", end="", flush=True)
            raw_recon_data += line
            
        process.wait(timeout=600)
        print("-"*50 + f"\n[✅] Pipeline execution completed for {domain}.\n")
        
    except subprocess.TimeoutExpired:
        print("\n[❌] Pipeline execution timed out after 10 minutes.")
        raw_recon_data += "\nPipeline execution timed out after 10 minutes."
    except Exception as e:
        print(f"\n[❌] Pipeline execution failed: {e}")
        raw_recon_data += f"\nPipeline execution failed: {e}"
        
    # 2. Parse raw output into structured format
    print("\n[🔍] Parsing raw recon output into structured format...")
    
    try:
        # Extract subdomains from raw output
        subdomains = []
        ports_dict = {}
        
        # Parse the raw output to extract sections
        lines = raw_recon_data.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if "[SUBDOMAINS]" in line:
                current_section = "subdomains"
                continue
            elif "[LIVE HOSTS" in line or "[PORTS]" in line or "[NMAP" in line or "[DISCOVERED" in line:
                current_section = None
                continue
                
            if current_section == "subdomains" and line and not line.startswith("["):
                if line != "No subdomains found.":
                    subdomains.append(line)
        
        # Parse ports if available - ports output format is typically: host:port
        ports_section_start = raw_recon_data.find("[PORTS]")
        if ports_section_start != -1:
            ports_section = raw_recon_data[ports_section_start:].split('\n')[1:]
            for line in ports_section:
                line = line.strip()
                if not line or line.startswith("[") or "found" in line.lower():
                    continue
                
                # Expected format: subdomain:port or ip:port
                if ':' in line:
                    parts = line.rsplit(':', 1)
                    if len(parts) == 2:
                        host, port = parts
                        host = host.strip()
                        try:
                            port_num = int(port.strip())
                            if host not in ports_dict:
                                ports_dict[host] = []
                            if port_num not in ports_dict[host]:
                                ports_dict[host].append(port_num)
                        except ValueError:
                            pass
        
        # Build assets array
        assets = []
        for subdomain in subdomains:
            asset = {
                "subdomain": subdomain,
                "ports": ports_dict.get(subdomain, [])
            }
            assets.append(asset)
        
        result = {
            "domain": domain,
            "mode": request.mode,
            "assets": assets,
            "total_subdomains": len(subdomains),
            "total_assets": len(assets)
        }
        
        print(f"[✅] Successfully parsed {len(assets)} assets with {len(ports_dict)} hosts with ports.")
        return result
        
    except Exception as e:
        print(f"\n[❌] Parsing Error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to parse recon output: {str(e)}")


@api.post("/api/testssl")
def run_testssl(request: TestSSLRequest):
    """
    Runs testssl.sh and returns the output.json JSON response.
    """
    import tempfile
    import os
    
    host = request.host.strip()
    port = request.port
    
    if not host:
        raise HTTPException(status_code=400, detail="Host cannot be empty.")
    
    try:
        print(f"\n[🔐] testssl.sh: {host}:{port}")
        
        # Create temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            # Run testssl
            cmd = [
                "testssl.sh",
                "--quiet",
                "--warnings", "off",
                "--jsonfile", "output.json",
                f"{host}:{port}"
            ]
            
            result = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=300, 
                cwd=tmpdir
            )
            
            # Read output.json
            json_file_path = os.path.join(tmpdir, "output.json")
            
            if not os.path.exists(json_file_path):
                raise HTTPException(
                    status_code=500,
                    detail=f"testssl.sh did not generate output.json"
                )
            
            with open(json_file_path, 'r') as f:
                output_data = json.load(f)
            
            print(f"[✅] Done")
            return output_data
        
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout")
        raise HTTPException(
            status_code=504,
            detail="testssl.sh timed out"
        )
    except FileNotFoundError:
        print(f"[!] testssl.sh not found")
        raise HTTPException(
            status_code=500,
            detail="testssl.sh not found"
        )
    except json.JSONDecodeError as e:
        print(f"[!] JSON error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse JSON: {str(e)}"
        )
    except Exception as e:
        print(f"[!] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api.post("/api/ollama/chat", response_model=ChatResponse)
def ollama_chat(request: ChatRequest):
    """
    Chat endpoint that sends a prompt to Ollama and returns the response.
    Can include target context (assets, ports, services) for better analysis.
    """
    prompt = request.prompt.strip()
    model = request.model
    target_id = request.target_id
    context = request.context
    
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")
    
    try:
        print(f"\n[💬] Ollama Chat Request")
        print(f"[+] Model: {model}")
        if target_id:
            print(f"[+] Target ID: {target_id}")
        if context:
            print(f"[+] Context: {type(context).__name__} provided")
        print(f"[+] Prompt: {prompt[:80]}...")
        
        # Build full prompt with context if provided
        full_prompt = prompt
        if context:
            context_str = json.dumps(context, indent=2)
            full_prompt = f"{prompt}\n\nContext Data:\n{context_str}"
        
        # Initialize Ollama chat
        chat = ChatOllama(model=model, temperature=0)
        
        # Send prompt and get response
        print(f"[⏳] Getting response from Ollama...")
        response = chat.invoke([HumanMessage(content=full_prompt)])
        
        # Extract response text
        response_text = response.content if hasattr(response, 'content') else str(response)
        
        print(f"[✅] Response received ({len(response_text)} chars)")
        
        return ChatResponse(
            response=response_text,
            model=model,
            prompt=prompt,
            target_id=target_id,
            context=context
        )
        
    except Exception as e:
        print(f"[!] Error: {e}")
        raise HTTPException(status_code=500, detail=f"Error communicating with Ollama: {str(e)}")




@api.post("/api/get_ip")
def get_ip(request: GetIPRequest):
    """
    Resolve domain to IP using dig and return first IP.
    """
    
    host = request.host.strip()
    
    if not host:
        raise HTTPException(status_code=400, detail="Host cannot be empty.")
    
    try:
        result = subprocess.run(
            ["dig", "+short", host],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="dig command failed")
        
        # Get first IP from output
        ips = result.stdout.strip().splitlines()
        
        if not ips:
            raise HTTPException(status_code=404, detail="No IP found")
        
        return {
            "host": host,
            "ip": ips[0]
        }
    
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="dig timed out")
    
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="dig not installed")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))