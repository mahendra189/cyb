import os
import uuid
import subprocess
import json
import re
from typing import Optional

# Set environment variable before importing tools to bypass CLI interactive prompts
os.environ["STREAMLIT"] = "1"

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_ollama import ChatOllama

# Import your LangGraph compiled agent
from app import app as langgraph_agent

# Initialize FastAPI
api = FastAPI(
    title="💀 CyberSec Hacker Agent API",
    description="Backend API exposing the autonomous LangGraph security agent.",
    version="1.0.0"
)

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
    Runs testssl.sh on the specified host and returns SSL/TLS certificate
    and vulnerability analysis in structured JSON format.
    """
    host = request.host.strip()
    port = request.port
    
    if not host:
        raise HTTPException(status_code=400, detail="Host cannot be empty.")
    
    try:
        print(f"\n[🔐] Running testssl.sh on {host}:{port}...")
        
        # Run testssl.sh with JSON output
        cmd = [
            "testssl.sh",
            "--json",
            "--severity", "HIGH",
            "--no-counseling",
            f"{host}:{port}"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0 and not result.stdout:
            raise HTTPException(
                status_code=500,
                detail=f"testssl.sh failed: {result.stderr or 'Unknown error'}"
            )
        
        # Parse testssl JSON output
        testssl_data = json.loads(result.stdout) if result.stdout else {}
        
        # Extract and transform data into the required format
        parsed_result = _parse_testssl_output(testssl_data, host, port)
        
        print(f"[✅] Successfully completed testssl scan for {host}:{port}")
        return parsed_result
        
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse testssl JSON output: {str(e)}"
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="testssl.sh execution timed out (>120 seconds)"
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail="testssl.sh not found. Please install testssl.sh: https://github.com/drwetter/testssl.sh"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running testssl: {str(e)}")


def _parse_testssl_output(testssl_data: dict, host: str, port: int) -> dict:
    """
    Parses testssl.sh JSON output and transforms it into the required format.
    """
    
    # Initialize result structure
    result = {
        "overallGrade": "N/A",
        "finalScore": 0,
        "metrics": {
            "Protocol Support": 0,
            "Key Exchange": 0,
            "Cipher Strength": 0
        },
        "protocols": [],
        "vulnerabilities": [],
        "certificate": {
            "commonName": "N/A",
            "issuer": "N/A",
            "notBefore": "N/A",
            "notAfter": "N/A",
            "keySize": "N/A",
            "signatureAlgorithm": "N/A",
            "subjectAltNames": []
        }
    }
    
    try:
        # Extract summary information
        if "summaries" in testssl_data and testssl_data["summaries"]:
            summary = testssl_data["summaries"][0]
            result["overallGrade"] = summary.get("grade", "N/A")
            
            # Extract score from grade (rough conversion)
            grade_scores = {
                "A+": 100, "A": 95, "A-": 90,
                "B+": 85, "B": 80, "B-": 75,
                "C+": 70, "C": 65, "C-": 60,
                "D+": 55, "D": 50, "D-": 45,
                "E": 40, "F": 20, "T": 0
            }
            result["finalScore"] = grade_scores.get(summary.get("grade", "N/A"), 50)
        
        # Parse protocol support
        if "scanResult" in testssl_data:
            for result_item in testssl_data["scanResult"]:
                # Extract TLS/SSL protocols
                if "protocol" in result_item.get("id", ""):
                    protocol_name = result_item.get("id", "").replace("TLSv", "TLS ").replace("SSLv", "SSL ")
                    status = result_item.get("finding", "").upper()
                    
                    if "offered" in status or "enabled" in status.lower() or result_item.get("severity", "").lower() == "info":
                        result["protocols"].append({
                            "name": protocol_name,
                            "offered": True,
                            "status": "OK" if "accepted" in status.lower() else status
                        })
                    elif "deprecated" in status.lower() or "weak" in status.lower():
                        result["protocols"].append({
                            "name": protocol_name,
                            "offered": True,
                            "status": "DEPRECATED" if "deprecated" in status.lower() else status
                        })
                
                # Extract vulnerabilities
                vuln_keywords = ["heartbleed", "ccs", "lucky13", "crime", "breach", "sweet32", "logjam", "drown", "poodle"]
                test_id_lower = result_item.get("id", "").lower()
                
                for keyword in vuln_keywords:
                    if keyword in test_id_lower:
                        severity = result_item.get("severity", "").lower()
                        is_vulnerable = severity in ["high", "critical", "medium"] or "vulnerable" in result_item.get("finding", "").lower()
                        
                        result["vulnerabilities"].append({
                            "id": keyword.upper(),
                            "vulnerable": is_vulnerable,
                            "cve": _get_cve_for_vuln(keyword)
                        })
                        break
                
                # Extract certificate information
                if "cert" in result_item.get("id", "").lower():
                    cert_info = result_item.get("finding", "")
                    if "CN=" in cert_info:
                        # Parse certificate details from finding string
                        cn_match = re.search(r"CN=([^,/\s]*)", cert_info)
                        if cn_match:
                            result["certificate"]["commonName"] = cn_match.group(1)
                    
                    if "issuer" in result_item.get("id", "").lower():
                        result["certificate"]["issuer"] = cert_info[:50] if cert_info else "N/A"
        
        # Extract certificate details from certChain if available
        if "certChain" in testssl_data and testssl_data["certChain"]:
            for cert in testssl_data["certChain"]:
                if "CN" in cert.get("subject", ""):
                    cn_match = re.search(r"CN=([^,/\s]*)", cert.get("subject", ""))
                    if cn_match:
                        result["certificate"]["commonName"] = cn_match.group(1)
                
                if "O" in cert.get("issuer", ""):
                    result["certificate"]["issuer"] = cert.get("issuer", "N/A")
                
                if "notBefore" in cert:
                    result["certificate"]["notBefore"] = str(cert["notBefore"])[:10]
                
                if "notAfter" in cert:
                    result["certificate"]["notAfter"] = str(cert["notAfter"])[:10]
                
                if "keySize" in cert:
                    result["certificate"]["keySize"] = f"{cert.get('keyType', 'RSA')} {cert['keySize']}"
                
                if "signatureAlgorithm" in cert:
                    result["certificate"]["signatureAlgorithm"] = cert["signatureAlgorithm"]
                
                if "subjectAltName" in cert:
                    result["certificate"]["subjectAltNames"] = cert["subjectAltName"]
        
        # Calculate metrics based on available protocols and vulnerabilities
        protocol_count = len(result["protocols"])
        if protocol_count > 0:
            result["metrics"]["Protocol Support"] = min(100, 50 + (protocol_count * 10))
        
        vuln_count = sum(1 for v in result["vulnerabilities"] if v["vulnerable"])
        if len(result["vulnerabilities"]) > 0:
            result["metrics"]["Key Exchange"] = max(0, 100 - (vuln_count * 15))
        
        result["metrics"]["Cipher Strength"] = result["finalScore"]
        
    except Exception as e:
        print(f"[⚠️] Error parsing testssl output: {e}")
        # Return partially filled result if parsing fails
    
    return result


def _get_cve_for_vuln(vuln_name: str) -> str:
    """
    Returns the CVE ID for known vulnerabilities.
    """
    cve_map = {
        "heartbleed": "CVE-2014-0160",
        "ccs": "CVE-2014-0224",
        "lucky13": "CVE-2013-0169",
        "crime": "CVE-2012-4929",
        "breach": "CVE-2013-3566",
        "sweet32": "CVE-2016-2183",
        "logjam": "CVE-2015-4000",
        "drown": "CVE-2016-0800",
        "poodle": "CVE-2014-3566"
    }
    return cve_map.get(vuln_name.lower(), "N/A")
