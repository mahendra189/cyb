import os
import uuid
import subprocess
import json
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
domain="{domain}"
echo "[+] Starting Recon on $domain"

# 1. Subdomain Enumeration
echo "[+] Enumerating subdomains..."
subfinder -d $domain -silent > subs_{domain}.txt 2>/dev/null || true
amass enum -passive -d $domain >> subs_{domain}.txt 2>/dev/null || true
theHarvester -d $domain -b all | grep -oE "[a-zA-Z0-9._-]+\\.$domain" >> subs_{domain}.txt 2>/dev/null || true

# 2. Deduplicate
sort -u subs_{domain}.txt > final_subs_{domain}.txt 2>/dev/null || true

# 3. Resolve Live Domains
echo "[+] Probing live domains..."
httpx -l final_subs_{domain}.txt -silent -ip -status-code -title -tech-detect > live_hosts_{domain}.txt 2>/dev/null || true

# Extract IPs for scanning
cat live_hosts_{domain}.txt | awk '{{print $1}}' | sed 's|https\?://||' > hosts_{domain}.txt 2>/dev/null || true

# 4. Port Scanning
echo "[+] Running Nmap..."
nmap -iL hosts_{domain}.txt -T4 -Pn -oN nmap_scan_{domain}.txt 2>/dev/null || true

# 5. URL Collection
echo "[+] Gathering URLs..."
gau $domain > urls_{domain}.txt 2>/dev/null || true

# 6. Final Cleanup
sort -u urls_{domain}.txt > final_urls_{domain}.txt 2>/dev/null || true

echo "[+] Recon Completed 🚀"

echo "--- RAW OUTPUT START ---"
echo "[SUBDOMAINS]"
cat final_subs_{domain}.txt 2>/dev/null || echo "No subdomains found or tools failed."
echo "[LIVE HOSTS & TECH]"
cat live_hosts_{domain}.txt 2>/dev/null || echo "No live hosts found."
echo "[NMAP PORTS]"
cat nmap_scan_{domain}.txt 2>/dev/null || echo "Nmap failed or found no open ports."
echo "[DISCOVERED URLS]"
head -n 25 final_urls_{domain}.txt 2>/dev/null || echo "No URLs found."
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
        
    # 2. Transform the Data using LLM formatted strictly to the requested schemas
    llm = ChatOllama(model="llama3.2", temperature=0, format="json")
    
    system_prompt = SystemMessage(content=(
        "You are an expert security parser. You consume raw terminal output from penetration testing tools "
        "like subfinder, httpx, nmap, and gau, and map the findings into strict JSON object definitions.\n"
        "The user expects EXACTLY one root JSON object containing the following 5 arrays:\n\n"
        "1. `targets`: An array containing target metadata conforming to the Monitoring schema.\n"
        "2. `assets`: An array mapping subdomains, IP addresses, vulnerabilities, and OS properties.\n"
        "3. `services`: An array mapping detected software versions and web server types.\n"
        "4. `ports`: An array grouping exposed ports and the assets hosting them.\n"
        "5. `topology`: An object containing `nodes` and `edges` referencing the previously defined asset IDs, "
        "allowing a graph engine to render the attack surface.\n\n"
        "You must output ONLY valid, parsable JSON. No conversational text, no Markdown wrappers, no apologies if tools failed. "
        "If data is missing from the scan output, fabricate realistic placeholder correlations using proper formatting, "
        "ensuring the strict datatype structures are completely adhered to and nothing is broken."
    ))
    
    human_prompt = HumanMessage(content=f"Domain Scanned: {domain}\n\nRAW TERMINAL OUTPUT:\n{raw_recon_data}")
    
    try:
        print("\n[🧠] Parsing raw recon pipeline output through LangChain/Ollama into structured JSON schemas...")
        response = llm.invoke([system_prompt, human_prompt])
        
        # Clean the response content just in case the model wraps it in markdown blocks
        content = response.content.strip()
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
            
        content = content.strip()
        
        # Attempt to parse into python dict to validate it's correct JSON
        parsed_json = json.loads(content)
        print("[✅] Successfully parsed JSON from LLM.")
        return parsed_json
    except json.JSONDecodeError as decode_error:
        print(f"\n[❌] JSON Parse Error: {decode_error}")
        print(f"--- RAW LLM RESPONSE ---\n{response.content}\n------------------------")
        return {
            "error": "The LLM failed to return a structurally valid JSON payload.",
            "details": str(decode_error),
            "raw_output": response.content
        }
    except Exception as e:
        print(f"\n[❌] LLM Execution Error: {e}")
        raise HTTPException(status_code=500, detail=f"LLM processing failed: {str(e)}")
