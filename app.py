import operator
import json
import urllib.request
import socket
from typing import TypedDict, Annotated, Sequence

from langchain_core.messages import BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

# --- 1. Define OSINT Tools ---

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
        # First resolve domain if an IP wasn't provided directly
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

tools = [dns_lookup, get_ip_info, get_http_headers]

# --- 2. Define State ---
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]

# --- 3. Initialize Model ---
# Make sure you have pulled a model in Ollama that supports tool calling.
# Examples: llama3.1, mistral, llama3.2
model = ChatOllama(model="qwen3:1.7b", temperature=0)
model_with_tools = model.bind_tools(tools)

# --- 4. Define Nodes ---
def call_model(state: AgentState):
    messages = state["messages"]
    response = model_with_tools.invoke(messages)
    return {"messages": [response]}

# Configure the tool node
tool_node = ToolNode(tools)

# --- 5. Build Graph ---
workflow = StateGraph(AgentState)

# Add the nodes
workflow.add_node("agent", call_model)
workflow.add_node("tools", tool_node)

# Set the entrypoint as `agent`
workflow.add_edge(START, "agent")

# We conditionally route between the tool node or ending
workflow.add_conditional_edges(
    "agent",
    tools_condition,
)

# After tools run, go back to the agent
workflow.add_edge("tools", "agent")

# Compile the graph
app = workflow.compile()

# --- 6. Run the Agent Loop ---
if __name__ == "__main__":
    print("🤖 OSINT Agent Initialized using LangGraph & Ollama.")
    print("Available tools: DNS Lookup, IP Geolocation, HTTP Header Check")
    print("Provide a domain or IP for the agent to investigate. (Type 'quit' to exit)")
    print("-" * 50)
    
    while True:
        user_input = input("\nYou: ")
        if user_input.lower() in ["quit", "exit"]:
            break
            
        inputs = {"messages": [HumanMessage(content=user_input)]}
        print("\nAgent is thinking...")
        
        # Stream the output
        for chunk in app.stream(inputs, stream_mode="values"):
            message = chunk["messages"][-1]
            if isinstance(message, HumanMessage):
                continue
            
            # Print intermediate tool calls if any
            if hasattr(message, "tool_calls") and message.tool_calls:
                for t in message.tool_calls:
                    print(f"🔧 Using tool: {t['name']}({t['args']})")
                    
            # Print the final response
            elif message.content:
                print(f"\nAgent: {message.content}")
