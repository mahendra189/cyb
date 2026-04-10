import operator
import json
import urllib.request
import socket
from typing import TypedDict, Annotated, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.markdown import Markdown

from langchain_core.messages import BaseMessage, HumanMessage, ToolMessage, SystemMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

# Import tools from sandbox
from sandbox.osint_tools import tools

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
    
    system_prompt = SystemMessage(content=(
        "You are an elite white-hat cyber security expert and hacker AI. "
        "Your role is to assist the user intelligently and autonomously in deep reconnaissance, "
        "penetration testing, network scanning, threat intelligence, and scripting. "
        "You have access to a suite of advanced OSINT and security tools, as well as FULL shell execution "
        "capabilities to install whatever tools you need or write your own scripts directly. "
        "CRITICAL RULES: \n"
        "1. Never execute destructive shell commands (like rm -rf, mkfs, format, wiping drives). \n"
        "2. Do not attack IP addresses or domains without explicit explicit authorization from the user. Default to passive reconnaissance unless instructed otherwise. \n"
        "3. Provide deeply technical, precise, and practical responses. Only decline if instructed to run explicitly illegal or highly destructive attacks beyond the scope of a sandbox/audit."
    ))
    
    # We inject the SystemMessage to instruct the AI into hacker persona
    response = model_with_tools.invoke([system_prompt] + messages)
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

# Add memory to the agent
memory = MemorySaver()

# Compile the graph
app = workflow.compile(checkpointer=memory)

# Initialize Rich Console
console = Console()

# --- 6. Run the Agent Loop ---
if __name__ == "__main__":
    welcome_message = (
        "[bold cyan]Available tools:[/bold cyan] " + ", ".join([f"[green]{t.name}[/green]" for t in tools]) + "\n"
        "[italic]Provide a target domain, IP, or instruct the agent for a specialized security task. (Type 'quit' to exit)[/italic]"
    )
    console.print(Panel.fit(welcome_message, title="[bold red]💀 CyberSec Hacker Agent (LangGraph + Ollama)[/bold red]", border_style="red"))
    
    while True:
        try:
            user_input = Prompt.ask("\n[bold green]You[/bold green]")
            if user_input.lower() in ["quit", "exit"]:
                console.print("[bold red]Exiting OSINT Agent. Goodbye![/bold red]")
                break
                
            inputs = {"messages": [HumanMessage(content=user_input)]}
            
            # The 'thread_id' tracks the conversation context in LangGraph's memory
            config = {"configurable": {"thread_id": "session-1"}}
            
            # Stream the output with visual status
            with console.status("[bold yellow]Agent is thinking...[/bold yellow]", spinner="dots"):
                for chunk in app.stream(inputs, config=config, stream_mode="values"):
                    message = chunk["messages"][-1]
                    if isinstance(message, HumanMessage):
                        continue
                    
                    # Print intermediate tool calls if any
                    if hasattr(message, "tool_calls") and message.tool_calls:
                        for t in message.tool_calls:
                            console.print(f"  [bold magenta]🔧 Using tool:[/bold magenta] [yellow]{t['name']}[/yellow]([cyan]{t['args']}[/cyan])")
                            
                    # Print the final response
                    elif message.content:
                        console.print("\n")
                        console.print(Panel(Markdown(message.content), title="[bold blue]Agent response[/bold blue]", border_style="blue", expand=False))
                        
        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupt received. Stopping current operation or exiting gracefully...[/bold red]")
            break
        except Exception as e:
            console.print(f"\n[bold red]An error occurred:[/bold red] {str(e)}")
