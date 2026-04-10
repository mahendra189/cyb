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
    print(f"Available tools: {', '.join([t.name for t in tools])}")
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
