#!/usr/bin/env python3
"""
AgentGround — Entrypoint CLI for A2A Service & Model Context Protocol (MCP) Server.
"""

import sys
import os

# Add directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_ground_service import run_server, run_mcp_server, DEFAULT_PORT, execute_claim_verification

def main():
    if "--remote" in sys.argv or "--gateway" in sys.argv:
        from agent_ground_remote_gateway import run_gateway, DEFAULT_GATEWAY_PORT
        port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else DEFAULT_GATEWAY_PORT
        run_gateway(port)
    elif "--mcp" in sys.argv:
        run_mcp_server()
    elif "--help" in sys.argv or "-h" in sys.argv:
        print("AgentGround — Cross-Check Claim & Factual Grounding Verifier")
        print("Usage:")
        print("  python agent_ground.py           # Start HTTP server on default port 8092")
        print("  python agent_ground.py 8080      # Start HTTP server on custom port")
        print("  python agent_ground.py --mcp     # Run as Model Context Protocol (MCP) server over stdio")
        print("  python agent_ground.py --remote  # Run as Remote Hosted Invocation Gateway (REST + MCP SSE)")
        sys.exit(0)
    else:
        port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else DEFAULT_PORT
        run_server(port)

if __name__ == "__main__":
    main()
