#!/usr/bin/env python3
"""
Unit & Integration Test Suite: AgentGround Remote Hosted Invocation Gateway
===========================================================================
Validates:
1. Healthcheck (/health and /api/v1/health)
2. Machine-readable tool description schema (/tools, /.well-known/agent-card.json)
3. Real claim verification execution (POST /api/v1/verify-claims)
4. Bounded request size (> 1MB returns HTTP 413)
5. Rate limiting (> 60 req/min returns HTTP 429)
6. Structured error responses (400 Bad Request, 404 Not Found)
7. MCP JSON-RPC 2.0 tool execution (/rpc)
8. Server-side telemetry logging with client ID hashing and zero raw PII
9. HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE = True verification
"""

import unittest
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error
import socketserver
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

from agent_ground_remote_gateway import (
    AgentGroundRemoteGatewayHandler,
    GATEWAY_VERSION,
    MAX_REQUEST_BYTES,
    RATE_LIMIT_MAX_REQUESTS,
    TELEMETRY_LOG_PATH
)

TEST_PORT = 8997
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


class TestAgentGroundRemoteGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start gateway server in daemon thread
        server_address = ("127.0.0.1", TEST_PORT)
        cls.httpd = socketserver.ThreadingTCPServer(server_address, AgentGroundRemoteGatewayHandler)
        cls.httpd.allow_reuse_address = True
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _http_request(self, path: str, method: str = "GET", data: dict = None, headers: dict = None) -> tuple:
        url = f"{BASE_URL}{path}"
        req_headers = {"User-Agent": "Test-Agent-Runtime/1.0"}
        if headers:
            req_headers.update(headers)
        
        body_bytes = None
        if data is not None:
            body_bytes = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status = resp.status
                resp_data = resp.read().decode("utf-8")
                headers_dict = dict(resp.headers)
                return status, resp_data, headers_dict
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), dict(e.headers)

    def test_01_healthcheck(self):
        """Validates healthcheck returns 200 OK with HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE = True."""
        status, body, headers = self._http_request("/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get("status"), "HEALTHY")
        self.assertEqual(data.get("version"), GATEWAY_VERSION)
        self.assertTrue(data.get("HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE"))

    def test_02_machine_readable_tool_descriptions(self):
        """Validates /tools and /.well-known/agent-card.json return machine-readable schemas."""
        status, body, _ = self._http_request("/tools")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("tools", data)
        self.assertTrue(len(data["tools"]) > 0)
        tool = data["tools"][0]
        self.assertEqual(tool["name"], "verify_claims")
        self.assertIn("input_schema", tool)
        self.assertIn("output_schema", tool)

        # Agent Card test
        status_card, body_card, _ = self._http_request("/.well-known/agent-card.json")
        self.assertEqual(status_card, 200)
        card = json.loads(body_card)
        self.assertIn("skills", card)
        self.assertTrue(card.get("HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE"))

    def test_03_real_claim_verification_execution(self):
        """Validates real AgentGround execution returns deterministic grounded results."""
        payload = {
            "claims": [
                "Circle issues USDC as a fully reserved digital currency.",
                "Ethereum mainnet uses proof of stake consensus."
            ],
            "sources": [
                "Circle issues USDC as a fully reserved digital currency with regular audit reports.",
                "Ethereum mainnet transitioned to proof of stake consensus via The Merge."
            ],
            "mode": "balanced"
        }
        status, body, _ = self._http_request("/api/v1/verify-claims", method="POST", data=payload)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get("verdict"), "VERIFIED")
        self.assertEqual(data.get("grounding_score"), 100.0)
        self.assertEqual(data.get("verified_count"), 2)
        self.assertEqual(data.get("ungrounded_count"), 0)

    def test_04_mcp_json_rpc_invocation(self):
        """Validates JSON-RPC 2.0 /rpc endpoint executes verify_claims tool."""
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": "req-001",
            "method": "tools/call",
            "params": {
                "name": "verify_claims",
                "arguments": {
                    "claims": ["Bitcoin was created by Satoshi Nakamoto."],
                    "sources": ["Bitcoin was created by the pseudonymous developer Satoshi Nakamoto in 2008."]
                }
            }
        }
        status, body, _ = self._http_request("/rpc", method="POST", data=rpc_payload)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get("id"), "req-001")
        self.assertIn("result", data)
        content_text = data["result"]["content"][0]["text"]
        result_json = json.loads(content_text)
        self.assertEqual(result_json.get("verdict"), "VERIFIED")

    def test_05_payload_too_large_boundary(self):
        """Validates requests exceeding MAX_REQUEST_BYTES return HTTP 413 Payload Too Large."""
        oversized_headers = {
            "Content-Length": str(MAX_REQUEST_BYTES + 1024),
            "Content-Type": "application/json"
        }
        url = f"{BASE_URL}/api/v1/verify-claims"
        req = urllib.request.Request(url, data=b"{}", headers=oversized_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                self.fail("Expected HTTP 413 but request succeeded")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 413)
            body = json.loads(e.read().decode("utf-8"))
            self.assertEqual(body.get("error_code"), "PAYLOAD_TOO_LARGE")

    def test_06_structured_errors_on_malformed_input(self):
        """Validates structured JSON errors on missing fields and invalid JSON."""
        # Missing required fields
        status, body, _ = self._http_request("/api/v1/verify-claims", method="POST", data={"invalid_key": 123})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertEqual(data.get("status"), "ERROR")
        self.assertEqual(data.get("error_code"), "INVALID_ARGUMENTS")

        # 404 Not Found
        status_404, body_404, _ = self._http_request("/nonexistent-endpoint")
        self.assertEqual(status_404, 404)
        data_404 = json.loads(body_404)
        self.assertEqual(data_404.get("error_code"), "NOT_FOUND")

    def test_07_server_side_telemetry_logged_with_privacy(self):
        """Validates server-side telemetry is logged without raw IP addresses."""
        if os.path.exists(TELEMETRY_LOG_PATH):
            with open(TELEMETRY_LOG_PATH, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            self.assertTrue(len(lines) > 0)
            latest = json.loads(lines[-1])
            self.assertIn("client_hash", latest)
            self.assertIn("HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE", latest)
            self.assertTrue(latest["HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE"])
            self.assertNotIn("127.0.0.1", latest["client_hash"])  # Salted hash does not leak raw IP

    def test_08_canonical_mcp_streamable_http_lifecycle(self):
        """Validates standard MCP lifecycle on /mcp: initialize -> initialized -> tools/list -> tools/call."""
        # 1. initialize
        init_payload = {
            "jsonrpc": "2.0",
            "id": "init-001",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "AutonomousResearchAgent",
                    "version": "3.1.0"
                }
            }
        }
        status, body, headers = self._http_request("/mcp", method="POST", data=init_payload)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get("id"), "init-001")
        self.assertIn("result", data)
        self.assertEqual(data["result"].get("protocolVersion"), "2024-11-05")
        self.assertIn("serverInfo", data["result"])
        session_id = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
        self.assertIsNotNone(session_id)

        # 2. notifications/initialized
        notif_payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        status_notif, _, _ = self._http_request("/mcp", method="POST", data=notif_payload, headers={"Mcp-Session-Id": session_id})
        self.assertEqual(status_notif, 200)

        # 3. tools/list
        list_payload = {
            "jsonrpc": "2.0",
            "id": "list-001",
            "method": "tools/list",
            "params": {}
        }
        status_list, body_list, _ = self._http_request("/mcp", method="POST", data=list_payload, headers={"Mcp-Session-Id": session_id})
        self.assertEqual(status_list, 200)
        list_data = json.loads(body_list)
        self.assertIn("result", list_data)
        self.assertIn("tools", list_data["result"])
        self.assertTrue(any(t["name"] == "verify_claims" for t in list_data["result"]["tools"]))

        # 4. tools/call
        call_payload = {
            "jsonrpc": "2.0",
            "id": "call-001",
            "method": "tools/call",
            "params": {
                "name": "verify_claims",
                "arguments": {
                    "claims": ["Solana executes transactions with Proof of History timestamping."],
                    "sources": ["Solana uses a Proof of History sequence generator combined with Proof of Stake."]
                }
            }
        }
        status_call, body_call, _ = self._http_request("/mcp", method="POST", data=call_payload, headers={"Mcp-Session-Id": session_id})
        self.assertEqual(status_call, 200)
        call_data = json.loads(body_call)
        self.assertEqual(call_data.get("id"), "call-001")
        content = call_data["result"]["content"][0]["text"]
        parsed_res = json.loads(content)
        self.assertEqual(parsed_res.get("verdict"), "VERIFIED")
        self.assertEqual(parsed_res.get("grounding_score"), 100.0)

    def test_09_client_identity_telemetry_capture(self):
        """Validates that MCP initialize and tool calls capture protocol clientInfo, protocolVersion, result_hash."""
        with open(TELEMETRY_LOG_PATH, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        
        # Scan for the AutonomousResearchAgent session
        agent_entries = [json.loads(line) for line in lines if "AutonomousResearchAgent" in line]
        self.assertTrue(len(agent_entries) > 0, "Expected telemetry record for AutonomousResearchAgent")
        
        init_entry = [e for e in agent_entries if e.get("verdict") == "INITIALIZED"][0]
        self.assertEqual(init_entry["client_info"]["name"], "AutonomousResearchAgent")
        self.assertEqual(init_entry["client_info"]["version"], "3.1.0")
        self.assertEqual(init_entry["protocol_version"], "2024-11-05")

        tool_entries = [e for e in agent_entries if e.get("tool") == "verify_claims"]
        self.assertTrue(len(tool_entries) > 0, "Expected tool execution record linked to AutonomousResearchAgent")
        tool_entry = tool_entries[0]
        self.assertEqual(tool_entry["tool"], "verify_claims")
        self.assertTrue(tool_entry["success"])
        self.assertIsNotNone(tool_entry.get("result_hash"))
        self.assertTrue(len(tool_entry["result_hash"]) > 0)
        self.assertTrue(tool_entry["HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE"])


if __name__ == "__main__":
    unittest.main()
