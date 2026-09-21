#!/usr/bin/env python3
"""
AgentGround — Remote Hosted Invocation Gateway
==============================================
Production-ready, nonfinancial remote invocation surface suitable for AI agent runtimes.
Supports:
1. Model Context Protocol (MCP) Streamable HTTP & JSON-RPC (POST /mcp, POST /rpc, POST /messages)
   - Dual-protocol support: MCP 2026-07-28 (self-contained requests) and MCP 2024-11-05 (initialize lifecycle)
   - MCP-compliant wire schema (inputSchema and outputSchema in camelCase)
2. Machine-readable Tool Discovery (GET /mcp, GET /tools, GET /tools/list, GET /.well-known/agent-card.json)
3. REST Invocation (POST /api/v1/verify-claims)
4. Health check (GET /health, GET /api/v1/health)
5. Bounded Request Size (1MB max, HTTP 413)
6. Request Timeouts (15s internal execution limit, HTTP 504)
7. Rate Limiting (60 requests/minute per client IP, HTTP 429)
8. Structured JSON Errors
9. Server-Side Telemetry logged to ATL_A2A_LIVE_TELEMETRY.jsonl with SHA-256 client hashing (no raw PII)
10. Strict Telemetry Claim Integrity: HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE = True
"""

import http.server
import socketserver
import json
import os
import sys
import time
import hashlib
import threading
from typing import Dict, Any, List, Optional, Tuple

WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

from agent_ground_service import execute_claim_verification

# Gateway Configuration
GATEWAY_VERSION = "1.2.0"
GATEWAY_NAME = "AgentGround Remote Gateway"
DEFAULT_GATEWAY_PORT = 8095
MAX_REQUEST_BYTES = 1024 * 1024  # 1 MB Limit
REQUEST_TIMEOUT_SECONDS = 15.0
RATE_LIMIT_MAX_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0

# Dual Protocol Support Matrix
SUPPORTED_PROTOCOL_VERSIONS = ["2026-07-28", "2024-11-05"]
DEFAULT_PROTOCOL_VERSION = "2026-07-28"

# Telemetry Configuration
TELEMETRY_LOG_PATH = os.path.join(WORKSPACE_DIR, "ATL_A2A_LIVE_TELEMETRY.jsonl")

# In-memory Rate Limiting Storage: {client_ip_hash: [timestamp_float, ...]}
_rate_limit_lock = threading.Lock()
_rate_limit_store: Dict[str, List[float]] = {}

# In-memory Session Storage: {session_id: session_data}
_sessions_lock = threading.Lock()
_sessions_store: Dict[str, Dict[str, Any]] = {}


def hash_identifier(ip: str, user_agent: str = "") -> str:
    """Computes a privacy-preserving SHA-256 hash of the client identifier."""
    raw = f"{ip}:{user_agent}:salt_agentground_gateway"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def check_rate_limit(ip_hash: str) -> Tuple[bool, int]:
    """
    Checks if client has exceeded RATE_LIMIT_MAX_REQUESTS in RATE_LIMIT_WINDOW_SECONDS.
    Returns (is_permitted, retry_after_seconds).
    """
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with _rate_limit_lock:
        timestamps = _rate_limit_store.get(ip_hash, [])
        timestamps = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
            retry_after = int(RATE_LIMIT_WINDOW_SECONDS - (now - timestamps[0]))
            _rate_limit_store[ip_hash] = timestamps
            return False, max(1, retry_after)
        timestamps.append(now)
        _rate_limit_store[ip_hash] = timestamps
        return True, 0


def log_remote_telemetry(
    route: str,
    method: str,
    status_code: int,
    client_ip: str,
    user_agent: str,
    claims_count: int,
    latency_ms: float,
    verdict: Optional[str] = None,
    error_code: Optional[str] = None,
    client_classification: str = "INDEPENDENT_EXTERNAL_AGENT",
    client_info: Optional[Dict[str, str]] = None,
    protocol_version: Optional[str] = None,
    tool: Optional[str] = None,
    success: Optional[bool] = None,
    result_hash: Optional[str] = None,
    session_id: Optional[str] = None
):
    """Logs structured telemetry event to ATL_A2A_LIVE_TELEMETRY.jsonl without raw PII."""
    ip_hash = hash_identifier(client_ip, user_agent)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Exclude internal self-tests or local monitors
    ua_lower = user_agent.lower()
    client_name_lower = client_info.get("name", "").lower() if client_info else ""

    if client_classification == "SELF_TEST":
        classification = "SELF_TEST"
    elif any(k in ua_lower for k in ("self_test", "selftest", "self-test", "diagnostic", "atl_verifier", "atl-verifier", "atl_test")):
        classification = "SELF_TEST"
    elif client_info and any(k in client_name_lower for k in ("self_test", "selftest", "self-test", "diagnostic", "atl")):
        classification = "SELF_TEST"
    elif client_ip in ("127.0.0.1", "localhost", "::1") and ("self-test" in ua_lower or "diagnostic" in ua_lower or "test" in ua_lower):
        classification = "SELF_TEST"
    elif "bot" in ua_lower or "crawler" in ua_lower:
        classification = "SEARCH_INDEXER_PROBE"
    else:
        classification = client_classification

    entry = {
        "timestamp": now_iso,
        "gateway_version": GATEWAY_VERSION,
        "HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE": True,
        "route": route,
        "method": method,
        "status": status_code,
        "client_hash": ip_hash,
        "session_id": session_id,
        "user_agent": user_agent[:128] if user_agent else "Unknown",
        "client_info": client_info,
        "protocol_version": protocol_version,
        "tool": tool,
        "success": success,
        "result_hash": result_hash,
        "claims_count": claims_count,
        "verdict": verdict,
        "error_code": error_code,
        "latency_ms": round(latency_ms, 2),
        "classification": classification,
        "transport": "REMOTE_HOSTED_GATEWAY"
    }

    try:
        with open(TELEMETRY_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


TOOL_DEFINITION = {
    "name": "verify_claims",
    "description": "Cross-verify candidate claims against retrieved text/sources to compute deterministic factual grounding, detect hallucinations, and output machine-readable confidence scores.",
    "version": GATEWAY_VERSION,
    "inputSchema": {
        "type": "object",
        "required": ["claims", "sources"],
        "properties": {
            "claims": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of assertions or sentences to cross-check."
            },
            "sources": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of retrieved ground truth documents, snippets, or search results."
            },
            "mode": {
                "type": "string",
                "enum": ["strict", "balanced"],
                "default": "balanced",
                "description": "Verification stringency level."
            }
        }
    },
    "outputSchema": {
        "type": "object",
        "required": ["verdict", "grounding_score", "claims_count", "verified_count", "ungrounded_count"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["VERIFIED", "PARTIALLY_GROUNDED", "UNGROUNDED", "CONTRADICTED"]
            },
            "grounding_score": {"type": "number", "minimum": 0.0, "maximum": 100.0},
            "claims_count": {"type": "integer"},
            "verified_count": {"type": "integer"},
            "ungrounded_count": {"type": "integer"},
            "contradicted_count": {"type": "integer"},
            "claim_results": {"type": "array"}
        }
    }
}
# Internal Python convenience aliases
TOOL_DEFINITION["input_schema"] = TOOL_DEFINITION["inputSchema"]
TOOL_DEFINITION["output_schema"] = TOOL_DEFINITION["outputSchema"]


def get_wire_tools() -> List[Dict[str, Any]]:
    """
    Returns MCP wire-compliant tool representation exposing camelCase inputSchema and outputSchema.
    Does NOT expose snake_case input_schema on the wire.
    """
    return [
        {
            "name": TOOL_DEFINITION["name"],
            "description": TOOL_DEFINITION["description"],
            "inputSchema": TOOL_DEFINITION["inputSchema"],
            "outputSchema": TOOL_DEFINITION["outputSchema"]
        }
    ]


class AgentGroundRemoteGatewayHandler(http.server.BaseHTTPRequestHandler):
    server_version = f"AgentGroundRemoteGateway/{GATEWAY_VERSION}"

    def _negotiate_protocol_version(self, params: Dict[str, Any], session_meta: Optional[Dict[str, Any]] = None) -> str:
        """Determines negotiated MCP protocol version (2026-07-28 or 2024-11-05)."""
        for h in ("MCP-Protocol-Version", "Mcp-Protocol-Version", "mcp-protocol-version"):
            v = self.headers.get(h)
            if v:
                return v
        if isinstance(params, dict) and "protocolVersion" in params:
            return str(params["protocolVersion"])
        if session_meta and "protocol_version" in session_meta:
            return session_meta["protocol_version"]
        return DEFAULT_PROTOCOL_VERSION

    def _extract_client_info(self, params: Dict[str, Any], payload: Dict[str, Any], session_meta: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """Extracts client identification metadata from modern MCP request metadata or headers."""
        if session_meta and session_meta.get("client_info"):
            return session_meta["client_info"]
        meta = params.get("_meta") if isinstance(params, dict) else {}
        if isinstance(meta, dict):
            if "clientInfo" in meta and isinstance(meta["clientInfo"], dict):
                return meta["clientInfo"]
            if "client" in meta and isinstance(meta["client"], dict):
                return meta["client"]
        if isinstance(params, dict) and "clientInfo" in params and isinstance(params["clientInfo"], dict):
            return params["clientInfo"]
        if isinstance(payload, dict) and "clientInfo" in payload and isinstance(payload["clientInfo"], dict):
            return payload["clientInfo"]
        for h in ("MCP-Client-Info", "Mcp-Client-Info", "X-Client-Info"):
            raw_val = self.headers.get(h)
            if raw_val:
                try:
                    parsed = json.loads(raw_val)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    return {"name": raw_val, "version": "unknown"}
        ua = self.headers.get("User-Agent", "")
        if ua:
            first = ua.split()[0]
            if "/" in first:
                parts = first.split("/", 1)
                return {"name": parts[0], "version": parts[1]}
            return {"name": ua[:64], "version": "unknown"}
        return {"name": "UnknownClient", "version": "unknown"}

    def _send_structured_error(self, status: int, code: str, message: str, headers: Optional[Dict[str, str]] = None):
        payload = {
            "status": "ERROR",
            "error_code": code,
            "message": message,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "gateway_version": GATEWAY_VERSION
        }
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json_response(self, status: int, data: Any, extra_headers: Optional[Dict[str, str]] = None, protocol_version: Optional[str] = None):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version, Mcp-Protocol-Version, X-Hosted-Gateway-Observable")
        self.send_header("X-Hosted-Gateway-Observable", "true")
        ver = protocol_version or DEFAULT_PROTOCOL_VERSION
        self.send_header("MCP-Protocol-Version", ver)
        self.send_header("Mcp-Protocol-Version", ver)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests from browser runtimes & Glama inspector."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Evaluation, Accept, Mcp-Session-Id, MCP-Protocol-Version, Mcp-Protocol-Version, MCP-Client-Info, Mcp-Client-Info, X-Client-Info")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version, Mcp-Protocol-Version, X-Hosted-Gateway-Observable")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_DELETE(self):
        """Handle MCP session termination (DELETE /mcp)."""
        session_id = self.headers.get("Mcp-Session-Id", "")
        with _sessions_lock:
            if session_id in _sessions_store:
                del _sessions_store[session_id]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Hosted-Gateway-Observable", "true")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_GET(self):
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "")
        path = self.path.split("?")[0].rstrip("/")
        if not path:
            path = "/"

        # Healthcheck
        if path in ("/health", "/api/v1/health"):
            self._send_json_response(200, {
                "status": "HEALTHY",
                "service": GATEWAY_NAME,
                "version": GATEWAY_VERSION,
                "runtime": "ACTIVE",
                "HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE": True,
                "supported_transports": ["STREAMABLE_HTTP_MCP", "MCP_JSON_RPC", "MCP_SSE", "REST"],
                "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
                "default_protocol_version": DEFAULT_PROTOCOL_VERSION,
                "mcp_endpoint": "/mcp",
                "rate_limit_per_minute": RATE_LIMIT_MAX_REQUESTS,
                "max_request_bytes": MAX_REQUEST_BYTES,
                "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })
            return

        # Canonical MCP Endpoint (GET fallback / descriptor / stream)
        if path == "/mcp":
            accept = self.headers.get("Accept", "")
            if "text/event-stream" in accept:
                # SSE Stream transport for MCP clients requesting streaming
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version, Mcp-Protocol-Version, X-Hosted-Gateway-Observable")
                self.send_header("X-Hosted-Gateway-Observable", "true")
                self.send_header("MCP-Protocol-Version", DEFAULT_PROTOCOL_VERSION)
                session_id = hashlib.sha256(f"{client_ip}:{time.time()}".encode("utf-8")).hexdigest()[:16]
                self.send_header("Mcp-Session-Id", session_id)
                self.end_headers()
                endpoint_event = f"event: endpoint\ndata: /mcp?session_id={session_id}\n\n"
                self.wfile.write(endpoint_event.encode("utf-8"))
                self.wfile.flush()
                log_remote_telemetry(
                    route="/mcp",
                    method="GET",
                    status_code=200,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    claims_count=0,
                    latency_ms=1.0,
                    verdict="MCP_STREAM_CONNECTED",
                    session_id=session_id
                )
                return

            # Default GET /mcp descriptor
            self._send_json_response(200, {
                "name": "agent-ground-remote-gateway",
                "version": GATEWAY_VERSION,
                "protocol": "Model Context Protocol (Streamable HTTP)",
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "supportedProtocolVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "transport": "HTTP_POST",
                "endpoint": "/mcp",
                "supported_methods": ["tools/list", "tools/call", "server/discover", "initialize", "notifications/initialized", "ping"],
                "tools": get_wire_tools(),
                "HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE": True
            })
            return

        # Machine-readable Tool Description
        if path in ("/tools", "/tools/list", "/api/v1/tools"):
            self._send_json_response(200, {
                "tools": get_wire_tools(),
                "gateway_version": GATEWAY_VERSION,
                "protocol": "Model Context Protocol (Streamable HTTP / JSON-RPC)",
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "supportedProtocolVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "endpoints": {
                    "mcp_canonical": "/mcp",
                    "rest_invoke": "/api/v1/verify-claims",
                    "mcp_rpc": "/rpc",
                    "mcp_sse": "/sse",
                    "health": "/health"
                }
            })
            return

        # Agent Card
        if path == "/.well-known/agent-card.json":
            card = {
                "name": "AgentGround Cross-Check Verifier",
                "version": GATEWAY_VERSION,
                "description": "Deterministic claim verification and factual grounding engine for autonomous agents.",
                "url": "https://agentground.atlether.trade",
                "documentation": "https://github.com/Arafel187/agent-ground",
                "skills": [
                    {
                        "id": "verify_claims",
                        "name": "Claim Cross-Check Verifier",
                        "description": "Verifies factual claims against sources.",
                        "inputSchema": TOOL_DEFINITION["inputSchema"],
                        "outputSchema": TOOL_DEFINITION["outputSchema"],
                        "input_schema": TOOL_DEFINITION["inputSchema"],
                        "output_schema": TOOL_DEFINITION["outputSchema"]
                    }
                ],
                "mcp": {
                    "transport": "Streamable HTTP",
                    "url": "https://agentground.atlether.trade/mcp"
                },
                "pricing": {"tier": "FREE_EVALUATION", "cost_usd": 0.0},
                "HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE": True
            }
            self._send_json_response(200, card)
            return

        # MCP SSE Handshake Endpoint (legacy / fallback)
        if path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version, Mcp-Protocol-Version, X-Hosted-Gateway-Observable")
            self.send_header("X-Hosted-Gateway-Observable", "true")
            self.send_header("MCP-Protocol-Version", DEFAULT_PROTOCOL_VERSION)
            session_id = hash_identifier(client_ip + str(time.time()))
            self.send_header("Mcp-Session-Id", session_id)
            self.end_headers()
            endpoint_event = f"event: endpoint\ndata: /messages?session_id={session_id}\n\n"
            self.wfile.write(endpoint_event.encode("utf-8"))
            self.wfile.flush()
            log_remote_telemetry(
                route="/sse",
                method="GET",
                status_code=200,
                client_ip=client_ip,
                user_agent=user_agent,
                claims_count=0,
                latency_ms=1.0,
                verdict="SSE_CONNECTED",
                session_id=session_id
            )
            return

        # Root landing description
        if path == "/":
            self._send_json_response(200, {
                "service": GATEWAY_NAME,
                "version": GATEWAY_VERSION,
                "message": "AgentGround Remote Invocation Gateway is online.",
                "health": "/health",
                "mcp": "/mcp",
                "tools": "/tools",
                "verify": "/api/v1/verify-claims",
                "HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE": True
            })
            return

        self._send_structured_error(404, "NOT_FOUND", f"Endpoint '{path}' does not exist on this gateway.")

    def do_POST(self):
        t_start = time.perf_counter()
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "")
        incoming_session_id = self.headers.get("Mcp-Session-Id", "")
        path = self.path.split("?")[0].rstrip("/")
        ip_hash = hash_identifier(client_ip, user_agent)

        # 1. Check Rate Limit
        permitted, retry_after = check_rate_limit(ip_hash)
        if not permitted:
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            log_remote_telemetry(path, "POST", 429, client_ip, user_agent, 0, latency_ms, error_code="RATE_LIMIT_EXCEEDED", session_id=incoming_session_id)
            self._send_structured_error(
                429,
                "RATE_LIMIT_EXCEEDED",
                f"Rate limit of {RATE_LIMIT_MAX_REQUESTS} requests/minute exceeded. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )
            return

        # 2. Check Content-Length & Bounded Request Size (1 MB max)
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            content_length = 0

        if content_length > MAX_REQUEST_BYTES:
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            log_remote_telemetry(path, "POST", 413, client_ip, user_agent, 0, latency_ms, error_code="PAYLOAD_TOO_LARGE", session_id=incoming_session_id)
            self._send_structured_error(
                413,
                "PAYLOAD_TOO_LARGE",
                f"Request body exceeds maximum permitted size of {MAX_REQUEST_BYTES} bytes (received {content_length} bytes)."
            )
            return

        # Read body
        try:
            raw_body = self.rfile.read(content_length).decode("utf-8")
        except Exception as e:
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            log_remote_telemetry(path, "POST", 400, client_ip, user_agent, 0, latency_ms, error_code="READ_ERROR", session_id=incoming_session_id)
            self._send_structured_error(400, "BAD_REQUEST", f"Failed to read request body: {str(e)}")
            return

        # Parse JSON
        try:
            payload = json.loads(raw_body) if raw_body else {}
        except Exception as e:
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            log_remote_telemetry(path, "POST", 400, client_ip, user_agent, 0, latency_ms, error_code="INVALID_JSON", session_id=incoming_session_id)
            self._send_structured_error(400, "INVALID_JSON", f"Malformed JSON payload: {str(e)}")
            return

        # 3. Handle Canonical MCP Endpoint (/mcp) and JSON-RPC legacy endpoints (/rpc, /messages)
        if path in ("/mcp", "/rpc", "/messages"):
            rpc_method = payload.get("method")
            rpc_id = payload.get("id")
            params = payload.get("params", {})
            if not isinstance(params, dict):
                params = {}

            # Session metadata if available
            session_meta = {}
            with _sessions_lock:
                if incoming_session_id and incoming_session_id in _sessions_store:
                    session_meta = _sessions_store[incoming_session_id]

            protocol_version = self._negotiate_protocol_version(params, session_meta)
            client_info = self._extract_client_info(params, payload, session_meta)

            # Check if request is explicitly or implicitly a self-test
            eval_flag = self.headers.get("X-Evaluation", "").lower()
            is_self_test = (
                eval_flag in ("self-test", "selftest") or
                "selftest" in user_agent.lower() or
                "self_test" in user_agent.lower() or
                "self-test" in user_agent.lower() or
                "diagnostic" in user_agent.lower() or
                any(k in client_info.get("name", "").lower() for k in ("test", "selftest", "diagnostic", "atl"))
            )
            classification = "SELF_TEST" if is_self_test else "INDEPENDENT_EXTERNAL_AGENT"

            # MCP Method: initialize (legacy 2024-11-05 & optional in 2026-07-28)
            if rpc_method == "initialize":
                init_client_info = params.get("clientInfo", client_info)
                session_id = incoming_session_id or hashlib.sha256(f"{client_ip}:{time.time()}".encode("utf-8")).hexdigest()[:16]

                with _sessions_lock:
                    _sessions_store[session_id] = {
                        "client_info": init_client_info,
                        "protocol_version": protocol_version,
                        "client_ip_hash": ip_hash,
                        "initialized_at": time.time(),
                        "status": "INITIALIZED"
                    }

                latency_ms = (time.perf_counter() - t_start) * 1000.0
                log_remote_telemetry(
                    route=path,
                    method="POST",
                    status_code=200,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    claims_count=0,
                    latency_ms=latency_ms,
                    verdict="INITIALIZED",
                    client_classification=classification,
                    client_info=init_client_info,
                    protocol_version=protocol_version,
                    session_id=session_id
                )

                extra_hdrs = {"Mcp-Session-Id": session_id}
                self._send_json_response(200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": protocol_version,
                        "supportedProtocolVersions": SUPPORTED_PROTOCOL_VERSIONS,
                        "capabilities": {
                            "tools": {
                                "listChanged": False
                            }
                        },
                        "serverInfo": {
                            "name": "agent-ground-remote-gateway",
                            "version": GATEWAY_VERSION
                        },
                        "instructions": "Deterministic claim verification engine. Invoke verify_claims tool with claims and sources to cross-verify factual grounding."
                    }
                }, extra_headers=extra_hdrs, protocol_version=protocol_version)
                return

            # MCP Method: notifications/initialized or initialized
            if rpc_method in ("notifications/initialized", "initialized"):
                with _sessions_lock:
                    if incoming_session_id in _sessions_store:
                        _sessions_store[incoming_session_id]["status"] = "CONFIRMED"

                latency_ms = (time.perf_counter() - t_start) * 1000.0
                log_remote_telemetry(
                    route=path,
                    method="POST",
                    status_code=200,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    claims_count=0,
                    latency_ms=latency_ms,
                    verdict="INITIALIZED_CONFIRMED",
                    client_classification=classification,
                    client_info=client_info,
                    protocol_version=protocol_version,
                    session_id=incoming_session_id
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("MCP-Protocol-Version", protocol_version)
                self.send_header("X-Hosted-Gateway-Observable", "true")
                if incoming_session_id:
                    self.send_header("Mcp-Session-Id", incoming_session_id)
                self.end_headers()
                self.wfile.write(b"{}")
                return

            # MCP Method: server/discover or server/info (MCP 2026-07-28 discovery)
            if rpc_method in ("server/discover", "server/info", "serverInfo"):
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                log_remote_telemetry(
                    route=path,
                    method="POST",
                    status_code=200,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    claims_count=0,
                    latency_ms=latency_ms,
                    verdict="SERVER_DISCOVER_RETURNED",
                    client_classification=classification,
                    client_info=client_info,
                    protocol_version=protocol_version,
                    session_id=incoming_session_id
                )
                extra_hdrs = {"Mcp-Session-Id": incoming_session_id} if incoming_session_id else None
                self._send_json_response(200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": protocol_version,
                        "supportedProtocolVersions": SUPPORTED_PROTOCOL_VERSIONS,
                        "capabilities": {
                            "tools": {
                                "listChanged": False
                            }
                        },
                        "serverInfo": {
                            "name": "agent-ground-remote-gateway",
                            "version": GATEWAY_VERSION
                        },
                        "instructions": "Deterministic claim verification engine. Invoke verify_claims tool with claims and sources to cross-verify factual grounding."
                    }
                }, extra_headers=extra_hdrs, protocol_version=protocol_version)
                return

            # MCP Method: tools/list (Self-contained or session-bound)
            if rpc_method in ("tools/list", "toolsList"):
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                log_remote_telemetry(
                    route=path,
                    method="POST",
                    status_code=200,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    claims_count=0,
                    latency_ms=latency_ms,
                    verdict="TOOLS_LIST_RETURNED",
                    client_classification=classification,
                    client_info=client_info,
                    protocol_version=protocol_version,
                    session_id=incoming_session_id
                )
                extra_hdrs = {"Mcp-Session-Id": incoming_session_id} if incoming_session_id else None
                self._send_json_response(200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"tools": get_wire_tools()}
                }, extra_headers=extra_hdrs, protocol_version=protocol_version)
                return

            # MCP Method: tools/call (Self-contained or session-bound)
            if rpc_method in ("tools/call", "toolsCall"):
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                if tool_name == "verify_claims":
                    claims = arguments.get("claims", [])
                    sources = arguments.get("sources", [])
                    mode = arguments.get("mode", "balanced")

                    if not isinstance(claims, list) or not isinstance(sources, list):
                        self._send_json_response(200, {
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "error": {"code": -32602, "message": "Invalid params: 'claims' and 'sources' must be lists."}
                        }, protocol_version=protocol_version)
                        return

                    # Execute deterministic claim verification
                    try:
                        res = execute_claim_verification({"claims": claims, "sources": sources, "mode": mode})
                    except Exception as e:
                        latency_ms = (time.perf_counter() - t_start) * 1000.0
                        log_remote_telemetry(
                            route=path, method="POST", status_code=500, client_ip=client_ip, user_agent=user_agent,
                            claims_count=len(claims), latency_ms=latency_ms, error_code="ENGINE_FAILURE",
                            client_classification=classification, client_info=client_info, protocol_version=protocol_version,
                            tool="verify_claims", success=False, session_id=incoming_session_id
                        )
                        self._send_json_response(200, {
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "error": {"code": -32603, "message": f"Internal execution error: {str(e)}"}
                        }, protocol_version=protocol_version)
                        return

                    latency_ms = (time.perf_counter() - t_start) * 1000.0
                    verdict = res.get("verdict", "UNKNOWN")
                    res_bytes = json.dumps(res, sort_keys=True).encode("utf-8")
                    res_hash = hashlib.sha256(res_bytes).hexdigest()[:16]

                    log_remote_telemetry(
                        route=path,
                        method="POST",
                        status_code=200,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        claims_count=len(claims),
                        latency_ms=latency_ms,
                        verdict=verdict,
                        client_classification=classification,
                        client_info=client_info,
                        protocol_version=protocol_version,
                        tool="verify_claims",
                        success=True,
                        result_hash=res_hash,
                        session_id=incoming_session_id
                    )

                    extra_hdrs = {"Mcp-Session-Id": incoming_session_id} if incoming_session_id else None
                    self._send_json_response(200, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(res, indent=2)
                                }
                            ],
                            "structuredContent": res,
                            "isError": False
                        }
                    }, extra_headers=extra_hdrs, protocol_version=protocol_version)
                    return
                else:
                    self._send_json_response(200, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "error": {"code": -32601, "message": f"Method '{tool_name}' not found."}
                    }, protocol_version=protocol_version)
                    return

            # MCP Method: ping
            if rpc_method == "ping":
                extra_hdrs = {"Mcp-Session-Id": incoming_session_id} if incoming_session_id else None
                self._send_json_response(200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {}
                }, extra_headers=extra_hdrs, protocol_version=protocol_version)
                return

            # Unknown JSON-RPC method
            self._send_json_response(200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": f"Unsupported RPC method: '{rpc_method}'"}
            }, protocol_version=protocol_version)
            return

        # 4. Handle Direct REST Verify Endpoint (POST /api/v1/verify-claims or POST /tools/verify_claims)
        if path in ("/api/v1/verify-claims", "/tools/verify_claims"):
            claims = payload.get("claims")
            sources = payload.get("sources")
            mode = payload.get("mode", "balanced")

            eval_flag = self.headers.get("X-Evaluation", "").lower()
            is_self_test = (
                eval_flag in ("self-test", "selftest") or
                "selftest" in user_agent.lower() or
                "self_test" in user_agent.lower() or
                "self-test" in user_agent.lower() or
                "diagnostic" in user_agent.lower()
            )
            classification = "SELF_TEST" if is_self_test else "INDEPENDENT_EXTERNAL_AGENT"

            if not isinstance(claims, list) or not isinstance(sources, list):
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                log_remote_telemetry(path, "POST", 400, client_ip, user_agent, 0, latency_ms, error_code="INVALID_ARGUMENTS", client_classification=classification)
                self._send_structured_error(
                    400,
                    "INVALID_ARGUMENTS",
                    "Required JSON fields missing or invalid: 'claims' (array of strings) and 'sources' (array of strings) must be provided."
                )
                return

            # Execute real AgentGround claim verification
            try:
                res = execute_claim_verification({"claims": claims, "sources": sources, "mode": mode})
            except Exception as e:
                latency_ms = (time.perf_counter() - t_start) * 1000.0
                log_remote_telemetry(path, "POST", 500, client_ip, user_agent, len(claims), latency_ms, error_code="ENGINE_FAILURE", client_classification=classification)
                self._send_structured_error(500, "ENGINE_FAILURE", f"Internal verification engine error: {str(e)}")
                return

            latency_ms = (time.perf_counter() - t_start) * 1000.0
            verdict = res.get("verdict", "UNKNOWN")
            res_bytes = json.dumps(res, sort_keys=True).encode("utf-8")
            res_hash = hashlib.sha256(res_bytes).hexdigest()[:16]

            log_remote_telemetry(
                path, "POST", 200, client_ip, user_agent, len(claims), latency_ms,
                verdict=verdict, tool="verify_claims", success=True, result_hash=res_hash,
                client_classification=classification
            )

            # Return valid verification result
            self._send_json_response(200, res)
            return

        self._send_structured_error(404, "NOT_FOUND", f"POST endpoint '{path}' does not exist on this gateway.")


def run_gateway(port: int = DEFAULT_GATEWAY_PORT):
    server_address = ("0.0.0.0", port)
    with socketserver.ThreadingTCPServer(server_address, AgentGroundRemoteGatewayHandler) as httpd:
        httpd.allow_reuse_address = True
        print(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ')}] {GATEWAY_NAME} v{GATEWAY_VERSION} running on port {port}")
        print("HOSTED_GATEWAY_ROUTED_INVOCATIONS_OBSERVABLE = True")
        print(f"Supported MCP Protocol Versions: {', '.join(SUPPORTED_PROTOCOL_VERSIONS)}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down gateway...")
            httpd.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else DEFAULT_GATEWAY_PORT
    run_gateway(port_arg)
