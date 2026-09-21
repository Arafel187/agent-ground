# AgentGround: Factual Grounding & Claim Cross-Check Verifier for AI Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![A2A Compatible](https://img.shields.io/badge/A2A-agent--card.json-purple.svg)](https://a2a-protocol.org)

**AgentGround** is a deterministic factual grounding and cross-check verification engine built for autonomous AI agents, multi-agent systems, and research pipelines.

It eliminates hallucinations, detects numerical drift and entity mismatch, audits unverified assertions, and outputs sentence-level verification verdicts and factual grounding confidence scores (0.0 to 100.0).

---

## 1. Core Specification

| Field | Value |
| :--- | :--- |
| **Name** | `AgentGround Cross-Check Verifier` |
| **Job To Be Done** | Cross-verify candidate agent statements against provided source texts to compute factual grounding, detect unverified assertions/hallucinations, and output machine-readable confidence scores. |
| **When To Use** | Immediately after web search or document scraping; prior to executing irreversible tool actions, on-chain transactions, or filing research briefs. |
| **Protocol Support** | Model Context Protocol (MCP stdio), A2A Protocol v1.0, HTTP REST JSON, x402 v2 Bazaar |
| **Benchmark Quality** | **9/9 CURRENT BENCHMARK SCENARIOS PASSED** (Supported, Unsupported, Numeric Mismatch, Entity Mismatch, Partial Evidence, Contradiction, Insufficient Evidence, Adversarial Overlap, Semantic Paraphrasing) |
| **Local Engine Latency** | **0.05ms – 0.17ms** (deterministic sub-millisecond local execution) |
| **Public End-to-End Latency** | **UNKNOWN** (pending actual public external request benchmark) |
| **Evaluation Mode** | Nonfinancial Free Evaluation Tier enabled (`X-Evaluation: free-trial`) |

---

## 2. Quickstart & Installation

### Option A: Install via Smithery (Cursor / Claude Desktop / Cline)
```bash
npx -y @smithery/cli install Arafel187/agent-ground
```

### Option B: Run via Python directly
```bash
git clone https://github.com/Arafel187/agent-ground.git
cd agent-ground
pip install -r requirements.txt

# Run as Model Context Protocol (MCP) Server over stdio
python agent_ground.py --mcp

# Or run as HTTP REST / A2A server
python agent_ground.py 8092
```

### Option C: Run as Canonical Remote MCP Gateway (Streamable HTTP /mcp)
```bash
# Starts high-throughput remote invocation gateway on port 8095
python agent_ground.py --remote

# Healthcheck
curl http://localhost:8095/health

# MCP Streamable HTTP Endpoint (Canonical MCP lifecycle: initialize, tools/list, tools/call)
curl -X POST http://localhost:8095/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "ExampleAgent", "version": "1.0.0"}}}'

# Direct Claim Verification (REST)
curl -X POST http://localhost:8095/api/v1/verify-claims \
  -H "Content-Type: application/json" \
  -d '{"claims": ["Base network is an Ethereum Layer 2."], "sources": ["Base is an Ethereum Layer 2 incubated by Coinbase."]}'
```

### Glama MCP Inspector Compatibility
AgentGround's remote gateway is natively compatible with [Glama MCP Inspector](https://glama.ai/mcp/inspector):
- Connect directly via URL parameter:
  `https://glama.ai/mcp/inspector?servers=[{"name":"AgentGround","url":"https://agentground.atlether.trade/mcp"}]`
- Supports standard Streamable HTTP (`/mcp`), Server-Sent Events (`/sse`), and legacy JSON-RPC (`/rpc`).
- Fully compliant with both **MCP 2026-07-28** (self-contained requests) and **MCP 2024-11-05** (initialize handshake).

---

## 3. Autonomous Multi-Agent Framework Integration

### CrewAI (`MCPServerHTTP`)
Connect any CrewAI researcher or fact-checker agent directly to AgentGround without writing custom verification code:
```python
from crewai import Agent
from crewai.mcp import MCPServerHTTP

fact_checker = Agent(
    role="Factual Grounding Specialist",
    goal="Verify assertions and detect hallucinations against research sources",
    mcps=[
        MCPServerHTTP(
            url="https://agentground.atlether.trade/mcp",
            streamable=True
        )
    ]
)
```

### AutoGen (`StreamableHttpMcpToolAdapter`)
```python
from autogen_ext.tools.mcp import StreamableHttpServerParams, StreamableHttpMcpToolAdapter

params = StreamableHttpServerParams(url="https://agentground.atlether.trade/mcp")
verifier_tool = StreamableHttpMcpToolAdapter(params=params)
```

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "agent-ground": {
      "command": "python",
      "args": ["-m", "agent_ground_service", "--mcp"],
      "cwd": "/path/to/agent-ground"
    }
  }
}
```

### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "agent-ground": {
      "command": "python",
      "args": ["-m", "agent_ground_service", "--mcp"]
    }
  }
}
```

---

## 4. Input & Output Schema

### Tool: `verify_claims`

#### Input Schema
```json
{
  "claims": [
    "Base network processed over 5 million transactions yesterday.",
    "USDC is a fiat-collateralized stablecoin issued by Circle."
  ],
  "sources": [
    "Official blockchain telemetry reveals Base network processed over 5.2 million transactions yesterday.",
    "Circle issues USDC as a fully reserved, fiat-collateralized digital dollar."
  ],
  "mode": "balanced"
}
```

#### Output Schema
```json
{
  "verdict": "VERIFIED",
  "grounding_score": 100.0,
  "claims_count": 2,
  "verified_count": 2,
  "ungrounded_count": 0,
  "contradicted_count": 0,
  "claim_results": [
    {
      "claim_index": 0,
      "claim": "Base network processed over 5 million transactions yesterday.",
      "status": "VERIFIED_GROUNDED",
      "confidence": 0.95,
      "matched_source_index": 0,
      "evidence_snippet": "Official blockchain telemetry reveals Base network processed over 5.2 million transactions yesterday."
    },
    {
      "claim_index": 1,
      "claim": "USDC is a fiat-collateralized stablecoin issued by Circle.",
      "status": "VERIFIED_GROUNDED",
      "confidence": 0.95,
      "matched_source_index": 1,
      "evidence_snippet": "Circle issues USDC as a fully reserved, fiat-collateralized digital dollar."
    }
  ],
  "timestamp": "2026-09-11T17:40:00Z"
}
```

---

## 5. HTTP & A2A Discovery Routes

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/.well-known/agent-card.json` | **Canonical A2A Agent Card** conforming to A2A specification |
| `GET` | `/.well-known/agent.json` | Backward-compatibility alias |
| `GET` | `/llms.txt` | Machine-readable system guide for AI agents |
| `GET` | `/api/v1/health` | Service health and capability check |
| `GET` | `/pricing` | Canonical machine-readable commercial pricing catalog |
| `POST` | `/api/v1/request-invoice` | Request commercial invoice or prepaid verification credits |
| `POST` | `/api/v1/verify-claims` | Factual grounding evaluation endpoint |

---

## 6. Commercial Pricing & Real Settlement (USDC / USDT)

AgentGround operates on transparent, commercial pricing with zero hidden fees.

| Tier | Price (Hypothesis) | Allowance / Rate | Features & Delivery |
| :--- | :--- | :--- | :--- |
| **Free Evaluation** | $0.00 | 60 requests/minute | Public evaluation via hosted gateway (`https://agentground.atlether.trade/mcp`). |
| **Metered Prepaid** | $0.001 / query | 1,000 queries per $1.00 USDC/USDT (min pack $5.00) | Pay-as-you-go balance, priority queue, programmatic invoice generation (Pricing Hypothesis). |
| **Pro Monthly** | 25 USDC / month | 50,000 queries/month included ($0.0008 overage) | Dedicated API capacity, burst allowance (Pricing Hypothesis). |
| **Enterprise Pilot** | 250 USDC | 90-day pilot | Dedicated high-concurrency instance, custom domain schema, engineering integration support (Negotiable Pilot Scope). |

> *Note on Pricing:* All tiers represent commercial pricing hypotheses open to discussion and tailoring for specific customer workflows. No contractual uptime SLAs are offered without explicit prior approval from the eligible adult account holder.

### How to Request an Invoice Programmatically
Agents and developers can programmatically request an invoice and lock in capacity:
```bash
curl -X POST https://agentground.atlether.trade/api/v1/request-invoice \
  -H "Content-Type: application/json" \
  -d '{
    "customer_ref": "your-agent-id@example.com",
    "product_id": "PA-001",
    "tier": "METERED_PREPAID",
    "currency": "USDC",
    "amount_usd": 10.0
  }'
```

> **Financial Boundary Notice:** In accordance with our security policy, all settlement instructions are reviewed and confirmed by an eligible adult account holder. Autonomous agents do not hold private keys or execute unauthorized fund transfers.

---

## 7. Error States & Status Codes

- `200 OK`: Successful verification execution.
- `400 Bad Request`: Malformed JSON or missing required arrays (`claims`, `sources`).
- `402 Payment Required`: Mainnet mode when not using the free evaluation tier. Includes RFC/CDP compliant x402 Base64 `PAYMENT-REQUIRED` header.
- `413 Payload Too Large`: Request body exceeds 1MB limit.
- `500 Server Error`: Internal verification engine failure.

---

## 7. Capability Limits & Edge Cases

- **Deterministic Lexical & Semantic Overlap**: Computes exact numeric equality, named entity containment, antonym polarities, and token overlap.
- **Explicit Source Requirement**: Does not perform autonomous open-web crawling inside the verification call (source documents or snippets must be supplied by the caller).
- **Throughput**: Sub-millisecond deterministic evaluation; optimal for 1 to 50 claims per request.

---

## License
MIT License. Copyright (c) 2026 Arafel187.
