#!/usr/bin/env python3
"""
ATL — Owner Material Event Notification Service
=================================================
Dispatches critical material owner events through authorized notification channels.

TRANSPORTS SUPPORTED:
1. TELEGRAM_BOT (Primary Remote Transport):
   - Reads ATL_TELEGRAM_BOT_TOKEN or SH3_TELEGRAM_BOT_TOKEN from environment.
   - Target chat: ATL_TELEGRAM_CHAT_ID, SH3_TELEGRAM_CHAT_ID, or authorized default (437715321 / @konstantin187).
2. WINDOWS_TOAST (Local Desktop Notification Transport):
   - Native Windows Toast Notification via Windows.UI.Notifications.
   - Delivers instantly to owner's screen and Windows Notification Center.
3. OWNER_WEBHOOK (Optional Remote Webhook):
   - If ATL_OWNER_WEBHOOK_URL is configured, dispatches JSON payload.

SAFETY INVARIANTS:
- Only MATERIAL events are dispatched (SETTLEMENT_APPROVAL_REQUIRED, FIRST_VERIFIED_REVENUE, etc.).
- Routine scheduler cycles are NEVER notified.
- Zero private keys, seed phrases, passwords, or signing credentials.
- MESSAGE_CREATED != MESSAGE_DELIVERED (strict delivery verification).
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

QUEUE_PATH = os.path.join(WORKSPACE_DIR, "ATL_MATERIAL_EVENT_QUEUE.json")
NOTIF_LOG_PATH = os.path.join(WORKSPACE_DIR, "ATL_NOTIFICATION_RECEIPTS.jsonl")

# Material events permitted for owner notification (Directive 4)
ALLOWED_MATERIAL_EVENTS = {
    "SETTLEMENT_APPROVAL_REQUIRED",
    "FIRST_VERIFIED_REVENUE",
    "FIRST_EXTERNAL_EXECUTION_PA001",
    "FIRST_EXTERNAL_EXECUTION_PA002",
    "FIRST_REPEAT_AGENT_USAGE",
    "PRODUCT_KILLED",
    "PRODUCT_SCALED",
    "MATERIAL_RUNTIME_FAILURE",
    "L0_ESCALATION"
}

# Known ecosystem defaults
DEFAULT_TELEGRAM_CHAT_ID = "437715321"  # @konstantin187


def get_configured_transports() -> Dict[str, Any]:
    """
    Inspects which notification transports are currently configured and authorized.
    """
    telegram_token = os.environ.get("ATL_TELEGRAM_BOT_TOKEN") or os.environ.get("SH3_TELEGRAM_BOT_TOKEN", "")
    telegram_chat = os.environ.get("ATL_TELEGRAM_CHAT_ID") or os.environ.get("SH3_TELEGRAM_CHAT_ID") or DEFAULT_TELEGRAM_CHAT_ID
    webhook_url = os.environ.get("ATL_OWNER_WEBHOOK_URL") or os.environ.get("OWNER_WEBHOOK_URL", "")
    
    # Validate Telegram token plausibility (must not be placeholder)
    telegram_valid = False
    if telegram_token:
        is_placeholder = any(p in telegram_token.upper() for p in ("PASTE", "YOUR_TOKEN", "REDACTED", "TEST_TOKEN"))
        if ":" in telegram_token and len(telegram_token) >= 25 and not is_placeholder:
            telegram_valid = True

    # Windows Toast is always available on Windows platforms
    windows_toast_available = (sys.platform == "win32")

    has_remote = telegram_valid or bool(webhook_url)

    return {
        "remote_transport_configured": has_remote,
        "local_transport_configured": windows_toast_available,
        "transports": {
            "telegram": {
                "configured": telegram_valid,
                "chat_id_target": telegram_chat if telegram_valid else None,
                "token_env_checked": ["ATL_TELEGRAM_BOT_TOKEN", "SH3_TELEGRAM_BOT_TOKEN"]
            },
            "windows_toast": {
                "configured": windows_toast_available,
                "platform": sys.platform
            },
            "webhook": {
                "configured": bool(webhook_url)
            }
        }
    }


def format_settlement_alert_message(event_payload: Dict[str, Any], financial_boundary: Dict[str, Any]) -> str:
    """
    Formats the settlement approval alert strictly according to Directive 5.
    """
    buyer = event_payload.get("buyer_reference", "UNKNOWN_BUYER")
    product = f"{event_payload.get('product_name', 'ATL Product')} ({event_payload.get('product_agent_id', 'PA-001')})"
    invoice_id = event_payload.get("invoice_id", "INV-UNKNOWN")
    amount = event_payload.get("agreed_amount_formatted") or f"{event_payload.get('agreed_amount', 0.0):.2f} USDC"
    asset = event_payload.get("requested_currency", "USDC")
    network = event_payload.get("requested_network", "NOT_SPECIFIED")
    scope = event_payload.get("agreed_scope", "Commercial pilot execution")
    
    addr_status = financial_boundary.get("SETTLEMENT_ADDRESS_STATUS", "NOT_CONFIGURED")
    addr_str = "CONFIGURED" if addr_status == "CONFIGURED_AND_APPROVED" else "NOT CONFIGURED"

    msg = f"""ATL — SETTLEMENT APPROVAL REQUIRED

Buyer:
{buyer}

Product:
{product}

Invoice:
{invoice_id}

Agreed amount:
{amount}

Requested asset:
{asset}

Requested network:
{network}

Scope:
{scope}

Buyer ready to settle:
YES

Settlement address:
{addr_str}


OWNER ACTION REQUIRED:

APPROVE
REJECT
MODIFY"""

    # Strict check: never contain private wallet information
    msg_lower = msg.lower()
    for sensitive_word in ("private_key", "seed_phrase", "wallet_password", "signing_credential", "privatekey", "mnemonic"):
        assert sensitive_word not in msg_lower, f"CRITICAL SECURITY VIOLATION: '{sensitive_word}' in alert message!"

    return msg


def send_windows_toast_notification(title: str, body: str) -> Tuple[bool, Optional[str]]:
    """
    Sends a native Windows Toast Notification via PowerShell and WinRT API.
    Returns (success, error_or_output).
    """
    if sys.platform != "win32":
        return False, "Windows Toast notifications only supported on Windows OS"

    # Clean text to prevent PowerShell injection
    safe_title = title.replace('"', '`"').replace("$", "`$")
    safe_body = body.replace('"', '`"').replace("$", "`$")

    ps_script = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName("text")
$textNodes.Item(0).AppendChild($template.CreateTextNode("{safe_title}")) | Out-Null
$textNodes.Item(1).AppendChild($template.CreateTextNode("{safe_body}")) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ATL System Alert")
$notifier.Show($toast)
Write-Output "TOAST_DELIVERED"
"""
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        if res.returncode == 0 and "TOAST_DELIVERED" in res.stdout:
            return True, "TOAST_DELIVERED"
        return False, f"PowerShell failed (code {res.returncode}): {res.stderr.strip() or res.stdout.strip()}"
    except Exception as e:
        return False, f"Exception dispatching Windows Toast: {str(e)}"


def send_telegram_notification(text: str) -> Tuple[bool, Optional[str]]:
    """
    Dispatches message to the owner's Telegram chat via api.telegram.org.
    """
    token = os.environ.get("ATL_TELEGRAM_BOT_TOKEN") or os.environ.get("SH3_TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("ATL_TELEGRAM_CHAT_ID") or os.environ.get("SH3_TELEGRAM_CHAT_ID") or DEFAULT_TELEGRAM_CHAT_ID

    if not token:
        return False, "TELEGRAM_BOT_TOKEN_MISSING"

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML"
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            resp_body = resp.read().decode("utf-8")
            resp_json = json.loads(resp_body)
            if resp_json.get("ok"):
                return True, f"Delivered to Telegram chat {chat_id}"
            return False, f"Telegram API error: {resp_json.get('description', 'Unknown error')}"
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8") if e.fp else ""
        return False, f"Telegram HTTPError {e.code}: {err_body}"
    except Exception as e:
        return False, f"Telegram connection error: {str(e)}"


def dispatch_material_event_notification(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatches a material event to the owner across configured transports.
    Generates a formal DELIVERY RECEIPT complying with Directive 6.
    """
    event_id = event.get("event_id", "UNKNOWN_EVENT")
    event_type = event.get("event_type", "UNKNOWN_TYPE")
    
    # Directive 4: Filter strictly for material events
    if event_type not in ALLOWED_MATERIAL_EVENTS:
        return {
            "notification_id": f"NOTIF-SKIPPED-{int(time.time())}",
            "material_event_id": event_id,
            "transport": "NONE",
            "delivery_attempted": False,
            "delivery_succeeded": False,
            "failure_reason": f"Event type '{event_type}' not in ALLOWED_MATERIAL_EVENTS filter."
        }

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    notif_id = f"NOTIF-{time.strftime('%Y%m%d')}-{hashlib.sha256(f'{event_id}:{now_iso}'.encode()).hexdigest()[:8].upper()}"

    # Format message
    if event_type == "SETTLEMENT_APPROVAL_REQUIRED":
        message_text = format_settlement_alert_message(
            event.get("payload", {}),
            event.get("financial_boundary", {})
        )
        short_title = "ATL: Settlement Approval Required"
        short_body = f"Buyer: {event.get('payload', {}).get('buyer_reference')} | Amount: {event.get('payload', {}).get('agreed_amount_formatted')}"
    else:
        message_text = f"ATL MATERIAL EVENT: {event_type}\nEvent ID: {event_id}\nDetails: {json.dumps(event.get('payload', {}), indent=2)}"
        short_title = f"ATL: {event_type}"
        short_body = f"Event ID: {event_id}"

    transports_state = get_configured_transports()
    delivery_receipts: List[Dict[str, Any]] = []
    overall_success = False
    chosen_transport = "NONE"

    # 1. Try Remote Telegram if configured
    if transports_state["transports"]["telegram"]["configured"]:
        tg_success, tg_detail = send_telegram_notification(message_text)
        delivery_receipts.append({
            "transport": "TELEGRAM_BOT",
            "attempted": True,
            "succeeded": tg_success,
            "detail": tg_detail
        })
        if tg_success:
            overall_success = True
            chosen_transport = "TELEGRAM_BOT"

    # 2. Local Windows Toast (Active on Windows platform)
    if transports_state["transports"]["windows_toast"]["configured"]:
        toast_success, toast_detail = send_windows_toast_notification(short_title, short_body)
        delivery_receipts.append({
            "transport": "WINDOWS_TOAST",
            "attempted": True,
            "succeeded": toast_success,
            "detail": toast_detail
        })
        if toast_success:
            overall_success = True
            if chosen_transport == "NONE":
                chosen_transport = "WINDOWS_TOAST"
            else:
                chosen_transport += "+WINDOWS_TOAST"

    delivery_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) if overall_success else None
    failure_reason = None if overall_success else "No configured notification transport succeeded."

    receipt = {
        "notification_id": notif_id,
        "material_event_id": event_id,
        "event_type": event_type,
        "transport": chosen_transport,
        "created_at": now_iso,
        "delivery_attempted": True,
        "delivery_succeeded": overall_success,
        "delivery_timestamp": delivery_timestamp,
        "failure_reason": failure_reason,
        "owner_action_pending": True,
        "transports_detail": delivery_receipts
    }

    # Append to append-only notification receipts log
    try:
        with open(NOTIF_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(receipt) + "\n")
    except Exception as e:
        print(f"Error logging notification receipt: {e}", file=sys.stderr)

    # Update event record in queue
    if os.path.exists(QUEUE_PATH):
        try:
            with open(QUEUE_PATH, "r", encoding="utf-8") as f:
                queue_data = json.load(f)
            
            for ev in queue_data.get("pending_material_events", []):
                if ev.get("event_id") == event_id:
                    ev.setdefault("notification_receipts", []).append(receipt)
                    ev["notification_delivered"] = overall_success
                    ev["latest_notification_transport"] = chosen_transport
            
            with open(QUEUE_PATH, "w", encoding="utf-8") as f:
                json.dump(queue_data, f, indent=2)
        except Exception as e:
            print(f"Error updating event queue with notification receipt: {e}", file=sys.stderr)

    return receipt


def handle_owner_response(
    material_event_id: str,
    invoice_id: str,
    action: str,
    receiving_address: Optional[str] = None,
    network: Optional[str] = None,
    currency: Optional[str] = None,
    notes: str = ""
) -> Dict[str, Any]:
    """
    Handles formal owner responses according to Directive 8 & 9.
    Maps strictly to one specific material_event_id and invoice_id.
    Supported actions: APPROVE, REJECT, MODIFY.
    
    If APPROVE and receiving_address is None:
      Prompts for APPROVED PUBLIC RECEIVING ADDRESS REQUIRED.
    """
    action_clean = action.strip().upper()
    if action_clean not in ("APPROVE", "REJECT", "MODIFY"):
        return {
            "status": "INVALID_ACTION",
            "message": f"Action '{action}' not recognized. Supported: APPROVE, REJECT, MODIFY."
        }

    if not os.path.exists(QUEUE_PATH):
        return {"status": "QUEUE_NOT_FOUND", "message": "ATL_MATERIAL_EVENT_QUEUE.json does not exist."}

    with open(QUEUE_PATH, "r", encoding="utf-8") as f:
        queue_data = json.load(f)

    # Find target event
    target_event = None
    for ev in queue_data.get("pending_material_events", []):
        if ev.get("event_id") == material_event_id and ev.get("payload", {}).get("invoice_id") == invoice_id:
            target_event = ev
            break

    if not target_event:
        return {
            "status": "EVENT_NOT_FOUND",
            "message": f"No pending event matches material_event_id '{material_event_id}' and invoice_id '{invoice_id}'."
        }

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Case 1: REJECT
    if action_clean == "REJECT":
        target_event["status"] = "OWNER_REJECTED"
        target_event["resolved_at"] = now_iso
        target_event["resolution_notes"] = notes or "Rejected by owner."
        queue_data["pending_material_events"].remove(target_event)
        queue_data.setdefault("processed_material_events", []).append(target_event)
        with open(QUEUE_PATH, "w", encoding="utf-8") as f:
            json.dump(queue_data, f, indent=2)
        return {
            "status": "SETTLEMENT_REJECTED",
            "material_event_id": material_event_id,
            "invoice_id": invoice_id,
            "message": "Settlement rejected by owner. Commercial proposal cancelled or re-negotiation required."
        }

    # Case 2: MODIFY
    if action_clean == "MODIFY":
        target_event["status"] = "OWNER_MODIFICATION_REQUESTED"
        target_event["modification_notes"] = notes
        with open(QUEUE_PATH, "w", encoding="utf-8") as f:
            json.dump(queue_data, f, indent=2)
        return {
            "status": "MODIFICATION_RECORDED",
            "material_event_id": material_event_id,
            "invoice_id": invoice_id,
            "message": f"Modification requested by owner: {notes}"
        }

    # Case 3: APPROVE
    if action_clean == "APPROVE":
        # Check if address was provided
        if not receiving_address or not isinstance(receiving_address, str) or not receiving_address.strip():
            # Directive 9: Request approved public receiving address
            address_request_prompt = """==================================================
APPROVED PUBLIC RECEIVING ADDRESS REQUIRED
==================================================

Owner has approved commercial settlement for:
Invoice: {inv}
Buyer: {buyer}
Amount: {amt}

To release buyer-facing payment instructions, please supply:
- Approved public receiving address (e.g., 0x...)
- Approved network (e.g., Base, Arbitrum, Ethereum)
- Approved currency (USDC / USDT)

ATL WILL NEVER REQUEST OR STORE PRIVATE KEYS, SEED PHRASES, OR PASSWORDS.
==================================================""".format(
                inv=invoice_id,
                buyer=target_event.get("payload", {}).get("buyer_reference"),
                amt=target_event.get("payload", {}).get("agreed_amount_formatted")
            )
            return {
                "status": "AWAITING_APPROVED_PUBLIC_ADDRESS",
                "material_event_id": material_event_id,
                "invoice_id": invoice_id,
                "address_request_prompt": address_request_prompt,
                "message": "Owner approved settlement terms. Public receiving address is required before payment instructions can be released."
            }

        # Validate provided public address
        addr_clean = receiving_address.strip()
        assert not any(k in addr_clean.lower() for k in ("private", "key", "secret", "password")), "CRITICAL: Private credential passed as address!"

        app_net = network.strip() if network else target_event.get("payload", {}).get("requested_network", "Base")
        app_curr = currency.strip().upper() if currency else target_event.get("payload", {}).get("requested_currency", "USDC")
        app_amount = float(target_event.get("payload", {}).get("agreed_amount", 0.0))

        approval_record = {
            "invoice_id": invoice_id,
            "material_event_id": material_event_id,
            "OWNER_SETTLEMENT_APPROVED": True,
            "APPROVED_AMOUNT": app_amount,
            "APPROVED_CURRENCY": app_curr,
            "APPROVED_NETWORK": app_net,
            "APPROVED_SETTLEMENT_ADDRESS": addr_clean,
            "APPROVAL_TIMESTAMP": now_iso,
            "notes": notes
        }

        target_event["status"] = "OWNER_APPROVED"
        target_event["resolved_at"] = now_iso
        target_event["financial_boundary"]["APPROVED_SETTLEMENT_ADDRESS"] = addr_clean
        target_event["financial_boundary"]["SETTLEMENT_ADDRESS_STATUS"] = "CONFIGURED_AND_APPROVED"
        target_event["financial_boundary"]["OWNER_SETTLEMENT_APPROVED"] = True
        target_event["owner_approval_record"] = approval_record

        queue_data["pending_material_events"].remove(target_event)
        queue_data.setdefault("processed_material_events", []).append(target_event)
        with open(QUEUE_PATH, "w", encoding="utf-8") as f:
            json.dump(queue_data, f, indent=2)

        return {
            "status": "OWNER_APPROVAL_RECORDED",
            "material_event_id": material_event_id,
            "invoice_id": invoice_id,
            "approval_record": approval_record,
            "message": "Owner settlement approval recorded. Buyer-facing payment instructions may now be generated."
        }
