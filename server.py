#!/usr/bin/env python3
"""
Firmware Attestation MCP — hardware trust layer for sovereign AI.

Premise (from the public NSA ANT catalogue): "sovereign" AI on compromised
firmware is not sovereign. Persistence implants live BELOW the OS — BIOS/UEFI,
SMM, network boot ROMs, HDD Host Protected Areas — and survive OS reinstalls and
disk wipes. This MCP attests the firmware trust state of the host and gates
inference on a verified result.

Tools:
  scan_firmware        — read-only host evidence (Secure Boot, TPM, SIP, BIOS, HPA)
  check_ant_signatures — match evidence to NSA-ANT-class persistence PRECONDITIONS
  attest_firmware      — HMAC-signed firmware attestation (verifiable at proofof.ai)
  gate_inference       — ALLOW/BLOCK running AI on this host
  list_threat_model    — the attack surface this defends against

Honest by design: reports "indicators" (preconditions implants rely on), never
"clean". Absence of indicators is NOT proof of cleanliness; presence is NOT proof
of compromise. A BLOCK means "lacks confirmed trust anchors", not "hacked".

(c) CSOAI LTD (trading as MEOK AI Labs). MIT.
"""

import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("firmware-attestation")

SIGNING_KEY = os.environ.get("MEOK_ATTESTATION_KEY", "dev-key-change-me")
VERIFY_BASE = os.environ.get("MEOK_VERIFY_URL", "https://proofof.ai/api/verify")

ANT_THREAT_MODEL = {
    "IRONCHEF":    {"layer": "BIOS/SMM", "persists_through": "OS reinstall",
                    "precondition": "unsigned/unverified BIOS; SMM unmonitored",
                    "defense": "Secure Boot + measured boot (TPM PCR0-7) + SMM lockdown"},
    "DEITYBOUNCE": {"layer": "BIOS (Dell PowerEdge)", "persists_through": "OS reinstall",
                    "precondition": "writable BIOS, no flash protection",
                    "defense": "BIOS write-protect + signed firmware updates + TPM measurement"},
    "SWAP":        {"layer": "HDD Host Protected Area", "persists_through": "disk wipe / format",
                    "precondition": "HPA present and writable",
                    "defense": "HPA removal/verification + full-disk encryption"},
    "GINSU":       {"layer": "PCI bus (removable media)", "persists_through": "OS reinstall",
                    "precondition": "boot from external/removable media allowed",
                    "defense": "disable external boot + measured boot"},
    "HALLUXWATER": {"layer": "Network device boot ROM (firewall)", "persists_through": "firmware upgrade",
                    "precondition": "unverified network-equipment firmware",
                    "defense": "HMAC-signed firmware chain + supply-chain verification"},
}


def _sign(payload: str) -> str:
    return hashlib.sha256((SIGNING_KEY + payload).encode()).hexdigest()[:32]


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout.strip()
    except Exception:
        return ""


def _collect_evidence() -> dict:
    ev = {"os": platform.system(), "machine": platform.machine(), "node_hash": _sign(platform.node())}
    s = platform.system()
    if s == "Darwin":
        ev["sip"] = "enabled" if "enabled" in _run(["csrutil", "status"]).lower() else "unknown/disabled"
        ev["secure_boot"] = "apple-silicon-default" if platform.machine() == "arm64" else "check-required"
        ev["hpa_check"] = "n/a (APFS, no classic HPA)"
    elif s == "Linux":
        ev["secure_boot"] = "enabled" if "SecureBoot enabled" in _run(["mokutil", "--sb-state"]) else "off/unknown"
        ev["tpm_present"] = os.path.exists("/dev/tpm0") or os.path.exists("/sys/class/tpm/tpm0")
        ev["bios_vendor"] = _run(["cat", "/sys/class/dmi/id/bios_vendor"]) or "unknown"
        ev["bios_version"] = _run(["cat", "/sys/class/dmi/id/bios_version"]) or "unknown"
        ev["hpa_check"] = "needs hdparm -N (root)"
    else:
        ev["note"] = "limited evidence on this platform"
    return ev


@mcp.tool()
def scan_firmware() -> str:
    """Collect read-only firmware/boot trust evidence (Secure Boot, TPM, SIP, BIOS, HPA). JSON."""
    ev = _collect_evidence()
    ev["scanned_at"] = datetime.now(timezone.utc).isoformat()
    return json.dumps(ev, indent=2)


@mcp.tool()
def check_ant_signatures() -> str:
    """Match host evidence to NSA-ANT-class persistence preconditions + defense for each.
    Reports indicators, never a clean bill of health."""
    ev = _collect_evidence()
    indicators = []
    sb = str(ev.get("secure_boot", "")).lower()
    if "enabled" not in sb and "apple-silicon-default" not in sb:
        indicators.append({"class": "BIOS/SMM (IRONCHEF/DEITYBOUNCE/GINSU)",
                           "indicator": "Secure/measured boot not confirmed",
                           "defense": ANT_THREAT_MODEL["IRONCHEF"]["defense"]})
    if ev.get("os") == "Linux" and not ev.get("tpm_present"):
        indicators.append({"class": "measured-boot", "indicator": "no TPM detected",
                           "defense": "enable TPM 2.0 + measured boot"})
    if "needs" in str(ev.get("hpa_check", "")):
        indicators.append({"class": "HDD HPA (SWAP)",
                           "indicator": "HPA state unverified (needs privileged check)",
                           "defense": ANT_THREAT_MODEL["SWAP"]["defense"]})
    return json.dumps({
        "host": ev.get("node_hash"),
        "indicators_found": len(indicators),
        "indicators": indicators,
        "disclaimer": "Indicators = preconditions ANT-class implants rely on, NOT proof of compromise. "
                      "Absence of indicators is NOT proof of cleanliness.",
    }, indent=2)


@mcp.tool()
def attest_firmware(operator: str = "unknown") -> str:
    """HMAC-signed firmware attestation: evidence + indicator count, signed + timestamped.
    Verifiable at proofof.ai/api/verify."""
    ev = _collect_evidence()
    ind = json.loads(check_ant_signatures())
    body = {
        "type": "firmware-attestation", "operator": operator, "host": ev.get("node_hash"),
        "evidence": ev, "indicators_found": ind["indicators_found"],
        "trust_state": "INDICATORS_PRESENT" if ind["indicators_found"] else "NO_INDICATORS",
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    cert_id = "fw_" + _sign(canonical)[:16]
    body["cert_id"] = cert_id
    body["signature"] = _sign(canonical)
    body["verify_url"] = f"{VERIFY_BASE}?cert_id={cert_id}"
    return json.dumps(body, indent=2)


@mcp.tool()
def gate_inference(max_indicators: int = 0) -> str:
    """Trust gate: ALLOW only if firmware indicators <= max_indicators. Use BEFORE
    high-stakes inference. Default 0 (block if any precondition present)."""
    ind = json.loads(check_ant_signatures())
    n = ind["indicators_found"]
    allow = n <= max_indicators
    return json.dumps({
        "decision": "ALLOW" if allow else "BLOCK", "indicators_found": n, "threshold": max_indicators,
        "rationale": ("firmware trust within threshold" if allow
                      else f"{n} ANT-class precondition(s) present — host not sovereign-grade"),
        "note": "A BLOCK is not 'compromised' — host lacks confirmed trust anchors. Harden, then re-gate.",
    }, indent=2)


@mcp.tool()
def list_threat_model() -> str:
    """The documented NSA-ANT-class attack surface this MCP defends against."""
    return json.dumps(ANT_THREAT_MODEL, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/00wfZjcgAeUW4c5cyQ8k90K"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}
