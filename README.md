<!-- mcp-name: io.github.CSOAI-ORG/firmware-attestation-mcp -->
[![MCP Scorecard: 88/100](https://img.shields.io/badge/proofof.ai-88%2F100-5b21b6)](https://proofof.ai/scorecard/firmware-attestation-mcp.html)

# Firmware Attestation MCP

**Hardware trust layer for sovereign AI.** Persistence implants live *below* the OS (BIOS/UEFI, SMM, network boot ROMs, HDD HPA) and survive OS reinstalls and disk wipes. This MCP attests a host's firmware trust state and **gates inference on a verified result**.

## Tools
| Tool | What |
|---|---|
| `scan_firmware` | read-only host evidence (Secure Boot, TPM, SIP, BIOS, HPA) |
| `check_ant_signatures` | match to NSA-ANT-class persistence preconditions + defenses |
| `attest_firmware` | HMAC-signed attestation, verifiable at `proofof.ai/api/verify` |
| `gate_inference` | ALLOW/BLOCK AI on this host (strict by default) |
| `list_threat_model` | the attack surface this defends against |

## Honest by design
Reports **indicators** (preconditions implants rely on), never "clean". A `BLOCK` means "lacks confirmed trust anchors," not "hacked." Harden per the listed defenses, then re-gate.

```
pip install firmware-attestation-mcp
```
© CSOAI LTD (trading as MEOK AI Labs) · MIT


## Configuration

Add to your `claude_desktop_config.json` (Claude Desktop) or your MCP client config:

```json
{
  "mcpServers": {
    "firmware-attestation-mcp": {
      "command": "uvx",
      "args": ["firmware-attestation-mcp"]
    }
  }
}
```

Or: `pip install firmware-attestation-mcp` then run the `firmware-attestation-mcp` command (stdio transport).

## Examples

Once configured, ask your assistant, for example:
- "Use `scan_firmware` to …"
- "Use `check_ant_signatures` to …"
- "Use `attest_firmware` to …"


<!-- GEO-FOOTER:v1 -->

---

### Part of the MEOK constellation

This MCP is one node in a connected ecosystem built by **MEOK AI LABS** around a single
sovereign AI core — governed agents with a hash-chained audit trail, mapped to the CSOAI
compliance charter.

- 🌐 The whole map: **<https://meok.ai/constellation>**
- 🛡️ AI governance & certification: **<https://councilof.ai>** · **<https://csoai.org>**
- ✅ Verify any signed report: **<https://meok.ai/verify>**
