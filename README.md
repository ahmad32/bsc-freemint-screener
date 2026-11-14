# BSC Freemint Screener — zkVerify Agent Games (Wildcard)

An agent that screens a BSC contract and returns a verdict on whether its
free mint looks safe. Built for the zkVerify Agent Games Wildcard track
(usefulness, quality, originality).

## What it does

Send a BSC contract address; the agent checks:

1. **Sourcify verification** — is the source verified? (Unverified = UNSAFE.)
2. **Owner powers** — scans the verified ABI for drain-risk functions
   (withdraw / rescue / upgrade / proxy admin) and config powers
   (pause / setTax / setPrice). If the owner is renounced (0x0), those
   functions are uncallable and harmless.
3. **Market** — DexScreener pairs + liquidity. No market yet = speculative
   hold, cannot be sold/traded yet.

It returns one deterministic decision (`SAFE` / `CAUTION` / `UNSAFE`),
a `reason_code`, a human-readable `reason`, and a `details` object with
the evidence (Sourcify match, owner address, renounced flag, owner-power
breakdown, ABI function count, market pairs).

## Endpoint

- `GET /health` — liveness probe.
- `POST /agent` — the screening endpoint (HTTPS only, 60s deadline).

Request (any of these shapes works):

```json
{ "contract": "0x0c222b11A380DF4F68ceE7CAcB162357E60c7215" }
```

Response:

```json
{
  "decision": "CAUTION",
  "reason_code": "NO_MARKET_YET",
  "reason": "Contract is verified with minimal owner powers, but no DEX market/liquidity was found yet — speculative hold, cannot be sold/traded yet.",
  "details": {
    "contract": "0x0c222b11A380DF4F68ceE7CAcB162357E60c7215",
    "chain": "bsc",
    "sourcify": { "verified": true, "match": "exact_match" },
    "owner": "0x0000000000000000000000000000000000000000",
    "renounced": true,
    "ownerPowers": { "drain": [], "pause": [], "config": [], "upgrade": [], "ownership": [], "live": false },
    "abiFunctions": 134,
    "market": { "hasMarket": false, "note": "no DEX pairs found", "pairs": [] }
  }
}
```

Preflight: `POST /agent` with `{ "type": "preflight" }` returns
`{ "decision": "OK", "reason_code": "PREFLIGHT_OK", ... }`.

HMAC: if the `AGENT_GAMES_HMAC_SECRET` secret is set, the agent verifies
the `x-agent-games-signature` header (hex HMAC-SHA256 over the raw body)
and rejects bad signatures with 401. Without a secret configured it
accepts unsigned requests (for pre-registration testing).

## Verdict rules

| Condition | Decision |
|---|---|
| Contract not verified on Sourcify | UNSAFE |
| Live owner holds withdraw/rescue/upgrade powers | UNSAFE |
| Live owner holds pause/config powers | CAUTION |
| Verified, minimal powers, no DEX market yet | CAUTION |
| Verified, minimal powers, market with liquidity | SAFE |

## Deploy

Cloudflare Worker (`worker.js`, ES module). Deploy with the repo's
`cloudflare_deploy.py` helper, then enable the workers.dev subdomain:

```bash
python3 cloudflare_deploy.py bsc-freemint-screener worker.js
# enable subdomain via the Cloudflare API (POST .../workers/scripts/bsc-freemint-screener/subdomain {"enabled": true})
```

Live endpoint: `https://bsc-freemint-screener.ahmedkunpayaun.workers.dev/agent`

## Verified behaviour

- PONKE `0x0c222b11A380DF4F68ceE7CAcB162357E60c7215` (verified, owner
  renounced, no market) → CAUTION / NO_MARKET_YET.
- YWD launch `0x2AbF61da9e20C74E39CbB3640B1c7Bcd84a2A95D`
  (unverified) → UNSAFE / UNVERIFIED_CONTRACT.
