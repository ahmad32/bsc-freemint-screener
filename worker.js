// BSC Freemint Screener — zkVerify Agent Games (Wildcard track)
// POST /agent with JSON { contract | address | task: { contract } }
// Returns { decision, reason_code, reason, details }
// HMAC: if AGENT_GAMES_HMAC_SECRET is set, verifies x-agent-games-signature
// over the raw body (hex HMAC-SHA256). If not set, accepts unsigned requests.

const BSC_CHAIN_ID = 56;
const SOURCIFY_BASE = "https://sourcify.dev/server/v2/contract";
const DEXSCREENER_BASE = "https://api.dexscreener.com/latest/dex/tokens";
const BSC_RPC = "https://bsc-dataseed.binance.org";

// Owner-power scan: exact function names only (substring matching over-flags
// normal mint functions like mintFree / freeMinted / totalMinted).
const DRAIN_FNS = ["withdraw", "withdrawAmd", "withdrawTeam", "emergencyWithdraw", "drain", "rescue", "rescueTokens"];
const PAUSE_FNS = ["pause", "unpause", "setPaused"];
const CONFIG_FNS = ["setTax", "setTaxBps", "setFee", "setPrice", "setMinter", "setMinterRole", "setGiveawayRoot", "setMerkleRoot", "burnFailedFree", "burnUnsold"];
const UPGRADE_FNS = ["upgrade", "upgradeTo", "upgradeToAndCall", "setImplementation", "setProxyAdmin", "migrate", "setMigrator", "setKeeper"];
const OWNERSHIP_FNS = ["transferOwnership"];

function scanAbi(abi) {
  const names = [];
  if (!Array.isArray(abi)) return { drain: [], pause: [], config: [], upgrade: [], ownership: [], names: [] };
  for (const item of abi) {
    if (item && typeof item.name === "string") names.push(item.name);
  }
  const lower = names.map((n) => n.toLowerCase());
  const has = (list) => [...new Set(names.filter((n) => list.includes(n.toLowerCase())))];
  return {
    drain: has(DRAIN_FNS),
    pause: has(PAUSE_FNS),
    config: has(CONFIG_FNS),
    upgrade: has(UPGRADE_FNS),
    ownership: has(OWNERSHIP_FNS),
    names,
  };
}

const OWNER_FN_SELECTOR = "0x8da5cb5b"; // owner()

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function isAddress(v) {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
}

function extractContract(body) {
  if (!body || typeof body !== "object") return null;
  if (isAddress(body.contract)) return body.contract;
  if (isAddress(body.address)) return body.address;
  if (isAddress(body.token)) return body.token;
  if (body.task && typeof body.task === "object") return extractContract(body.task);
  if (body.input && typeof body.input === "object") return extractContract(body.input);
  if (typeof body.input === "string" && isAddress(body.input)) return body.input;
  if (typeof body.prompt === "string") {
    const m = body.prompt.match(/0x[0-9a-fA-F]{40}/);
    if (m) return m[0];
  }
  return null;
}

async function hmacHex(secret, rawBody) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, rawBody);
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function fetchJson(url, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { accept: "application/json" } });
    const text = await r.text();
    let data = null;
    try { data = JSON.parse(text); } catch { data = null; }
    return { ok: r.ok, status: r.status, data, raw: text };
  } catch (e) {
    return { ok: false, status: 0, data: null, raw: String(e && e.message ? e.message : e) };
  } finally {
    clearTimeout(t);
  }
}

async function ethCallOwner(contract) {
  // eth_call owner() -> address (32-byte word). Non-blocking; returns null on failure.
  const body = JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "eth_call",
    params: [{ to: contract, data: OWNER_FN_SELECTOR }, "latest"],
  });
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 6000);
  try {
    const r = await fetch(BSC_RPC, {
      method: "POST", signal: ctrl.signal,
      headers: { "content-type": "application/json" },
      body,
    });
    const j = await r.json();
    const result = j && j.result;
    if (typeof result === "string" && result.length >= 66) {
      return "0x" + result.slice(-40);
    }
    return null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function scoreVerdict(s) {
  // Returns { decision, reason_code, reason }
  if (!s.verified) {
    return {
      decision: "UNSAFE",
      reason_code: "UNVERIFIED_CONTRACT",
      reason: "Contract source is not verified on Sourcify — ABI and owner powers cannot be trusted. Do not mint.",
    };
  }
  // If owner is renounced, owner-only functions are uncallable — harmless.
  const ownerPowersLive = s.renounced !== true;
  const drain = ownerPowersLive ? s.powers.drain : [];
  const pause = ownerPowersLive ? s.powers.pause : [];
  const upgrade = ownerPowersLive ? s.powers.upgrade : [];
  const config = ownerPowersLive ? s.powers.config : [];
  const allLive = [...drain, ...pause, ...upgrade, ...config];
  if (drain.length > 0 || upgrade.length > 0 || (drain.length > 0 && pause.length > 0)) {
    return {
      decision: "UNSAFE",
      reason_code: "DRAIN_RISK_OWNER_POWERS",
      reason: "Owner holds drain-risk powers (" + allLive.join(", ") + "). Withdraw/rescue/upgrade can drain funds. Do not mint.",
    };
  }
  if (pause.length > 0 || config.length > 0) {
    return {
      decision: "CAUTION",
      reason_code: "OWNER_POWERS_PRESENT",
      reason: "Contract is verified but owner retains powers (" + allLive.join(", ") + "). Mint only a free lot and never approve spending. Market: " + s.marketNote,
    };
  }
  if (!s.hasMarket) {
    return {
      decision: "CAUTION",
      reason_code: "NO_MARKET_YET",
      reason: "Contract is verified with minimal owner powers, but no DEX market/liquidity was found yet — speculative hold, cannot be sold/traded yet.",
    };
  }
  return {
    decision: "SAFE",
    reason_code: "VERIFIED_MINIMAL_POWERS_WITH_MARKET",
    reason: "Contract verified, minimal owner powers, market/liquidity found. Free mint looks safe (value 0, gas only).",
  };
}

function extractAbiFromStdJson(stdJson) {
  if (!stdJson || !stdJson.output || !stdJson.output.contracts) return null;
  for (const file of Object.values(stdJson.output.contracts)) {
    if (!file || typeof file !== "object") continue;
    for (const c of Object.values(file)) {
      if (c && Array.isArray(c.abi)) return c.abi;
    }
  }
  return null;
}

function extractAbiFromMetadata(md) {
  if (!md) return null;
  if (typeof md === "string") {
    try { md = JSON.parse(md); } catch { return null; }
  }
  if (md.output && Array.isArray(md.output.abi)) return md.output.abi;
  return extractAbiFromStdJson(md);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      return jsonResponse({ ok: true, agent: "bsc-freemint-screener", track: "wildcard", version: "1.0.0" });
    }

    if (url.pathname !== "/agent") {
      return jsonResponse({ error: "not_found", hint: "POST /agent" }, 404);
    }
    if (request.method !== "POST") {
      return jsonResponse({ error: "method_not_allowed", hint: "POST /agent with JSON" }, 405);
    }

    const rawBody = new Uint8Array(await request.arrayBuffer());

    // HMAC verification (only when a secret is configured).
    const secret = env.AGENT_GAMES_HMAC_SECRET || "";
    if (secret) {
      const sig = request.headers.get("x-agent-games-signature") || "";
      const expected = await hmacHex(secret, rawBody);
      const norm = (v) => v.toLowerCase().replace(/^0x/, "");
      if (!sig || norm(sig) !== norm(expected)) {
        return jsonResponse({ decision: "REJECT", reason_code: "BAD_SIGNATURE", reason: "HMAC signature verification failed." }, 401);
      }
    }

    let body = null;
    try {
      body = JSON.parse(new TextDecoder().decode(rawBody));
    } catch {
      return jsonResponse({ decision: "REJECT", reason_code: "BAD_JSON", reason: "Request body is not valid JSON." }, 400);
    }

    // Preflight / healthcheck: platform pings the endpoint before marking it active.
    const kind = (body && (body.type || body.kind || body.task_type || "")) + "";
    if (/preflight|healthcheck|ping/i.test(kind) || body.preflight === true) {
      return jsonResponse({ decision: "OK", reason_code: "PREFLIGHT_OK", reason: "Endpoint alive.", details: { agent: "bsc-freemint-screener" } });
    }

    const contract = extractContract(body);
    if (!contract) {
      return jsonResponse({
        decision: "REJECT",
        reason_code: "NO_CONTRACT_ADDRESS",
        reason: "No BSC contract address found in the request. Send JSON { \"contract\": \"0x...\" }.",
      }, 400);
    }

    // 1) Sourcify verification + ABI (BSC chain 56). ?fields=abi returns the ABI inline.
    const src = await fetchJson(`${SOURCIFY_BASE}/${BSC_CHAIN_ID}/${contract}?fields=abi`, 9000);
    let verified = false;
    let abi = null;
    let sourcifyMatch = null;
    if (src.ok && src.data) {
      if (src.data.match || src.data.status === "perfect" || src.data.status === "partial") {
        verified = true;
        sourcifyMatch = src.data.match || src.data.status;
      }
      if (Array.isArray(src.data.abi)) abi = src.data.abi;
      if (!abi) abi = extractAbiFromStdJson(src.data.stdJson) || extractAbiFromMetadata(src.data.metadata) || null;
    }

    // 2) ABI scan for owner powers (exact names only).
    const powers = scanAbi(abi);

    // 3) Owner address (best effort, non-blocking).
    const owner = await ethCallOwner(contract);
    const renounced = owner ? owner.toLowerCase() === "0x0000000000000000000000000000000000000000" : null;

    // 4) Market check via DexScreener.
    const dex = await fetchJson(`${DEXSCREENER_BASE}/${contract}`, 8000);
    let hasMarket = false;
    let marketNote = "no DEX pairs found";
    let pairs = [];
    if (dex.ok && dex.data && Array.isArray(dex.data.pairs)) {
      pairs = dex.data.pairs.slice(0, 5).map((p) => ({
        dex: p.dexId, pair: p.pairAddress,
        liquidityUsd: p.liquidity ? p.liquidity.usd : null,
        priceUsd: p.priceUsd || null,
      }));
      const liquid = pairs.filter((p) => (p.liquidityUsd || 0) > 0);
      hasMarket = liquid.length > 0;
      marketNote = hasMarket
        ? `${liquid.length} liquid pair(s), best liquidity $${Math.max(...liquid.map((p) => p.liquidityUsd || 0)).toLocaleString()}`
        : `${pairs.length} pair(s) but no liquidity`;
    }

    const s = { verified, powers, renounced, hasMarket, marketNote };
    const v = scoreVerdict(s);

    return jsonResponse({
      decision: v.decision,
      reason_code: v.reason_code,
      reason: v.reason,
      details: {
        contract,
        chain: "bsc",
        sourcify: { verified, match: sourcifyMatch },
        owner: owner || "unknown",
        renounced,
        ownerPowers: {
          drain: powers.drain,
          pause: powers.pause,
          config: powers.config,
          upgrade: powers.upgrade,
          ownership: powers.ownership,
          live: renounced !== true,
        },
        abiFunctions: powers.names.length,
        market: { hasMarket, note: marketNote, pairs },
      },
    });
  },
};
