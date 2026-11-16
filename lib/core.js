"use strict";
/**
 * TOBIRAWI — Proof Gatekeeper agent core for the zkVerify Agent Games.
 *
 * Protocol facts (from https://agentgames.zkverify.io/build and
 * /events/proof-gatekeeper, read 2026-11-15):
 *  - The platform POSTs HMAC-signed JSON envelopes to the registered endpoint.
 *    Signature = HMAC-SHA256 over the RAW body, header x-agent-games-signature.
 *  - Preflight envelope { type: "agent-games.preflight.v1" } must be answered
 *    with a signed { ok: true, protocolVersion: "v1" }.
 *  - Gatekeeper task: decide APPROVE / REJECT deterministically; on every
 *    provable task attach a Groth16 proof (gatekeeper circuit) + public
 *    signals. PROOF_REUSED tasks carry no proof (documented exception).
 *  - Every response body is signed with the same HMAC in the response header.
 *  - Fail closed: any error -> REJECT, never an unproven APPROVE.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const SIGNATURE_HEADER = "x-agent-games-signature";
const CIRCUIT_BASE = "https://agentgames.zkverify.io/circuits";

/* ---------------- HMAC ---------------- */

function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function verifyBodySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7).trim();
  let candidate = null;
  if (/^[0-9a-fA-F]{64}$/.test(v)) candidate = Buffer.from(v, "hex");
  else {
    try {
      const b = Buffer.from(v, "base64");
      if (b.length === 32) candidate = b;
    } catch { /* ignore */ }
  }
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

/** Deterministic per-task salt for the circuit's private `salt` input. */
function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

/* ---------------- Field conversion ---------------- */

function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") n = v;
  else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

function parseUint(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

/* ---------------- Decision policy ----------------
 * Check order and boundary semantics mirror the gatekeeper circuit exactly
 * (the circuit enforces decision == AND of the five field checks):
 *   balance >= minimum passes · current_block < expiry_block passes ·
 *   amount <= max_transfer passes · VK equality · recipient equality.
 * PROOF_REUSED is stateful (local seen-set) and sits outside the circuit.
 */
function evaluate(p, isSeen) {
  const norm = (x) => String(x ?? "").trim().toLowerCase();
  if (norm(p.proofVk) !== norm(p.registeredVk))
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  if (isSeen(p.proofTx))
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  if (p.publicBalance < p.minimum)
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  if (p.currentBlock >= p.expiryBlock)
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  if (norm(p.recipient) !== norm(p.conditionRecipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  if (p.amount > p.maxTransfer)
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if ([minimum, publicBalance, amount, maxTransfer, expiryBlock, currentBlock].some((x) => x === null))
    return null;
  for (const k of ["registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"])
    if (typeof input[k] !== "string" || !input[k]) return null;
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum, publicBalance, amount, maxTransfer, expiryBlock, currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    proofTx: input.proof_tx,
  };
}

function buildCircuitInputs(taskId, p, decision, salt) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(p.registeredVk),
    proofVkHash: toFieldElement(p.proofVk),
    minimum: p.minimum.toString(10),
    publicBalance: p.publicBalance.toString(10),
    expiryBlock: p.expiryBlock.toString(10),
    currentBlock: p.currentBlock.toString(10),
    recipient: toFieldElement(p.recipient),
    conditionRecipient: toFieldElement(p.conditionRecipient),
    amount: p.amount.toString(10),
    maxTransfer: p.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

/* ---------------- Circuit artifacts (fetched once, cached) ---------------- */

let artifactPathsPromise = null;
async function artifactPaths() {
  if (!artifactPathsPromise) {
    artifactPathsPromise = (async () => {
      const localDir = process.env.CIRCUITS_DIR;
      if (localDir && fs.existsSync(path.join(localDir, "gatekeeper.wasm")))
        return {
          wasm: path.join(localDir, "gatekeeper.wasm"),
          zkey: path.join(localDir, "gatekeeper_final.zkey"),
        };
      const dir = fs.mkdtempSync(path.join(require("os").tmpdir(), "ag-circuits-"));
      const wasm = path.join(dir, "gatekeeper.wasm");
      const zkey = path.join(dir, "gatekeeper_final.zkey");
      for (const [name, dest] of [["gatekeeper.wasm", wasm], ["gatekeeper_final.zkey", zkey]]) {
        const res = await fetch(`${CIRCUIT_BASE}/${name}`);
        if (!res.ok) throw new Error(`artifact fetch failed: ${name} ${res.status}`);
        fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
      }
      return { wasm, zkey };
    })();
  }
  return artifactPathsPromise;
}

let snarkjsCache = null;
async function prove(inputs) {
  if (!snarkjsCache) snarkjsCache = require("snarkjs");
  const { wasm, zkey } = await artifactPaths();
  const { proof, publicSignals } = await snarkjsCache.groth16.fullProve(inputs, wasm, zkey);
  return { proof, publicSignals };
}

/* ---------------- Seen-set ----------------
 * PROOF_REUSED detection needs memory across serverless instances and
 * across rounds, so the primary store is an Upstash Redis SET reached over
 * its REST API (env UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN).
 * An in-process Set acts as L1 cache; any Redis failure falls back to it.
 */
const seenProofTx = new Set();
const responseCache = new Map();
const SEEN_KEY = "ag:seen-proof-tx";

async function redisCmd(cmd) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2000);
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(cmd),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json();
    return data.result ?? null;
  } catch {
    return null;
  }
}

const normTx = (tx) => String(tx).trim().toLowerCase();

async function isProofSeen(tx) {
  const m = normTx(tx);
  if (seenProofTx.has(m)) return true;
  const r = await redisCmd(["SISMEMBER", SEEN_KEY, m]);
  if (r === 1) { seenProofTx.add(m); return true; }
  return false;
}

async function markProofSeen(tx) {
  const m = normTx(tx);
  seenProofTx.add(m);
  await redisCmd(["SADD", SEEN_KEY, m]);
}

/** Prefetch circuit artifacts so the first scored task skips the download. */
function warmup() {
  return artifactPaths().catch(() => null);
}

/* ---------------- Main handler ----------------
 * handlePost(rawBody: Buffer, signatureHeader: string|undefined, secret)
 *   -> { status, body (string), signature (hex|null) }
 */
async function handlePost(rawBody, signatureHeader, secret) {
  const signed = (status, obj) => {
    const body = typeof obj === "string" ? obj : JSON.stringify(obj);
    return { status, body, signature: secret ? signBody(secret, body) : null };
  };

  if (!secret)
    return { status: 500, body: JSON.stringify({ error: "server_misconfigured" }), signature: null };

  if (!verifyBodySignature(secret, rawBody, signatureHeader))
    return { status: 401, body: JSON.stringify({ error: "invalid_signature" }), signature: null };

  let env;
  try { env = JSON.parse(rawBody.toString("utf8")); }
  catch { return signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" }); }

  if (env.type === PREFLIGHT_TYPE)
    return signed(200, { ok: true, protocolVersion: "v1" });

  // Steal the VFY turn envelope — safe HOLD fallback until policy proving is
  // wired (a schema-valid answer avoids the timeout penalty).
  if (env.eventId === "steal-the-vfy" || env.type === "agent-games.steal-the-vfy.v1") {
    const turn = env.turn ?? env.turnNumber ?? 0;
    return signed(200, {
      matchId: env.matchId,
      turn,
      action: { type: "HOLD" },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: crypto.randomUUID(),
    });
  }

  if (env.type !== TASK_TYPE)
    return signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });

  const taskId = env.task_id;
  if (taskId && responseCache.has(taskId)) return signed(200, responseCache.get(taskId));

  try {
    const deadlineMs = env.deadline_at ? Date.parse(env.deadline_at) : NaN;
    if (!Number.isNaN(deadlineMs) && Date.now() > deadlineMs)
      return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });

    const parsed = parseInput(env.input ?? env);
    if (!parsed || !taskId)
      return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });

    const seen = await isProofSeen(parsed.proofTx);
    const evaluation = evaluate(parsed, () => seen);
    const response = { decision: evaluation.decision, reason_code: evaluation.reason_code };

    if (evaluation.provable) {
      const salt = deriveSalt(secret, taskId);
      const inputs = buildCircuitInputs(taskId, parsed, evaluation.decision, salt);
      try {
        const { proof, publicSignals } = await prove(inputs);
        response.proof = proof;
        response.public_signals = publicSignals;
        response.proof_tx = parsed.proofTx;
      } catch (err) {
        // Fail closed: an APPROVE we cannot prove becomes a plain REJECT.
        console.error("[agent] proving failed:", err.message);
        return signed(200, {
          decision: "REJECT",
          reason_code: evaluation.decision === "APPROVE" ? "INVALID_TASK" : evaluation.reason_code,
          proof_tx: parsed.proofTx,
        });
      }
    } else {
      response.proof_tx = parsed.proofTx; // PROOF_REUSED: no proof to submit
    }

    await markProofSeen(parsed.proofTx);
    const result = signed(200, response);
    if (taskId) responseCache.set(taskId, result.body);
    return result;
  } catch (err) {
    console.error("[agent] task error:", err.message);
    return signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
}

module.exports = {
  handlePost, signBody, verifyBodySignature, deriveSalt, toFieldElement,
  evaluate, parseInput, buildCircuitInputs, prove, warmup,
  isProofSeen, markProofSeen, SIGNATURE_HEADER,
};
