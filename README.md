# TOBIRAWI — Proof Gatekeeper Agent

An AI agent for the **zkVerify Agent Games** (Proof Gatekeeper track). It
receives HMAC-signed payment tasks from the platform, decides APPROVE or
REJECT with deterministic checks, and answers with a Groth16 proof of the
decision generated locally with the tournament's own gatekeeper circuit —
so anyone can verify the decision followed the rules.

## How it works

1. Verify the `x-agent-games-signature` HMAC over the raw request body
   before parsing anything. Bad signature → 401.
2. Answer preflight envelopes with a signed `{ ok: true, protocolVersion: "v1" }`.
3. Evaluate the task deterministically (fail closed):
   - `proof_vk != registered_vk` → REJECT `VK_SUBSTITUTION`
   - `proof_tx` seen before → REJECT `PROOF_REUSED` (no proof, per the rules)
   - `public_balance < minimum` → REJECT `THRESHOLD_MISMATCH`
   - `current_block >= expiry_block` → REJECT `EXPIRED_CONDITION`
   - `recipient != condition_recipient` → REJECT `RECIPIENT_MISMATCH`
   - `amount > max_transfer` → REJECT `AMOUNT_OVERFLOW`
   - otherwise → APPROVE `VALID_CONDITION`
4. For every provable decision, generate a Groth16 proof with snarkjs using
   the official `gatekeeper.wasm` / `gatekeeper_final.zkey` artifacts
   (fetched from agentgames.zkverify.io at cold start) and return
   `{ decision, reason_code, proof, public_signals, proof_tx }`, signed.

The circuit itself enforces that the decision bit equals the AND of the
five field checks — a wrong decision cannot be proven.

## Deploy (Vercel)

1. Import this repository in Vercel (framework preset: Other).
2. Set the environment variable `AGENT_GAMES_HMAC_SECRET` to the secret
   shown once by **Rotate Secret** in the Agent Games dashboard.
3. Deploy, then register the endpoint in the dashboard as
   `https://<your-project>.vercel.app/agent` (full handler path).
4. The platform runs a signed preflight; when it passes, the agent is
   marked active and can take practice tasks.

## Local test

```bash
npm install
CIRCUITS_DIR=/path/to/circuits NODE_PATH=./node_modules node test_local.js
```

## Security

- The HMAC secret comes only from the environment — never commit it.
- `.env` is git-ignored; see `.env.example`.
- No wallet keys are used by this agent.
