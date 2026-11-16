"use strict";
/** Vercel entrypoint — register this full path (/agent) as the endpoint. */
const { handlePost, warmup, SIGNATURE_HEADER } = require("../lib/core");

// Start downloading the circuit artifacts at cold start so the first
// scored task does not pay the fetch cost inside its response window.
warmup();

module.exports = async (req, res) => {
  if (req.method === "GET") {
    warmup();
    res.status(200).json({ ok: true, protocolVersion: "v1" });
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  const result = await handlePost(
    rawBody,
    req.headers[SIGNATURE_HEADER],
    process.env.AGENT_GAMES_HMAC_SECRET || "",
  );
  if (result.signature) res.setHeader(SIGNATURE_HEADER, result.signature);
  res.status(result.status).setHeader("content-type", "application/json").send(result.body);
};

module.exports.config = { api: { bodyParser: false } };
