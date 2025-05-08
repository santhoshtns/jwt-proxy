// api/token.js

import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  // Accept payload from caller
  const { client_id, code, redirect_uri, grant_type, code_verifier } = req.body;

  // Validate required parameters
  if (!client_id || !code || !redirect_uri || !grant_type || !code_verifier) {
    return res.status(400).json({ error: "Missing required parameters" });
  }

  // Load secrets and config
  const privateKey = process.env.SINGPASS_PRIVATE_KEY;
  const singpassTokenUrl = process.env.SINGPASS_TOKEN_URL;
  const tokenAud = process.env.SINGPASS_AUDIENCE || singpassTokenUrl;

  if (!privateKey || !singpassTokenUrl) {
    return res.status(500).json({
      error:
        "Missing required environment variables: SINGPASS_PRIVATE_KEY or SINGPASS_TOKEN_URL",
    });
  }

  // Construct signed JWT (client_assertion)
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: client_id,
    sub: client_id,
    aud: tokenAud,
    iat: now,
    exp: now + 300, // expires in 5 minutes
    jti: randomUUID(), // ✅ Secure unique ID
  };

  let clientAssertion;
  try {
    clientAssertion = jwt.sign(payload, privateKey, { algorithm: "RS256" });
  } catch (err) {
    return res
      .status(500)
      .json({ error: "JWT signing failed", details: err.message });
  }

  // Construct form body
  const params = new URLSearchParams();
  params.append("grant_type", grant_type);
  params.append("code", code);
  params.append("redirect_uri", redirect_uri);
  params.append("client_id", client_id);
  params.append(
    "client_assertion_type",
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  );
  params.append("client_assertion", clientAssertion);
  params.append("code_verifier", code_verifier);

  try {
    const response = await fetch(singpassTokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    const text = await response.text();

    try {
      const json = JSON.parse(text);
      res.status(response.status).json(json);
    } catch (jsonParseError) {
      res.status(response.status).json({
        error: "Invalid JSON response from Singpass",
        raw: text,
      });
    }
  } catch (error) {
    res.status(500).json({
      error: "Token exchange failed",
      details: error.message,
    });
  }
}
