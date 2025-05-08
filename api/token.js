// api/token.js

import { randomBytes, createHash } from 'crypto';
import { jwtDecrypt, jwtVerify, importPKCS8, createLocalJWKSet } from 'jose';
import fs from 'fs';
import path from 'path';

function generatePKCE() {
  const codeVerifier = randomBytes(32).toString('hex');
  const codeChallenge = createHash('sha256')
    .update(codeVerifier)
    .digest()
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return { codeVerifier, codeChallenge };
}

export default async function handler(req, res) {
  console.log(`[Request] Method: ${req.method}, URL: ${req.url}`);

  // === GET /api/token?generate=pkce ===
  if (req.method === 'GET') {
    console.log(`[GET] Query parameters:`, req.query);
    const { generate } = req.query;

    if (generate === 'pkce') {
      const { codeVerifier, codeChallenge } = generatePKCE();
      console.log(`[PKCE] Generated code_verifier: ${codeVerifier}`);
      console.log(`[PKCE] Generated code_challenge: ${codeChallenge}`);
      
      const responsePayload = {
        code_verifier: codeVerifier,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
      };

      console.log(`[GET] Response payload:`, responsePayload);
      return res.status(200).json(responsePayload);
    }

    console.warn(`[GET] Invalid usage with query:`, req.query);
    return res.status(400).json({ error: 'Invalid GET usage' });
  }

  // === POST /api/token ===
  if (req.method !== 'POST') {
    console.warn(`[POST] Method not allowed: ${req.method}`);
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const { client_id, code, redirect_uri, grant_type, code_verifier } = req.body;

  // Required field validation
  if (!client_id || !code || !redirect_uri || !grant_type) {
    console.error(`[Validation] Missing required parameters:`, req.body);
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  // Specific validation for PKCE code_verifier
  if (!code_verifier || code_verifier === 'undefined') {
    console.error(`[Validation] Invalid or missing code_verifier:`, code_verifier);
    return res.status(400).json({
      error: 'Missing or invalid code_verifier — must be generated during PKCE step and passed here.'
    });
  }

  const singpassTokenUrl = process.env.SINGPASS_TOKEN_URL;
  if (!singpassTokenUrl) {
    console.error(`[Config] Missing SINGPASS_TOKEN_URL`);
    return res.status(500).json({ error: 'Missing SINGPASS_TOKEN_URL' });
  }

  // Build token exchange parameters
  const params = new URLSearchParams();
  params.append('grant_type', grant_type);
  params.append('code', code);
  params.append('redirect_uri', redirect_uri);
  params.append('client_id', client_id);
  params.append('code_verifier', code_verifier);

  console.log(`[POST] Sending request to Singpass Token URL: ${singpassTokenUrl}`);
  console.log(`[POST] Request payload:`, Object.fromEntries(params));

  try {
    const tokenResponse = await fetch(singpassTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    const tokenText = await tokenResponse.text();
    console.log(`[Response] Raw token response:`, tokenText);

    let tokenData;
    try {
      tokenData = JSON.parse(tokenText);
    } catch {
      console.error(`[Response] Invalid JSON from Singpass:`, tokenText);
      return res.status(500).json({ error: 'Invalid JSON from Singpass', raw: tokenText });
    }

    const { id_token, access_token } = tokenData;
    if (!id_token) {
      console.error(`[Response] Missing id_token in response:`, tokenData);
      return res.status(500).json({ error: 'Missing id_token in response', raw: tokenData });
    }

    // Decrypt the JWE (id_token)
    const encKeyPem = process.env.SINGPASS_ENC_KEY_PEM
      || fs.readFileSync(path.join(process.cwd(), 'keys/enc-key.pem'), 'utf8');
    const encKey = await importPKCS8(encKeyPem, 'ECDH-ES+A256KW');

    const { plaintext: decryptedJWT } = await jwtDecrypt(id_token, encKey);
    const decryptedToken = decryptedJWT.toString();
    console.log(`[Decryption] Decrypted ID token:`, decryptedToken);

    // Verify the JWT signature (id_token)
    const jwksPath = path.join(process.cwd(), 'keys/jwks.json');
    const jwks = JSON.parse(fs.readFileSync(jwksPath, 'utf8'));
    const JWKS = createLocalJWKSet(jwks);

    const { payload: verifiedClaims, protectedHeader } = await jwtVerify(decryptedToken, JWKS, {
      audience: client_id
    });

    console.log(`[Verification] Verified claims:`, verifiedClaims);
    console.log(`[Verification] Protected header:`, protectedHeader);

    return res.status(200).json({
      access_token,
      id_token: verifiedClaims,
      header: protectedHeader
    });

  } catch (err) {
    console.error(`[Error] Token exchange or verification failed:`, err);
    return res.status(500).json({
      error: 'Token exchange or verification failed',
      details: err.message
    });
  }
}
