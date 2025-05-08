// api/token.js

import { jwtDecrypt, jwtVerify, importPKCS8, createLocalJWKSet } from 'jose';
import fs from 'fs';
import path from 'path';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const { client_id, code, redirect_uri, grant_type, code_verifier } = req.body;

  // Validate input
  if (!client_id || !code || !redirect_uri || !grant_type || !code_verifier) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  const singpassTokenUrl = process.env.SINGPASS_TOKEN_URL;
  if (!singpassTokenUrl) {
    return res.status(500).json({ error: 'Missing SINGPASS_TOKEN_URL env var' });
  }

  const params = new URLSearchParams();
  params.append('grant_type', grant_type);
  params.append('code', code);
  params.append('redirect_uri', redirect_uri);
  params.append('client_id', client_id);
  params.append('code_verifier', code_verifier);

  try {
    const tokenResponse = await fetch(singpassTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    const tokenText = await tokenResponse.text();
    let tokenData;
    try {
      tokenData = JSON.parse(tokenText);
    } catch {
      return res.status(500).json({ error: 'Invalid JSON from Singpass', raw: tokenText });
    }

    const { id_token, access_token } = tokenData;
    if (!id_token) {
      return res.status(500).json({ error: 'Missing id_token in response', raw: tokenData });
    }

    // 🔐 Decrypt the ID token (if it's JWE)
    const encKeyPem = process.env.SINGPASS_ENC_KEY_PEM || fs.readFileSync(path.join(process.cwd(), 'keys/enc-key.pem'), 'utf8');
    const encKey = await importPKCS8(encKeyPem, 'ECDH-ES+A256KW');

    const { plaintext: decryptedJWT } = await jwtDecrypt(id_token, encKey, {
      contentEncryptionAlgorithms: ['A256GCM']
    });

    const decryptedToken = decryptedJWT.toString();

    // ✅ Verify the signed JWT (you signed it with sig_key, registered in JWKS)
    const jwksPath = path.join(process.cwd(), 'keys/jwks.json');
    const jwks = JSON.parse(fs.readFileSync(jwksPath, 'utf8'));
    const JWKS = createLocalJWKSet(jwks);

    const { payload: verifiedClaims, protectedHeader } = await jwtVerify(decryptedToken, JWKS, {
      audience: client_id
    });

    return res.status(200).json({
      access_token,
      id_token: verifiedClaims, // Only return the claims
      header: protectedHeader
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: 'Token exchange or verification failed',
      details: err.message
    });
  }
}
