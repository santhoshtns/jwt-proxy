// api/token.js

import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const {
    client_id,
    code,
    redirect_uri,
    grant_type,
  } = req.body;

  // Load your private key from environment variables
  const privateKey = process.env.SINGPASS_PRIVATE_KEY;

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: client_id,
    sub: client_id,
    aud: 'https://stg-id.singpass.gov.sg/oauth2/token',
    iat: now,
    exp: now + 300,
    jti: Math.random().toString(36).substring(2),
  };

  const clientAssertion = jwt.sign(payload, privateKey, { algorithm: 'RS256' });

  const params = new URLSearchParams();
  params.append('grant_type', grant_type);
  params.append('code', code);
  params.append('redirect_uri', redirect_uri);
  params.append('client_id', client_id);
  params.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  params.append('client_assertion', clientAssertion);

  try {
    const response = await fetch('https://stg-id.singpass.gov.sg/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error', details: error.message });
  }
}
