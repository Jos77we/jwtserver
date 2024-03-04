const express = require('express');
const jwt = require('jsonwebtoken');
const JWK = require('node-rsa');
const jwkToPem = require('jwk-to-pem');

const app = express();
const port = 8080;

// Function to generate RSA key pair with a unique ID (kid) and expiry timestamp
const generateKeyPair = () => {
  const key = new JWK({ b: 2048 });

  const kid = Math.random().toString(36).substring(7);
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24; // 24 hours validity

  return {
    kid,
    publicKey: key.exportKey('public'),
    privateKey: key.exportKey('private'),
    expiresAt,
  };
};

let currentKeyPair = generateKeyPair();

// Express middleware to handle JSON parsing
app.use(express.json());

// RESTful JWKS endpoint
app.get('/jwks', (req, res) => {
    const { kid, publicKey, expiresAt } = currentKeyPair;
  
    if (Date.now() > expiresAt) {
      // Regenerate keys if expired
      currentKeyPair = generateKeyPair();
    }
  
    const jwks = [
      {
        alg: 'RS256',
        kty: 'RSA',
        use: 'sig',
        kid,
        nbf: Math.floor(Date.now() / 1000),
        exp: Math.floor(expiresAt / 1000),
        n: Buffer.from(currentKeyPair.publicKey, 'base64').toString('base64'),
        e: 'AQAB', // You may need to adjust this based on your key generation
      },
    ];
  
    res.json({ keys: jwks });
  });

// Authentication endpoint
app.post('/auth', (req, res) => {
  const { expired } = req.query;

  const { privateKey, expiresAt } = currentKeyPair;

  if (expired) {
    // Issue a JWT signed with the expired key pair
    const token = jwt.sign({ data: 'expired' }, privateKey, { algorithm: 'RS256' });
    res.json({ token });
  } else {
    // Issue a JWT signed with the current key pair
    const token = jwt.sign({ data: 'valid' }, privateKey, { algorithm: 'RS256' });
    res.json({ token });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
