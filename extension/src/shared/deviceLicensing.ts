// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file deviceLicensing.ts
 * @brief Primitives cryptographiques pour l'agent de licence par installation
 * (XSYNC-LIC-001, Pile_Ou_Face#70). Pas de dépendance vscode — testable en isolation.
 *
 * Remplace le modèle content_key partageable : chaque installation a sa propre
 * paire de clés RSA (générée ici, clé privée jamais transmise). Le serveur auth
 * renvoie un DEK enveloppé (RSA-OAEP) pour cette installation + un lease signé
 * (JWT RS256, vérifié ici avec la clé publique serveur via /auth/jwks) avant tout
 * déchiffrement — voir Pile_Ou_Face/docs/plans/2026-07-19-xsync-lic-001-licensing-agent.md.
 */
const crypto = require('crypto');

const LEASE_PROTOCOL_VERSION = 1;
const LEASE_ISSUER = 'pof-auth';
const LEASE_AUDIENCE = 'pof-plugin-runtime';
const LEASE_TTL_SECONDS = 8 * 60 * 60;

function generateDeviceKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

function generateDeviceId() {
  return crypto.randomUUID();
}

/** Signe un challenge d'enrôlement Auth avec la clé privée de l'installation. */
function signEnrollmentChallenge(challengeBase64, privateKeyPem) {
  const challenge = Buffer.from(String(challengeBase64 || ''), 'base64');
  if (challenge.length === 0) throw new Error('empty enrollment challenge');
  return crypto.sign('sha256', challenge, {
    key: privateKeyPem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
  }).toString('base64');
}

/** Déchiffre un DEK enveloppé (base64 RSA-OAEP/SHA-256) avec la clé privée de l'installation. */
function unwrapDek(wrappedDekBase64, privateKeyPem) {
  const wrapped = Buffer.from(wrappedDekBase64, 'base64');
  const dek = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    wrapped,
  );
  return dek.toString('base64');
}

function _b64urlToBuffer(input) {
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function getJwtSubject(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new LeaseVerificationError('malformed access token');
  try {
    const payload = JSON.parse(_b64urlToBuffer(parts[1]).toString('utf8'));
    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new Error('missing subject');
    }
    return payload.sub;
  } catch {
    throw new LeaseVerificationError('malformed access token subject');
  }
}

/**
 * Construit une clé publique PEM à partir d'un JWK RSA {n, e} (format renvoyé par /auth/jwks).
 */
function jwkToPublicKeyPem(jwk) {
  const keyObject = crypto.createPublicKey({
    key: { kty: 'RSA', n: jwk.n, e: jwk.e },
    format: 'jwk',
  });
  return keyObject.export({ type: 'spki', format: 'pem' });
}

class LeaseVerificationError extends Error {}

/**
 * Vérifie un lease JWT RS256 émis par /plugins/lease :
 * - signature valide avec la clé publique serveur (jwks)
 * - non expiré
 * - device_id et plugin_id correspondent à ce qui est attendu
 *
 * Vérification purement locale (lease stateless, voir design doc §5) — pas
 * d'appel réseau supplémentaire au-delà du jwks déjà récupéré/caché par l'appelant.
 */
function verifyLeaseJwt(
  token,
  jwks,
  expectedDeviceId,
  expectedPluginId,
  expectedReleaseId,
  expectedCiphertextSha256,
  expectedSubject,
) {
  if (!String(expectedReleaseId || '').trim()) {
    throw new LeaseVerificationError('expected release_id is required');
  }
  if (!/^[0-9a-f]{64}$/.test(String(expectedCiphertextSha256 || ''))) {
    throw new LeaseVerificationError('expected ciphertext_sha256 is required');
  }
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    throw new LeaseVerificationError('malformed lease token');
  }
  const [headerB64, payloadB64, sigB64] = parts;
  let header;
  let payload;
  try {
    header = JSON.parse(_b64urlToBuffer(headerB64).toString('utf8'));
    payload = JSON.parse(_b64urlToBuffer(payloadB64).toString('utf8'));
  } catch {
    throw new LeaseVerificationError('malformed lease payload');
  }
  if (header.alg !== 'RS256' || header.typ !== 'JWT' || typeof header.kid !== 'string') {
    throw new LeaseVerificationError('invalid lease header');
  }

  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = _b64urlToBuffer(sigB64);
  const verified = (jwks?.keys || []).filter((jwk) => jwk.kid === header.kid).some((jwk) => {
    try {
      const publicKeyPem = jwkToPublicKeyPem(jwk);
      return crypto.verify('RSA-SHA256', Buffer.from(signingInput), publicKeyPem, signature);
    } catch {
      return false;
    }
  });
  if (!verified) {
    throw new LeaseVerificationError('invalid lease signature');
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.protocol_version !== LEASE_PROTOCOL_VERSION) {
    throw new LeaseVerificationError('lease protocol_version mismatch');
  }
  if (payload.iss !== LEASE_ISSUER) {
    throw new LeaseVerificationError('lease issuer mismatch');
  }
  if (payload.aud !== LEASE_AUDIENCE) {
    throw new LeaseVerificationError('lease audience mismatch');
  }
  if (typeof payload.jti !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(payload.jti)) {
    throw new LeaseVerificationError('invalid lease jti');
  }
  if (typeof expectedSubject !== 'string' || !expectedSubject || payload.sub !== expectedSubject) {
    throw new LeaseVerificationError('lease subject mismatch');
  }
  if (payload.org_id !== null && (typeof payload.org_id !== 'string' || !payload.org_id)) {
    throw new LeaseVerificationError('invalid lease org_id');
  }
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.nbf) || !Number.isInteger(payload.exp)) {
    throw new LeaseVerificationError('invalid lease timestamps');
  }
  if (payload.iat > now || payload.nbf > now) {
    throw new LeaseVerificationError('lease not active');
  }
  if (payload.nbf !== payload.iat || payload.exp - payload.iat !== LEASE_TTL_SECONDS) {
    throw new LeaseVerificationError('invalid lease validity window');
  }
  if (typeof payload.exp !== 'number' || payload.exp <= now) {
    throw new LeaseVerificationError('lease expired');
  }
  if (payload.device_id !== expectedDeviceId) {
    throw new LeaseVerificationError('lease device_id mismatch');
  }
  if (payload.plugin_id !== expectedPluginId) {
    throw new LeaseVerificationError('lease plugin_id mismatch');
  }
  if (payload.release_id !== expectedReleaseId) {
    throw new LeaseVerificationError('lease release_id mismatch');
  }
  if (payload.ciphertext_sha256 !== expectedCiphertextSha256) {
    throw new LeaseVerificationError('lease ciphertext_sha256 mismatch');
  }
  return payload;
}

module.exports = {
  generateDeviceKeypair,
  generateDeviceId,
  getJwtSubject,
  signEnrollmentChallenge,
  unwrapDek,
  jwkToPublicKeyPem,
  verifyLeaseJwt,
  LeaseVerificationError,
};
