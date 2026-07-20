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
function verifyLeaseJwt(token, jwks, expectedDeviceId, expectedPluginId, expectedReleaseId = 'legacy') {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    throw new LeaseVerificationError('malformed lease token');
  }
  const [headerB64, payloadB64, sigB64] = parts;
  let payload;
  try {
    payload = JSON.parse(_b64urlToBuffer(payloadB64).toString('utf8'));
  } catch {
    throw new LeaseVerificationError('malformed lease payload');
  }

  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = _b64urlToBuffer(sigB64);
  const verified = (jwks?.keys || []).some((jwk) => {
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
  return payload;
}

module.exports = {
  generateDeviceKeypair,
  generateDeviceId,
  unwrapDek,
  jwkToPublicKeyPem,
  verifyLeaseJwt,
  LeaseVerificationError,
};
