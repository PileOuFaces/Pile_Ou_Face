// @ts-nocheck
const { expect } = require("chai");
const crypto = require("crypto");
const {
  generateDeviceKeypair,
  generateDeviceId,
  getJwtSubject,
  signEnrollmentChallenge,
  unwrapDek,
  verifyLeaseJwt,
  LeaseVerificationError,
} = require("../shared/deviceLicensing");

function b64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function signLease(payload, signingPrivateKeyPem, header = { alg: "RS256", typ: "JWT", kid: "1" }) {
  const headerB64 = b64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), signingPrivateKeyPem);
  return `${signingInput}.${b64url(signature)}`;
}

function serverKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const keyObject = crypto.createPublicKey(publicKey);
  const jwk = keyObject.export({ format: "jwk" });
  return { publicKey, privateKey, jwks: { keys: [{ kty: "RSA", n: jwk.n, e: jwk.e, kid: "1" }] } };
}

describe("deviceLicensing", () => {
  const DIGEST = "a".repeat(64);
  const SUBJECT = "user-1";

  function leaseClaims(overrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    return {
      protocol_version: 1,
      iss: "pof-auth",
      aud: "pof-plugin-runtime",
      jti: "123e4567-e89b-42d3-a456-426614174000",
      sub: SUBJECT,
      org_id: null,
      device_id: "dev-1",
      plugin_id: "pof.x",
      release_id: "release-test-1",
      ciphertext_sha256: DIGEST,
      iat: now,
      nbf: now,
      exp: now + 8 * 60 * 60,
      ...overrides,
    };
  }
  describe("generateDeviceKeypair / generateDeviceId", () => {
    it("generates a usable RSA PEM keypair", () => {
      const { publicKeyPem, privateKeyPem } = generateDeviceKeypair();
      expect(publicKeyPem).to.include("BEGIN PUBLIC KEY");
      expect(privateKeyPem).to.include("BEGIN PRIVATE KEY");
      // roundtrip sanity check
      const plain = Buffer.from("hello");
      const encrypted = crypto.publicEncrypt(
        { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
        plain,
      );
      const decrypted = crypto.privateDecrypt(
        { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
        encrypted,
      );
      expect(decrypted.toString()).to.equal("hello");
    });

    it("generates distinct device ids", () => {
      const a = generateDeviceId();
      const b = generateDeviceId();
      expect(a).to.not.equal(b);
      expect(a).to.match(/^[0-9a-f-]{36}$/);
    });
  });

  describe("signEnrollmentChallenge", () => {
    it("creates an RSA-PSS SHA-256 signature verifiable by the device public key", () => {
      const { publicKeyPem, privateKeyPem } = generateDeviceKeypair();
      const challenge = Buffer.from("pof-enroll-v1\nchallenge");
      const signature = signEnrollmentChallenge(challenge.toString("base64"), privateKeyPem);

      const valid = crypto.verify(
        "sha256",
        challenge,
        {
          key: publicKeyPem,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
        },
        Buffer.from(signature, "base64"),
      );
      expect(valid).to.equal(true);
    });

    it("rejects an empty challenge", () => {
      const { privateKeyPem } = generateDeviceKeypair();
      expect(() => signEnrollmentChallenge("", privateKeyPem)).to.throw(/empty/);
    });
  });

  describe("unwrapDek", () => {
    it("unwraps a DEK wrapped with the matching public key (RSA-OAEP)", () => {
      const { publicKeyPem, privateKeyPem } = generateDeviceKeypair();
      const dek = crypto.randomBytes(32);
      const wrapped = crypto.publicEncrypt(
        { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
        dek,
      );
      const result = unwrapDek(wrapped.toString("base64"), privateKeyPem);
      expect(result).to.equal(dek.toString("base64"));
    });

    it("throws when wrapped with a different key", () => {
      const { privateKeyPem } = generateDeviceKeypair();
      const other = generateDeviceKeypair();
      const dek = crypto.randomBytes(32);
      const wrapped = crypto.publicEncrypt(
        { key: other.publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
        dek,
      );
      expect(() => unwrapDek(wrapped.toString("base64"), privateKeyPem)).to.throw();
    });
  });

  describe("verifyLeaseJwt", () => {
    it("accepts a validly signed, unexpired, matching lease", () => {
      const { privateKey, jwks } = serverKeypair();
      const token = signLease(leaseClaims(), privateKey);
      const payload = verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT);
      expect(payload.device_id).to.equal("dev-1");
    });

    it("rejects a lease signed by an unknown key", () => {
      const { jwks } = serverKeypair();
      const attacker = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      const token = signLease(leaseClaims(), attacker.privateKey);
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT)).to.throw(LeaseVerificationError);
    });

    it("rejects an expired lease", () => {
      const { privateKey, jwks } = serverKeypair();
      const now = Math.floor(Date.now() / 1000);
      const token = signLease(leaseClaims({ iat: now - 28801, nbf: now - 28801, exp: now - 1 }), privateKey);
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT)).to.throw(LeaseVerificationError, /expired/);
    });

    it("rejects a lease issued for a different device_id", () => {
      const { privateKey, jwks } = serverKeypair();
      const token = signLease(leaseClaims({ device_id: "dev-OTHER" }), privateKey);
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT)).to.throw(LeaseVerificationError, /device_id/);
    });

    it("rejects a lease issued for a different plugin_id", () => {
      const { privateKey, jwks } = serverKeypair();
      const token = signLease(leaseClaims({ plugin_id: "pof.OTHER" }), privateKey);
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT)).to.throw(LeaseVerificationError, /plugin_id/);
    });

    it("rejects a lease issued for a different release_id", () => {
      const { privateKey, jwks } = serverKeypair();
      const token = signLease(leaseClaims({ release_id: "release-old" }), privateKey);
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-new", DIGEST, SUBJECT))
        .to.throw(LeaseVerificationError, /release_id/);
    });

    it("rejects a lease bound to a different encrypted payload", () => {
      const { privateKey, jwks } = serverKeypair();
      const token = signLease(leaseClaims({ ciphertext_sha256: "b".repeat(64) }), privateKey);
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT))
        .to.throw(LeaseVerificationError, /ciphertext_sha256/);
    });

    it("rejects a malformed token", () => {
      const { jwks } = serverKeypair();
      expect(() => verifyLeaseJwt("not-a-jwt", jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT)).to.throw(LeaseVerificationError);
    });

    for (const [name, override, message] of [
      ["protocol version", { protocol_version: 0 }, /protocol_version/],
      ["issuer", { iss: "attacker" }, /issuer/],
      ["audience", { aud: "other-runtime" }, /audience/],
      ["jti", { jti: "not-a-uuid" }, /jti/],
      ["subject", { sub: "other-user" }, /subject/],
      ["organization", { org_id: 42 }, /org_id/],
    ]) {
      it(`rejects an invalid ${name} claim`, () => {
        const { privateKey, jwks } = serverKeypair();
        const token = signLease(leaseClaims(override), privateKey);
        expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT))
          .to.throw(LeaseVerificationError, message);
      });
    }

    it("rejects an unknown signing kid", () => {
      const { privateKey, jwks } = serverKeypair();
      const token = signLease(leaseClaims(), privateKey, { alg: "RS256", typ: "JWT", kid: "other" });
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT))
        .to.throw(LeaseVerificationError, /signature/);
    });

    it("rejects a future or non-contractual validity window", () => {
      const { privateKey, jwks } = serverKeypair();
      const now = Math.floor(Date.now() / 1000);
      for (const claims of [
        leaseClaims({ iat: now + 10, nbf: now + 10, exp: now + 10 + 28800 }),
        leaseClaims({ exp: now + 3600 }),
      ]) {
        const token = signLease(claims, privateKey);
        expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x", "release-test-1", DIGEST, SUBJECT))
          .to.throw(LeaseVerificationError);
      }
    });
  });

  describe("getJwtSubject", () => {
    it("extracts a non-empty subject and rejects malformed tokens", () => {
      const payload = b64url(Buffer.from(JSON.stringify({ sub: SUBJECT })));
      expect(getJwtSubject(`header.${payload}.signature`)).to.equal(SUBJECT);
      expect(() => getJwtSubject("not-a-jwt")).to.throw(LeaseVerificationError);
    });
  });
});
