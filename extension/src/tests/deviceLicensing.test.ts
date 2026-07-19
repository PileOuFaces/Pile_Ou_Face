// @ts-nocheck
const { expect } = require("chai");
const crypto = require("crypto");
const {
  generateDeviceKeypair,
  generateDeviceId,
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

function signLease(payload, signingPrivateKeyPem) {
  const header = { alg: "RS256", typ: "JWT" };
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
      const now = Math.floor(Date.now() / 1000);
      const token = signLease(
        { device_id: "dev-1", plugin_id: "pof.x", iat: now, exp: now + 3600 },
        privateKey,
      );
      const payload = verifyLeaseJwt(token, jwks, "dev-1", "pof.x");
      expect(payload.device_id).to.equal("dev-1");
    });

    it("rejects a lease signed by an unknown key", () => {
      const { jwks } = serverKeypair();
      const attacker = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      const now = Math.floor(Date.now() / 1000);
      const token = signLease(
        { device_id: "dev-1", plugin_id: "pof.x", iat: now, exp: now + 3600 },
        attacker.privateKey,
      );
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x")).to.throw(LeaseVerificationError);
    });

    it("rejects an expired lease", () => {
      const { privateKey, jwks } = serverKeypair();
      const now = Math.floor(Date.now() / 1000);
      const token = signLease(
        { device_id: "dev-1", plugin_id: "pof.x", iat: now - 7200, exp: now - 3600 },
        privateKey,
      );
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x")).to.throw(LeaseVerificationError, /expired/);
    });

    it("rejects a lease issued for a different device_id", () => {
      const { privateKey, jwks } = serverKeypair();
      const now = Math.floor(Date.now() / 1000);
      const token = signLease(
        { device_id: "dev-OTHER", plugin_id: "pof.x", iat: now, exp: now + 3600 },
        privateKey,
      );
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x")).to.throw(LeaseVerificationError, /device_id/);
    });

    it("rejects a lease issued for a different plugin_id", () => {
      const { privateKey, jwks } = serverKeypair();
      const now = Math.floor(Date.now() / 1000);
      const token = signLease(
        { device_id: "dev-1", plugin_id: "pof.OTHER", iat: now, exp: now + 3600 },
        privateKey,
      );
      expect(() => verifyLeaseJwt(token, jwks, "dev-1", "pof.x")).to.throw(LeaseVerificationError, /plugin_id/);
    });

    it("rejects a malformed token", () => {
      const { jwks } = serverKeypair();
      expect(() => verifyLeaseJwt("not-a-jwt", jwks, "dev-1", "pof.x")).to.throw(LeaseVerificationError);
    });
  });
});
