const { expect } = require("chai");

const {
  DEFAULT_LOCAL_AUTH_URL,
  planLegacyAuthUrlMigration,
  requireSecureAuthUrl,
  resolveAuthServerUrl,
} = require("../shared/authConfig");
const { DEPLOYMENT_PROFILES } = require("../shared/productConfig");

const PROVIDER_URL = "https://provider.example.com";

describe("auth config helpers", () => {
  const product = (deploymentProfile, authProviderUrl = "", deploymentId = "test") => ({
    deploymentProfile,
    deploymentId,
    authProviderUrl,
    collabProviderUrl: "",
    telemetryProviderUrl: "",
  });

  it("prefers a saved auth URL when it is explicitly set", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "https://staging-auth.example.com",
      configuredAuthServerUrl: "",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: () => true,
    });

    expect(resolved).to.equal("https://staging-auth.example.com");
  });

  it("falls back to localhost in a local dev workspace", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "",
      configuredAuthServerUrl: "",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: (candidate) => candidate.endsWith("/Pile_ou_Face_auth/app/main.py"),
    });

    expect(resolved).to.equal(DEFAULT_LOCAL_AUTH_URL);
  });

  it("migrates a saved URL equal to the configured provider default to localhost in local dev", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: PROVIDER_URL,
      configuredAuthServerUrl: "",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: (candidate) => candidate.endsWith("/Pile_ou_Face_auth/app/main.py"),
      defaultRemoteAuthUrl: PROVIDER_URL,
    });

    expect(resolved).to.equal(DEFAULT_LOCAL_AUTH_URL);
  });

  it("uses the configured provider default outside local development", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "",
      configuredAuthServerUrl: "",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: () => false,
      defaultRemoteAuthUrl: PROVIDER_URL,
    });

    expect(resolved).to.equal(PROVIDER_URL);
  });

  it("connects nowhere by default when no provider is configured (neutral OSS build)", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "",
      configuredAuthServerUrl: "",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: () => false,
      defaultRemoteAuthUrl: "",
    });

    expect(resolved).to.equal("");
  });

  it("uses only the product endpoint in the official SaaS profile", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "https://saved.example.com",
      configuredAuthServerUrl: "https://configured.example.com",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: () => true,
      productConfig: product(
        DEPLOYMENT_PROFILES.OFFICIAL_SAAS,
        "https://auth.pileouface.dev/",
        "official-saas",
      ),
    });
    expect(resolved).to.equal("https://auth.pileouface.dev");
  });

  it("uses only the administered endpoint in the managed on-prem profile", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "https://saved.example.com",
      configuredAuthServerUrl: "https://configured.example.com",
      productConfig: product(
        DEPLOYMENT_PROFILES.MANAGED_ON_PREM,
        "https://auth.customer.example.com",
        "customer-a",
      ),
    });
    expect(resolved).to.equal("https://auth.customer.example.com");
  });

  it("disables online auth in the air-gapped profile", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "https://saved.example.com",
      configuredAuthServerUrl: "https://configured.example.com",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: () => true,
      productConfig: product(DEPLOYMENT_PROFILES.AIRGAP_ENTERPRISE, "", "airgap-a"),
    });
    expect(resolved).to.equal("");
  });

  it("rejects insecure non-loopback endpoints", () => {
    expect(() => requireSecureAuthUrl("http://auth.example.com")).to.throw("HTTPS");
    expect(requireSecureAuthUrl("http://127.0.0.1:8000")).to.equal("http://127.0.0.1:8000");
  });

  it("migrates a legacy URL only into an unconfigured OSS profile", () => {
    expect(planLegacyAuthUrlMigration({
      deploymentProfile: DEPLOYMENT_PROFILES.OSS_DEVELOPMENT,
      legacyUrl: "https://auth.community.example",
    })).to.deep.equal({
      removeLegacy: true,
      configuredUrl: "https://auth.community.example",
    });
    expect(planLegacyAuthUrlMigration({
      deploymentProfile: DEPLOYMENT_PROFILES.OFFICIAL_SAAS,
      legacyUrl: "https://legacy.example",
      configuredUrl: "",
    })).to.deep.equal({ removeLegacy: true, configuredUrl: "" });
  });
});
