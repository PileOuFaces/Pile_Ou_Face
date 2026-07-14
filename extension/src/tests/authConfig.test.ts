const { expect } = require("chai");

const {
  DEFAULT_LOCAL_AUTH_URL,
  resolveAuthServerUrl,
} = require("../shared/authConfig");

const PROVIDER_URL = "https://provider.example.com";

describe("auth config helpers", () => {
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
});
