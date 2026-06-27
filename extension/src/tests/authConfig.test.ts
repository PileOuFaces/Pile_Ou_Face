const { expect } = require("chai");

const {
  DEFAULT_LOCAL_AUTH_URL,
  DEFAULT_REMOTE_AUTH_URL,
  resolveAuthServerUrl,
} = require("../shared/authConfig");

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

  it("migrates the old saved production default to localhost in local dev", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: DEFAULT_REMOTE_AUTH_URL,
      configuredAuthServerUrl: "",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: (candidate) => candidate.endsWith("/Pile_ou_Face_auth/app/main.py"),
    });

    expect(resolved).to.equal(DEFAULT_LOCAL_AUTH_URL);
  });

  it("keeps the remote default outside local development", () => {
    const resolved = resolveAuthServerUrl({
      savedAuthServerUrl: "",
      configuredAuthServerUrl: "",
      projectRoot: "/workspace/Pile_Ou_Face",
      existsSync: () => false,
    });

    expect(resolved).to.equal(DEFAULT_REMOTE_AUTH_URL);
  });
});
