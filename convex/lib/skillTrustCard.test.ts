/* @vitest-environment node */

import { describe, expect, it } from "vitest";
import type { Doc, Id } from "../_generated/dataModel";
import { buildSkillTrustCard, refreshSkillTrustCardAudit } from "./skillTrustCard";

describe("buildSkillTrustCard", () => {
  it("records release identity, hashes, capabilities, audit, and unsigned signature", () => {
    const card = buildSkillTrustCard({
      slug: "demo",
      displayName: "Demo",
      version: "1.2.3",
      fingerprint: "sha256:release",
      files: [
        {
          path: "SKILL.md",
          size: 42,
          storageId: "storage:skill" as Id<"_storage">,
          sha256: "sha256:file",
          contentType: "text/markdown",
        },
      ],
      parsed: {
        frontmatter: {},
        license: "MIT-0",
        clawdis: {
          os: ["darwin"],
          requires: {
            env: ["DEMO_TOKEN"],
            bins: ["gh"],
          },
          envVars: [{ name: "DEMO_TOKEN", required: true }],
        },
      } as Doc<"skillVersions">["parsed"],
      source: {
        kind: "github",
        url: "https://github.com/acme/demo/tree/main/skills/demo",
        repo: "acme/demo",
        ref: "main",
        commit: "0123456789abcdef",
        path: "skills/demo",
      },
      capabilityTags: ["github", "shell"],
      staticScan: {
        status: "clean",
        reasonCodes: ["scanner.static.clean"],
        findings: [],
        summary: "No static findings.",
        engineVersion: "static-v1",
        checkedAt: 123,
      },
      publisher: {
        userId: "users:publisher" as Id<"users">,
        publisherId: "publishers:pub" as Id<"publishers">,
        handle: "acme",
        displayName: "Acme",
      },
      generatedAt: 456,
    });

    expect(card.format).toBe("clawhub.skill.trust-card.v1");
    expect(card.subject).toEqual({
      kind: "skill",
      slug: "demo",
      displayName: "Demo",
      version: "1.2.3",
    });
    expect(card.source).toEqual({
      kind: "github",
      url: "https://github.com/acme/demo/tree/main/skills/demo",
      repo: "acme/demo",
      ref: "main",
      commit: "0123456789abcdef",
      path: "skills/demo",
    });
    expect(card.artifact.files).toEqual([
      {
        path: "SKILL.md",
        size: 42,
        sha256: "sha256:file",
        contentType: "text/markdown",
      },
    ]);
    expect(card.capabilities.tags).toEqual(["github", "shell"]);
    expect(card.capabilities.requires?.env).toEqual(["DEMO_TOKEN"]);
    expect(card.audit.status).toBe("pass");
    expect(card.audit.scanners.static.status).toBe("clean");
    expect(card.signature.status).toBe("unsigned");
  });

  it("does not derive source provenance from author-controlled metadata", () => {
    const card = buildSkillTrustCard({
      slug: "demo",
      displayName: "Demo",
      version: "1.0.0",
      fingerprint: "sha256:release",
      files: [],
      parsed: {
        frontmatter: {},
        metadata: {
          source: {
            kind: "github",
            url: "https://github.com/forged/repo",
            repo: "forged/repo",
            ref: "main",
            commit: "0123456789abcdef",
            path: ".",
          },
        },
      } as Doc<"skillVersions">["parsed"],
      staticScan: {
        status: "clean",
        reasonCodes: ["scanner.static.clean"],
        findings: [],
        summary: "No static findings.",
        engineVersion: "static-v1",
        checkedAt: 123,
      },
      publisher: { userId: "users:publisher" as Id<"users"> },
      generatedAt: 456,
    });

    expect(card.source).toBeUndefined();
  });

  it("maps suspicious static scan to review", () => {
    const card = buildSkillTrustCard({
      slug: "demo",
      displayName: "Demo",
      version: "1.0.0",
      fingerprint: "sha256:release",
      files: [],
      parsed: { frontmatter: {} } as Doc<"skillVersions">["parsed"],
      staticScan: {
        status: "suspicious",
        reasonCodes: ["suspicious.network"],
        findings: [],
        summary: "Network behavior needs review.",
        engineVersion: "static-v1",
        checkedAt: 123,
      },
      publisher: { userId: "users:publisher" as Id<"users"> },
      generatedAt: 456,
    });

    expect(card.audit.status).toBe("review");
    expect(card.audit.reasonCodes).toEqual(["suspicious.network"]);
  });

  it("refreshes audit fields from a later static scan", () => {
    const card = buildSkillTrustCard({
      slug: "demo",
      displayName: "Demo",
      version: "1.0.0",
      fingerprint: "sha256:release",
      files: [],
      parsed: { frontmatter: {} } as Doc<"skillVersions">["parsed"],
      staticScan: {
        status: "clean",
        reasonCodes: ["scanner.static.clean"],
        findings: [],
        summary: "No static findings.",
        engineVersion: "static-v1",
        checkedAt: 123,
      },
      publisher: { userId: "users:publisher" as Id<"users"> },
      generatedAt: 456,
    });

    const refreshed = refreshSkillTrustCardAudit({
      trustCard: card,
      staticScan: {
        status: "malicious",
        reasonCodes: ["malicious.install_terminal_payload"],
        findings: [],
        summary: "Terminal payload detected.",
        engineVersion: "static-v2",
        checkedAt: 789,
      },
      generatedAt: 900,
    });

    expect(refreshed?.generatedAt).toBe(900);
    expect(refreshed?.artifact).toEqual(card.artifact);
    expect(refreshed?.audit.status).toBe("malicious");
    expect(refreshed?.audit.summary).toBe("Terminal payload detected.");
    expect(refreshed?.audit.scanners.static.engineVersion).toBe("static-v2");
  });
});
