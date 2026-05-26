/* @vitest-environment node */

import { describe, expect, it } from "vitest";
import {
  buildPluginSecurityScanArtifactState,
  buildSkillSecurityScanArtifactState,
  clampSecurityScanDigestBackfillBatchSize,
  clawScanVerdictForState,
  clawScanVerdictFromLlmAnalysis,
  getCurrentRollupDeltas,
  toSecurityScanHourBucket,
} from "./securityScanDigest";

const checkedAt = Date.UTC(2026, 0, 1, 12, 15, 0);

function makeClawScanAnalysis(overrides: Record<string, unknown> = {}) {
  return {
    status: "clean",
    verdict: "benign",
    summary: "Looks purpose aligned.",
    checkedAt,
    ...overrides,
  } as never;
}

function makeSkill(overrides: Record<string, unknown> = {}) {
  return {
    _id: "skills:abc" as never,
    slug: "demo-skill",
    displayName: "Demo Skill",
    ownerUserId: "users:owner" as never,
    ownerPublisherId: "publishers:owner" as never,
    ...overrides,
  };
}

function makeSkillVersion(overrides: Record<string, unknown> = {}) {
  return {
    _id: "skillVersions:v1" as never,
    version: "1.0.0",
    createdAt: checkedAt - 1_000,
    vtAnalysis: undefined,
    skillSpectorAnalysis: undefined,
    llmAnalysis: makeClawScanAnalysis(),
    staticScan: undefined,
    ...overrides,
  };
}

function makePackage(overrides: Record<string, unknown> = {}) {
  return {
    _id: "packages:plugin" as never,
    name: "@demo/plugin",
    displayName: "Demo Plugin",
    ownerUserId: "users:owner" as never,
    ownerPublisherId: "publishers:owner" as never,
    ...overrides,
  };
}

function makePackageRelease(overrides: Record<string, unknown> = {}) {
  return {
    _id: "packageReleases:r1" as never,
    version: "2.0.0",
    createdAt: checkedAt - 1_000,
    vtAnalysis: undefined,
    skillSpectorAnalysis: undefined,
    llmAnalysis: undefined,
    staticScan: undefined,
    ...overrides,
  };
}

function makeJob(overrides: Record<string, unknown> = {}) {
  return {
    _id: "securityScanJobs:j1" as never,
    status: "queued",
    source: "publish",
    createdAt: checkedAt - 500,
    updatedAt: checkedAt - 250,
    completedAt: undefined,
    lastError: undefined,
    ...overrides,
  };
}

describe("clawScanVerdictFromLlmAnalysis", () => {
  it("maps ClawScan/Codex verdicts into dashboard buckets", () => {
    expect(clawScanVerdictFromLlmAnalysis(makeClawScanAnalysis())).toBe("pass");
    expect(
      clawScanVerdictFromLlmAnalysis(
        makeClawScanAnalysis({ status: "suspicious", verdict: "suspicious" }),
      ),
    ).toBe("suspicious");
    expect(
      clawScanVerdictFromLlmAnalysis(
        makeClawScanAnalysis({ status: "completed", verdict: "malicious" }),
      ),
    ).toBe("malicious");
    expect(clawScanVerdictFromLlmAnalysis(undefined)).toBe("pending");
  });

  it("promotes clean ClawScan results with visible medium-or-higher findings to review", () => {
    expect(
      clawScanVerdictFromLlmAnalysis(
        makeClawScanAnalysis({
          agenticRiskFindings: [
            {
              categoryId: "ASI03",
              categoryLabel: "Identity and Privilege Abuse",
              riskBucket: "permission_boundary",
              status: "note",
              severity: "medium",
              confidence: "medium",
              evidence: {
                path: "metadata",
                snippet: "requires.env: TODOIST_API_TOKEN",
                explanation: "Broad account access is material.",
              },
              userImpact: "Account-level access.",
              recommendation: "Review the permission scope.",
            },
          ],
        }),
      ),
    ).toBe("suspicious");
  });
});

describe("clawScanVerdictForState", () => {
  it("uses queued/running/failed job state when no ClawScan analysis exists", () => {
    expect(clawScanVerdictForState({ scanJobStatus: "queued" })).toBe("pending");
    expect(clawScanVerdictForState({ scanJobStatus: "running" })).toBe("pending");
    expect(clawScanVerdictForState({ scanJobStatus: "failed" })).toBe("failed");
    expect(clawScanVerdictForState({ scanJobStatus: "none" })).toBe("unknown");
  });
});

describe("security scan digest builders", () => {
  it("builds a skill artifact state with ClawScan as the verdict source and scanner evidence", () => {
    const state = buildSkillSecurityScanArtifactState({
      skill: makeSkill() as never,
      version: makeSkillVersion({
        llmAnalysis: makeClawScanAnalysis({ status: "clean", verdict: "benign" }),
        skillSpectorAnalysis: {
          status: "suspicious",
          score: 85,
          severity: "HIGH",
          recommendation: "REVIEW",
          issueCount: 1,
          issues: [
            {
              issueId: "secret-egress",
              category: "Prompt Injection",
              severity: "HIGH",
              explanation: "Possible injection.",
            },
          ],
          checkedAt,
        },
        staticScan: {
          status: "malicious",
          reasonCodes: ["malicious.external_transfer"],
          findings: [],
          summary: "External transfer.",
          engineVersion: "v1",
          checkedAt,
        },
      }) as never,
      scanJob: makeJob({ status: "succeeded", completedAt: checkedAt }) as never,
      now: checkedAt,
    });

    expect(state.artifactKind).toBe("skill");
    expect(state.artifactKey).toBe("skill:skills:abc");
    expect(state.targetKey).toBe("skillVersion:skillVersions:v1");
    expect(state.clawScanVerdict).toBe("pass");
    expect(state.scanJobStatus).toBe("succeeded");
    expect(state.skillSpectorScore).toBe(85);
    expect(state.skillSpectorTopCategory).toBe("Prompt Injection");
    expect(state.staticStatus).toBe("malicious");
  });

  it("builds a plugin artifact state for failed scans without source analysis", () => {
    const state = buildPluginSecurityScanArtifactState({
      pkg: makePackage() as never,
      release: makePackageRelease() as never,
      scanJob: makeJob({ status: "failed", lastError: "Worker timed out" }) as never,
      now: checkedAt,
    });

    expect(state.artifactKind).toBe("plugin");
    expect(state.name).toBe("@demo/plugin");
    expect(state.clawScanVerdict).toBe("failed");
    expect(state.scanJobStatus).toBe("failed");
    expect(state.failureStatus).toBe("failed");
    expect(state.lastError).toBe("Worker timed out");
  });
});

describe("security scan digest rollups", () => {
  it("computes current rollup deltas when an artifact changes verdict and category", () => {
    const previous = buildSkillSecurityScanArtifactState({
      skill: makeSkill() as never,
      version: makeSkillVersion() as never,
      now: checkedAt,
    });
    const next = buildSkillSecurityScanArtifactState({
      skill: makeSkill() as never,
      version: makeSkillVersion({
        llmAnalysis: makeClawScanAnalysis({
          status: "malicious",
          verdict: "malicious",
          agenticRiskFindings: [
            {
              categoryId: "ASI07",
              categoryLabel: "Insecure Inter-Agent Communication",
              riskBucket: "sensitive_data_protection",
              status: "concern",
              severity: "critical",
              confidence: "high",
              evidence: {
                path: "SKILL.md",
                snippet: "send secrets",
                explanation: "Secrets leave the workspace.",
              },
              userImpact: "Secret exfiltration.",
              recommendation: "Remove the transfer.",
            },
          ],
        }),
      }) as never,
      now: checkedAt + 1,
    });

    const deltas = getCurrentRollupDeltas(previous, next);

    expect(deltas).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          delta: -1,
          dimensions: expect.objectContaining({
            rollupKind: "all",
            clawScanVerdict: "pass",
          }),
        }),
        expect.objectContaining({
          delta: 1,
          dimensions: expect.objectContaining({
            rollupKind: "all",
            clawScanVerdict: "malicious",
          }),
        }),
        expect.objectContaining({
          delta: 1,
          dimensions: expect.objectContaining({
            rollupKind: "clawscanRiskBucket",
            categoryKey: "sensitive_data_protection",
          }),
        }),
        expect.objectContaining({
          delta: 1,
          dimensions: expect.objectContaining({
            rollupKind: "clawscanCategory",
            categoryKey: "ASI07",
          }),
        }),
      ]),
    );
  });

  it("computes decrement deltas when an artifact state is pruned", () => {
    const previous = buildSkillSecurityScanArtifactState({
      skill: makeSkill() as never,
      version: makeSkillVersion() as never,
      now: checkedAt,
    });

    expect(getCurrentRollupDeltas(previous, null)).toEqual([
      expect.objectContaining({
        delta: -1,
        dimensions: expect.objectContaining({
          rollupKind: "all",
          categoryKey: "all",
          clawScanVerdict: "pass",
        }),
      }),
    ]);
  });
});

describe("security scan digest backfill helpers", () => {
  it("rounds timestamps down to hourly buckets", () => {
    expect(toSecurityScanHourBucket(Date.UTC(2026, 0, 1, 12, 59, 59))).toBe(
      Date.UTC(2026, 0, 1, 12, 0, 0),
    );
  });

  it("clamps page size for cursor-safe backfills", () => {
    expect(clampSecurityScanDigestBackfillBatchSize(undefined)).toBe(50);
    expect(clampSecurityScanDigestBackfillBatchSize(0)).toBe(1);
    expect(clampSecurityScanDigestBackfillBatchSize(500)).toBe(250);
    expect(clampSecurityScanDigestBackfillBatchSize(12.8)).toBe(12);
  });
});
