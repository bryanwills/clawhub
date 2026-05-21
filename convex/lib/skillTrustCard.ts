import type { Doc, Id } from "../_generated/dataModel";

type TrustCardPublisher = {
  userId: Id<"users">;
  publisherId?: Id<"publishers">;
  handle?: string;
  displayName?: string;
};

type TrustCardInput = {
  slug: string;
  displayName: string;
  version: string;
  fingerprint: string;
  files: Doc<"skillVersions">["files"];
  parsed: Doc<"skillVersions">["parsed"];
  source?: SkillTrustCard["source"];
  capabilityTags?: string[];
  staticScan: NonNullable<Doc<"skillVersions">["staticScan"]>;
  publisher: TrustCardPublisher;
  generatedAt: number;
};

export type SkillTrustCard = NonNullable<Doc<"skillVersions">["trustCard"]>;
type StaticScan = NonNullable<Doc<"skillVersions">["staticScan"]>;

export function buildSkillTrustCard(input: TrustCardInput): SkillTrustCard {
  const clawdis = input.parsed.clawdis;

  return {
    format: "clawhub.skill.trust-card.v1",
    generatedAt: input.generatedAt,
    generator: {
      name: "clawhub",
      version: "skill-trust-card-v1",
    },
    subject: {
      kind: "skill",
      slug: input.slug,
      displayName: input.displayName,
      version: input.version,
    },
    publisher: input.publisher,
    ...(input.source ? { source: input.source } : {}),
    artifact: {
      fingerprint: input.fingerprint,
      ...(input.parsed.license ? { license: input.parsed.license } : {}),
      files: input.files.map((file) => ({
        path: file.path,
        size: file.size,
        sha256: file.sha256,
        ...(file.contentType ? { contentType: file.contentType } : {}),
      })),
    },
    capabilities: {
      ...(input.capabilityTags?.length ? { tags: input.capabilityTags } : {}),
      ...(clawdis?.os?.length ? { os: clawdis.os } : {}),
      ...(clawdis?.requires ? { requires: clawdis.requires } : {}),
      ...(clawdis?.envVars?.length ? { envVars: clawdis.envVars } : {}),
      ...(clawdis?.install?.length ? { install: clawdis.install } : {}),
      ...(clawdis?.dependencies?.length ? { dependencies: clawdis.dependencies } : {}),
    },
    audit: skillTrustCardAuditFromStaticScan(input.staticScan),
    signature: {
      status: "unsigned",
    },
  };
}

export function refreshSkillTrustCardAudit(input: {
  trustCard?: SkillTrustCard;
  staticScan: StaticScan;
  generatedAt: number;
}): SkillTrustCard | undefined {
  if (!input.trustCard) return undefined;
  return {
    ...input.trustCard,
    generatedAt: input.generatedAt,
    audit: skillTrustCardAuditFromStaticScan(input.staticScan),
  };
}

function skillTrustCardAuditFromStaticScan(staticScan: StaticScan): SkillTrustCard["audit"] {
  return {
    status: auditStatusFromStaticScan(staticScan.status),
    summary: staticScan.summary,
    reasonCodes: staticScan.reasonCodes,
    scanners: {
      static: {
        status: staticScan.status,
        summary: staticScan.summary,
        reasonCodes: staticScan.reasonCodes,
        engineVersion: staticScan.engineVersion,
        checkedAt: staticScan.checkedAt,
      },
    },
  };
}

function auditStatusFromStaticScan(status: StaticScan["status"]) {
  switch (status) {
    case "clean":
      return "pass" as const;
    case "suspicious":
      return "review" as const;
    case "malicious":
      return "malicious" as const;
  }
  throw new Error("Unknown static scan status");
}
