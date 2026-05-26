/* @vitest-environment node */

import { describe, expect, it } from "vitest";
import {
  clearSecurityScanCurrentRollupsPage,
  deleteSecurityScanArtifactState,
  recordSecurityScanHourlyRollupEvent,
  rebuildSecurityScanCurrentRollupsFromStatesPage,
  upsertSecurityScanArtifactState,
} from "../securityScanDigests";
import { buildSkillSecurityScanArtifactState } from "./securityScanDigest";

type FakeRow = Record<string, unknown> & {
  _id: string;
  _creationTime: number;
};

type FakeTable =
  | "securityScanArtifactStates"
  | "securityScanCurrentRollups"
  | "securityScanHourlyRollups"
  | "securityScanHourlyRollupEvents";

class FakeDb {
  private nextId = 1;
  readonly tables: Record<FakeTable, FakeRow[]> = {
    securityScanArtifactStates: [],
    securityScanCurrentRollups: [],
    securityScanHourlyRollups: [],
    securityScanHourlyRollupEvents: [],
  };

  query(table: FakeTable) {
    const tables = this.tables;
    const filters: Array<[string, unknown]> = [];
    const range = {
      eq(field: string, value: unknown) {
        filters.push([field, value]);
        return range;
      },
    };
    const query = {
      withIndex(_indexName: string, buildRange: (q: typeof range) => unknown) {
        buildRange(range);
        return query;
      },
      async unique() {
        const matches = tables[table].filter((row) =>
          filters.every(([field, value]) => row[field] === value),
        );
        if (matches.length > 1) throw new Error(`Expected unique ${table} row`);
        return matches[0] ?? null;
      },
      async take(limit: number) {
        return tables[table]
          .filter((row) => filters.every(([field, value]) => row[field] === value))
          .slice(0, limit);
      },
      async paginate(opts: { cursor: string | null; numItems: number }) {
        const offset = opts.cursor ? Number(opts.cursor) : 0;
        const matches = tables[table].filter((row) =>
          filters.every(([field, value]) => row[field] === value),
        );
        const page = matches.slice(offset, offset + opts.numItems);
        const nextOffset = offset + page.length;
        const isDone = nextOffset >= matches.length;
        return {
          page,
          isDone,
          continueCursor: isDone ? null : String(nextOffset),
        };
      },
    };
    return query;
  }

  async insert(table: FakeTable, fields: Record<string, unknown>) {
    const row = {
      ...fields,
      _id: `${table}:${this.nextId}`,
      _creationTime: this.nextId,
    };
    this.nextId++;
    this.tables[table].push(row);
    return row._id;
  }

  async patch(id: string, fields: Record<string, unknown>) {
    const row = this.findById(id);
    Object.assign(row, fields);
  }

  async delete(id: string) {
    for (const rows of Object.values(this.tables)) {
      const index = rows.findIndex((row) => row._id === id);
      if (index >= 0) {
        rows.splice(index, 1);
        return;
      }
    }
    throw new Error(`Missing row ${id}`);
  }

  private findById(id: string) {
    for (const row of Object.values(this.tables).flat()) {
      if (row._id === id) return row;
    }
    throw new Error(`Missing row ${id}`);
  }
}

const checkedAt = Date.UTC(2026, 0, 1, 12, 15, 0);

function makeCtx() {
  const db = new FakeDb();
  return { db, ctx: { db } as never };
}

function makeSkillState(verdict: "pass" | "malicious" = "pass", now = checkedAt) {
  return buildSkillSecurityScanArtifactState({
    skill: {
      _id: "skills:abc" as never,
      slug: "demo-skill",
      displayName: "Demo Skill",
      ownerUserId: "users:owner" as never,
      ownerPublisherId: "publishers:owner" as never,
    },
    version: {
      _id: "skillVersions:v1" as never,
      version: "1.0.0",
      createdAt: checkedAt - 1_000,
      vtAnalysis: undefined,
      skillSpectorAnalysis: undefined,
      staticScan: undefined,
      llmAnalysis:
        verdict === "malicious"
          ? {
              status: "malicious",
              verdict: "malicious",
              checkedAt,
            }
          : {
              status: "clean",
              verdict: "benign",
              checkedAt,
            },
    } as never,
    now,
  });
}

describe("security scan digest mutation helpers", () => {
  it("keeps current rollups idempotent across upserts and verdict changes", async () => {
    const { db, ctx } = makeCtx();
    await upsertSecurityScanArtifactState(ctx, makeSkillState("pass"));
    await upsertSecurityScanArtifactState(ctx, makeSkillState("pass", checkedAt + 1));

    expect(db.tables.securityScanArtifactStates).toHaveLength(1);
    expect(db.tables.securityScanCurrentRollups).toMatchObject([
      { clawScanVerdict: "pass", count: 1 },
    ]);

    await upsertSecurityScanArtifactState(ctx, makeSkillState("malicious", checkedAt + 2));

    expect(db.tables.securityScanArtifactStates).toHaveLength(1);
    expect(db.tables.securityScanCurrentRollups).toMatchObject([
      { clawScanVerdict: "malicious", count: 1 },
    ]);
  });

  it("decrements current rollups when an artifact state is pruned", async () => {
    const { db, ctx } = makeCtx();
    await upsertSecurityScanArtifactState(ctx, makeSkillState("pass"));

    await deleteSecurityScanArtifactState(
      ctx,
      db.tables.securityScanArtifactStates[0] as never,
      checkedAt + 1,
    );

    expect(db.tables.securityScanArtifactStates).toHaveLength(0);
    expect(db.tables.securityScanCurrentRollups).toHaveLength(0);
  });

  it("repairs drifted current rollups by clearing and rebuilding from artifact states", async () => {
    const { db, ctx } = makeCtx();
    await upsertSecurityScanArtifactState(ctx, makeSkillState("pass"));
    db.tables.securityScanCurrentRollups[0].count = 42;

    expect(await clearSecurityScanCurrentRollupsPage(ctx, { artifactKind: "skill" })).toMatchObject(
      {
        deletedCount: 1,
        isDone: true,
      },
    );
    expect(
      await rebuildSecurityScanCurrentRollupsFromStatesPage(ctx, {
        artifactKind: "skill",
        batchSize: 10,
      }),
    ).toMatchObject({
      scannedCount: 1,
      rollupDeltaCount: 1,
      isDone: true,
    });

    expect(db.tables.securityScanCurrentRollups).toMatchObject([
      { artifactKind: "skill", clawScanVerdict: "pass", count: 1 },
    ]);
  });

  it("records hourly rollup events idempotently by event key", async () => {
    const { db, ctx } = makeCtx();
    const dimensions = {
      artifactKind: "skill" as const,
      clawScanVerdict: "pass" as const,
      scanJobStatus: "succeeded" as const,
      failureStatus: "none" as const,
    };

    await recordSecurityScanHourlyRollupEvent(ctx, {
      eventKey: "securityScanJobs:job1:succeeded",
      occurredAt: checkedAt,
      dimensions,
    });
    const duplicate = await recordSecurityScanHourlyRollupEvent(ctx, {
      eventKey: "securityScanJobs:job1:succeeded",
      occurredAt: checkedAt,
      dimensions,
    });

    expect(duplicate).toMatchObject({ duplicate: true, updated: false });
    expect(db.tables.securityScanHourlyRollupEvents).toHaveLength(1);
    expect(db.tables.securityScanHourlyRollups).toMatchObject([
      { artifactKind: "skill", clawScanVerdict: "pass", count: 1 },
    ]);
  });
});
