import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";

describe("scheduled live checks workflow", () => {
  it("serializes failure issue updates across refs", async () => {
    const workflow = parseYaml(
      await readFile(".github/workflows/scheduled-live-checks.yml", "utf8"),
    ) as {
      jobs?: Record<
        string,
        {
          concurrency?: {
            group?: string;
            "cancel-in-progress"?: boolean;
          };
        }
      >;
    };

    expect(workflow.jobs?.["open-failure-issue"]?.concurrency).toEqual({
      group: "clawhub-scheduled-live-checks-failure-issue",
      "cancel-in-progress": false,
    });
  });
});
