/* @vitest-environment jsdom */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = resolve(import.meta.dirname, "..");

function getCspHeader() {
  const vercelConfig = JSON.parse(readFileSync(resolve(repoRoot, "vercel.json"), "utf8"));
  const globalHeaders = vercelConfig.headers.find((entry) => entry.source === "/(.*)")?.headers;
  const csp = globalHeaders?.find((header) => header.key === "Content-Security-Policy")?.value;
  expect(csp).toEqual(expect.any(String));
  return csp;
}

function getDirective(csp, name) {
  return (
    csp
      .split(";")
      .map((directive) => directive.trim())
      .find((directive) => directive.startsWith(`${name} `)) ?? ""
  );
}

describe("Vercel security headers", () => {
  afterEach(() => {
    window.localStorage.clear();
    document.documentElement.className = "";
    delete document.documentElement.dataset.theme;
    delete document.documentElement.dataset.themeResolved;
    delete document.documentElement.dataset.themeMode;
    delete document.documentElement.dataset.themeFamily;
  });

  it("does not allow all inline scripts in the global CSP", () => {
    expect(getDirective(getCspHeader(), "script-src").split(/\s+/u)).not.toContain(
      "'unsafe-inline'",
    );
  });

  it("loads the theme bootstrap as an external self-hosted script", () => {
    const rootRoute = readFileSync(resolve(repoRoot, "src/routes/__root.tsx"), "utf8");

    expect(rootRoute).toContain('src="/theme-bootstrap.js');
    expect(rootRoute).not.toContain("dangerouslySetInnerHTML");
  });

  it("applies the stored theme selection from the external bootstrap", () => {
    window.localStorage.setItem(
      "clawhub-theme-selection",
      JSON.stringify({ theme: "claw", mode: "dark" }),
    );

    window.eval(readFileSync(resolve(repoRoot, "public/theme-bootstrap.js"), "utf8"));

    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.dataset.themeResolved).toBe("dark");
    expect(document.documentElement.dataset.themeMode).toBe("dark");
    expect(document.documentElement.dataset.themeFamily).toBe("claw");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
