#!/usr/bin/env node
//
// Fails when the frontend dependency tree carries an advisory the residual-risk
// register does not record, or one whose severity is above what that tree is
// allowed to carry.
//
// npm audit exits non-zero while any advisory remains, which cannot
// distinguish "a new advisory appeared" from "the recorded ones are still
// here". The report is therefore written by npm and judged here.
//
// frontend/package.json and frontend/package-lock.json are reference-only in
// this change set, and every remaining advisory needs either a dependency
// major upgrade or a replacement of the build toolchain, so the register
// records what that tree already carries rather than demanding zero. It is a
// ratchet in two independent directions: an identifier that is not recorded
// fails the job, and so does a severity above the tree's ceiling, even for an
// identifier that is recorded.
//
// Every identifier below appears in docs/security/RESIDUAL_RISK.md with its
// reachability evidence and its compensating control, and
// test_frontend_audit_register_matches_the_gate in
// backend/tests/security/test_pipeline_audit_contract.py fails if the two
// lists ever disagree.
//
// Usage: node check_frontend_audit_budget.js <report.json> <production|full>

"use strict";

const fs = require("fs");

// Advisories the register accepts, per tree. "production" is the tree the
// client would ship with, audited as `npm audit --omit=dev`; "full" adds the
// build and test toolchain, audited as `npm audit`.
const ACCEPTED = {
  production: [
    "GHSA-337j-9hxr-rhxg",
    "GHSA-jjmj-jmhj-qwj2",
    "GHSA-wrjc-x8rr-h8h6",
  ],
  full: [
    "GHSA-2p49-hgcm-8545",
    "GHSA-337j-9hxr-rhxg",
    "GHSA-4v9v-hfq4-rm2v",
    "GHSA-5c6j-r48x-rmvq",
    "GHSA-6g55-p6wh-862q",
    "GHSA-79cf-xcqc-c78w",
    "GHSA-7fh5-64p2-3v2j",
    "GHSA-9jgg-88mc-972h",
    "GHSA-f5vj-f2hx-8m93",
    "GHSA-fxqj-rqcc-2cmp",
    "GHSA-jjmj-jmhj-qwj2",
    "GHSA-m28w-2pqf-7qgj",
    "GHSA-mx8g-39q3-5c79",
    "GHSA-qj8w-gfj5-8c6v",
    "GHSA-qpx9-hpmf-5gmw",
    "GHSA-qx2v-qp2m-jg93",
    "GHSA-r28c-9q8g-f849",
    "GHSA-rp65-9cf3-cjxr",
    "GHSA-vpq2-c234-7xj6",
    "GHSA-w5hq-g745-h8pq",
    "GHSA-wrjc-x8rr-h8h6",
  ],
};

// Highest severity each tree may carry. The shipping tree carries only
// advisories in the router, which are moderate; the build toolchain carries
// high ones that no supported upgrade path reaches. A critical advisory in
// either tree is a decision nobody has taken, so neither ceiling admits one.
const CEILING = {
  production: "moderate",
  full: "high",
};

const ORDER = ["info", "low", "moderate", "high", "critical"];

const reportPath = process.argv[2];
const tree = process.argv[3];

if (!reportPath || !tree) {
  console.error(
    "usage: node check_frontend_audit_budget.js <report.json> " +
    "<production|full>"
  );
  process.exit(1);
}

if (!Object.prototype.hasOwnProperty.call(ACCEPTED, tree)) {
  console.error(
    "unknown tree '" + tree + "'; expected one of " +
    Object.keys(ACCEPTED).sort().join(", ")
  );
  process.exit(1);
}

const accepted = new Set(ACCEPTED[tree]);
const ceiling = ORDER.indexOf(CEILING[tree]);

let report;

try {
  report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
} catch (error) {
  console.error("could not read " + reportPath + ": " + error.message);
  process.exit(1);
}

// A report npm could not produce - no lockfile, no registry - carries an
// error object and no vulnerabilities map. Judging it would report zero
// advisories from a run that audited nothing.
if (report && report.error) {
  console.error(
    "npm audit reported an error rather than a result: " +
    JSON.stringify(report.error)
  );
  process.exit(1);
}

const packages = report && report.vulnerabilities;
const counts =
  report && report.metadata ? report.metadata.vulnerabilities : null;

if (!packages || typeof packages !== "object" || !counts) {
  console.error(
    reportPath + " does not carry an npm audit result: a 'vulnerabilities' " +
    "map and a 'metadata.vulnerabilities' summary are both required."
  );
  process.exit(1);
}

// One entry per advisory identifier, taken from the advisory objects in each
// package's `via` list. A string in that list names a parent package rather
// than an advisory, so it is skipped.
const found = new Map();

for (const name of Object.keys(packages).sort()) {
  const entry = packages[name] || {};
  for (const via of entry.via || []) {
    if (!via || typeof via !== "object") {
      continue;
    }
    const url = typeof via.url === "string" ? via.url : "";
    const identifier = url
      ? url.replace(/\/+$/, "").split("/").pop()
      : String(via.source || "");
    if (!identifier) {
      continue;
    }
    if (!found.has(identifier)) {
      found.set(identifier, {
        severity: String(via.severity || "unknown"),
        package: String(via.name || name),
        title: String(via.title || ""),
      });
    }
  }
}

const identifiers = Array.from(found.keys()).sort();
const unrecorded = identifiers.filter((id) => !accepted.has(id));
const fixed = Array.from(accepted).sort().filter((id) => !found.has(id));
const aboveCeiling = identifiers.filter(
  (id) => ORDER.indexOf(found.get(id).severity) > ceiling
);

const bySeverity = ORDER.map((severity) => {
  const total = identifiers.filter(
    (id) => found.get(id).severity === severity
  ).length;
  return total ? severity + " " + total : "";
})
  .filter(Boolean)
  .join(", ") || "none";

console.log(
  "frontend audit (" + tree + "): " + identifiers.length +
  " advisories across " + Object.keys(packages).length +
  " vulnerable packages [" + bySeverity + "]; register records " +
  accepted.size + ", ceiling " + CEILING[tree]
);
console.log(
  "  npm's own node counts: " + JSON.stringify(counts)
);

for (const id of fixed) {
  console.log(
    "::notice::" + id + " is no longer reported for the " + tree +
    " tree. Remove it from docs/security/RESIDUAL_RISK.md and from " +
    "ACCEPTED." + tree + " in this script."
  );
}

let failed = false;

if (unrecorded.length > 0) {
  failed = true;
  console.error(
    "These advisories are not recorded for the " + tree + " tree:"
  );
  for (const id of unrecorded) {
    const info = found.get(id);
    console.error(
      "  " + id + "  " + info.severity + "  " + info.package + "  " +
      info.title
    );
  }
  console.error(
    "Resolve it, or record it in docs/security/RESIDUAL_RISK.md with its " +
    "reachability evidence and its compensating control and add it to " +
    "ACCEPTED." + tree + " in this script."
  );
}

if (aboveCeiling.length > 0) {
  failed = true;
  console.error(
    "These advisories are above the " + CEILING[tree] + " ceiling the " +
    tree + " tree carries:"
  );
  for (const id of aboveCeiling) {
    const info = found.get(id);
    console.error(
      "  " + id + "  " + info.severity + "  " + info.package + "  " +
      info.title
    );
  }
  console.error(
    "A severity above the ceiling is a risk decision of its own. Resolve " +
    "it, or raise CEILING." + tree + " in this script and record the " +
    "reason in docs/security/RESIDUAL_RISK.md."
  );
}

if (failed) {
  process.exit(1);
}
