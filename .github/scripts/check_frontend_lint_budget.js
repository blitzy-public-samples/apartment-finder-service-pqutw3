#!/usr/bin/env node
//
// Fails when the frontend carries a lint error, or more lint warnings than
// the recorded budget.
//
// eslint exits non-zero while any problem remains, which cannot distinguish
// "a new problem was introduced" from "the known problems are still here".
// The report is therefore written by eslint and judged here.
//
// frontend/src is read-only reference material in this change set, so the
// budget records the warning count that source already carries rather than
// demanding zero. It is a ratchet: a new warning exceeds the budget and
// fails the job, while the existing ones do not.
//
// src/services/paypal.ts is exempt because it holds JSX in a .ts file,
// which no parser accepts. That defect is in read-only frontend source and
// is recorded as a reported finding in SECURITY.md rather than fixed here.
// It is exempted here rather than excluded from the lint run, so the
// finding stays visible in the uploaded report.

"use strict";

const fs = require("fs");
const path = require("path");

const EXEMPT = new Set(["src/services/paypal.ts"]);
const reportPath = process.argv[2] || "eslint-report.json";
const budget = Number(process.env.ESLINT_WARNING_BUDGET || "0");

if (!Number.isInteger(budget) || budget < 0) {
  console.error("ESLINT_WARNING_BUDGET must be a non-negative whole number.");
  process.exit(1);
}

let report;

try {
  report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
} catch (error) {
  console.error("could not read " + reportPath + ": " + error.message);
  process.exit(1);
}

let errors = 0;
let warnings = 0;
const offenders = [];

for (const file of report) {
  const relative = path.relative(process.cwd(), file.filePath)
    .split(path.sep).join("/");

  if (EXEMPT.has(relative)) {
    continue;
  }

  errors += file.errorCount;
  warnings += file.warningCount;

  if (file.errorCount > 0) {
    offenders.push(relative + " (" + file.errorCount + " errors)");
  }
}

console.log(
  "frontend lint: " + errors + " errors, " + warnings +
  " warnings, budget " + budget
);

if (errors > 0) {
  console.error("These files carry lint errors:");
  for (const offender of offenders) {
    console.error("  " + offender);
  }
  process.exit(1);
}

if (warnings > budget) {
  console.error(
    "The warning count " + warnings + " exceeds the budget " + budget +
    ". Resolve the new warning, or record the new count in " +
    "ESLINT_WARNING_BUDGET with the reason."
  );
  process.exit(1);
}