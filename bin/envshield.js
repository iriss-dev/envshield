#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

import { scanStagedFiles, scanDirectory, installHook, uninstallHook } from '../dist/index.js';

const args = process.argv.slice(2);
const command = args[0] || 'check';

async function main() {
  if (command === 'install') {
    const res = await installHook();
    if (res.ok) {
      console.log(`\x1b[32m✔\x1b[0m ${res.message}`);
      console.log(`  Hook location: \x1b[90m${res.path}\x1b[0m`);
      process.exit(0);
    } else {
      console.error(`\x1b[31m✖\x1b[0m ${res.message}`);
      process.exit(1);
    }
  }

  if (command === 'uninstall') {
    const res = await uninstallHook();
    console.log(`\x1b[32m✔\x1b[0m ${res.message}`);
    process.exit(0);
  }

  if (command === '--help' || command === '-h' || command === 'help') {
    console.log(`
envshield - Pre-commit secret leak prevention & audit

Usage:
  npx envshield [command]

Commands:
  check (default)  Scan staged git files for leaked secrets and .env files
  scan <dir>       Scan an entire directory recursively
  install          Install git pre-commit hook in the current repository
  uninstall        Remove the git pre-commit hook
  help             Show this help screen
`);
    process.exit(0);
  }

  let result;
  if (command === 'scan') {
    const targetDir = args[1] || '.';
    console.log(`\x1b[1mScanning directory:\x1b[0m ${targetDir}...`);
    result = await scanDirectory(targetDir);
  } else {
    // Default: check staged files
    result = await scanStagedFiles();
  }

  if (result.clean) {
    if (command === 'scan') {
      console.log(`\x1b[32m✔ Clean!\x1b[0m Scanned ${result.filesScanned} files. No secrets or .env files detected.`);
    }
    process.exit(0);
  }

  console.error(`\n\x1b[1;31m✖ [envshield] COMMIT BLOCKED — ${result.findings.length} secret(s) detected!\x1b[0m\n`);

  for (const f of result.findings) {
    const sevColor = f.severity === 'critical' ? '\x1b[41;37m CRITICAL \x1b[0m' : '\x1b[43;30m HIGH \x1b[0m';
    console.error(`  ${sevColor} \x1b[1m${f.rule}\x1b[0m`);
    console.error(`    File:     \x1b[36m${f.file}:${f.line}\x1b[0m`);
    console.error(`    Match:    \x1b[33m${f.preview}\x1b[0m\n`);
  }

  console.error(`\x1b[90mTip: Move secrets to .env.local or environment variables and stage again.\x1b[0m\n`);
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
