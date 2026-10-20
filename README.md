# envshield

[![npm version](https://img.shields.io/npm/v/envshield.svg?style=flat-square)](https://www.npmjs.com/package/envshield)
[![CI](https://github.com/iriss-dev/envshield/actions/workflows/ci.yml/badge.svg)](https://github.com/iriss-dev/envshield/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg?style=flat-square)](https://nodejs.org)

Zero-dependency Git pre-commit hook and CI secret leak prevention for Node.js. Intercepts leaked `.env` files, API tokens, and private keys in **<15ms** before they reach GitHub.

Accidentally pushing `.env` files, Discord bot tokens, or cloud API keys leads to compromised infrastructure, leaked databases, and revoked credentials. `envshield` installs a lightweight pre-commit hook with a single command and scans staged git diffs using precise signatures and Shannon entropy analysis.

---

## 1-Second Setup

Run this once inside any git repository:

```bash
npx envshield install
```

From now on, whenever you run `git commit`, `envshield` verifies that no secrets or environment files are staged. If a leak is found, the commit is aborted immediately.

---

## What It Catches

- **Environment Files**: Staged `.env`, `.env.local`, `.env.production`, `.env.staging` (allows `.env.example`, `.env.template`).
- **Discord Tokens**: Bot and user tokens with base64 ID + timestamp + HMAC validation.
- **OpenAI & Anthropic Keys**: `sk-proj-...` and `sk-ant-...` API keys.
- **GitHub Personal Access Tokens**: `ghp_...`, `gho_...`, and fine-grained `github_pat_...` tokens.
- **Cloud & Payment Credentials**: AWS Access Keys (`AKIA...`), Stripe Live Secret Keys (`sk_live_...`), Slack tokens (`xoxb-...`).
- **Private Encryption Keys**: RSA, OpenSSH, DSA, EC, and PGP private key blocks (`-----BEGIN PRIVATE KEY-----`).
- **Unclassified Secrets**: High Shannon entropy string heuristic on variable assignments (`API_SECRET="9f7a8b..."`).

---

## Terminal Preview on Blocked Commit

```text
✖ [envshield] COMMIT BLOCKED — 2 secret(s) detected!

  CRITICAL  Unsafe Environment File (.env)
    File:     .env:1
    Match:    .env

  CRITICAL  OpenAI API Secret Key
    File:     src/config.ts:14
    Match:    sk-p...98a2

Tip: Move secrets to .env.local or environment variables and stage again.
```

---

## CLI Usage

```bash
# Check staged git files (default command run by pre-commit hook)
npx envshield check

# Scan an entire directory recursively (great for CI/CD pipelines)
npx envshield scan .

# Install the pre-commit hook into .git/hooks/pre-commit
npx envshield install

# Remove the pre-commit hook
npx envshield uninstall
```

---

## Programmatic API

```typescript
import { scanText, scanDirectory, scanStagedFiles } from 'envshield';

// Scan arbitrary source text
const findings = scanText(sourceCode, 'file.ts');

// Scan staged git changes
const stagedResult = await scanStagedFiles();
if (!stagedResult.clean) {
  console.log(`Found ${stagedResult.findings.length} leaks!`);
}

// Full directory scan for CI
const dirResult = await scanDirectory('./src');
```

---

## License

GNU General Public License v3.0 (GPL-3.0-or-later). See [LICENSE](./LICENSE) for details.

Copyright (c) 2026 Iris ([@iriss-dev](https://github.com/iriss-dev)).
