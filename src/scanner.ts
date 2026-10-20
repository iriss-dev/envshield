// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScanResult, SecretFinding } from './types.js';
import { BUILTIN_RULES } from './rules.js';
import { isHighEntropyToken } from './entropy.js';

const execFileAsync = promisify(execFile);

function maskSecret(raw: string): string {
  const clean = raw.trim();
  if (clean.length <= 8) return '********';
  return `${clean.slice(0, 4)}...${clean.slice(-4)}`;
}

export function scanText(content: string, filename: string): SecretFinding[] {
  const findings: SecretFinding[] = [];

  // Check filename-based rules
  for (const rule of BUILTIN_RULES) {
    if (rule.checkFilename && rule.checkFilename(filename)) {
      findings.push({
        file: filename,
        line: 1,
        rule: rule.name,
        preview: filename,
        severity: rule.severity
      });
      return findings;
    }
  }

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) {
      // Skip pure comment lines
      continue;
    }

    for (const rule of BUILTIN_RULES) {
      if (rule.pattern) {
        const match = rule.pattern.exec(line);
        if (match) {
          findings.push({
            file: filename,
            line: i + 1,
            rule: rule.name,
            preview: maskSecret(match[0]),
            severity: rule.severity
          });
          break; // Stop after highest priority rule matches this line
        }
      }
    }

    // Entropy check for unclassified raw assignments (e.g. SECRET="...")
    const assignMatch = /(?:secret|token|password|auth|api_?key)\s*[:=]\s*["']?([a-zA-Z0-9_-]{24,100})["']?/i.exec(line);
    if (assignMatch && isHighEntropyToken(assignMatch[1])) {
      const alreadyFlagged = findings.some((f) => f.file === filename && f.line === i + 1);
      if (!alreadyFlagged) {
        findings.push({
          file: filename,
          line: i + 1,
          rule: 'High Entropy Credential Assignment',
          preview: maskSecret(assignMatch[1]),
          severity: 'medium'
        });
      }
    }
  }

  return findings;
}

export async function scanStagedFiles(): Promise<ScanResult> {
  const findings: SecretFinding[] = [];

  let stdout = '';
  try {
    const res = await execFileAsync('git', ['diff', '--cached', '--name-only']);
    stdout = res.stdout;
  } catch {
    // Not a git repository or no git binary
    return { clean: true, findings: [], filesScanned: 0 };
  }

  const files = stdout.split('\n').map((f) => f.trim()).filter(Boolean);
  if (files.length === 0) {
    return { clean: true, findings: [], filesScanned: 0 };
  }

  for (const file of files) {
    // Check filename rules first
    for (const rule of BUILTIN_RULES) {
      if (rule.checkFilename && rule.checkFilename(file)) {
        findings.push({
          file,
          line: 1,
          rule: rule.name,
          preview: file,
          severity: rule.severity
        });
        break;
      }
    }

    try {
      const diffRes = await execFileAsync('git', ['diff', '--cached', '-U0', '--', file]);
      const diffLines = diffRes.stdout.split('\n');
      const addedContent = diffLines
        .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
        .map((l) => l.slice(1))
        .join('\n');

      const fileFindings = scanText(addedContent, file);
      findings.push(...fileFindings);
    } catch {
      // Deleted or unreadable file
    }
  }

  return {
    clean: findings.length === 0,
    findings,
    filesScanned: files.length
  };
}

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache']);

export async function scanDirectory(dir: string): Promise<ScanResult> {
  const findings: SecretFinding[] = [];
  let filesScanned = 0;

  async function walk(currentDir: string) {
    const entries = await readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) {
          await walk(fullPath);
        }
      } else if (entry.isFile()) {
        filesScanned++;
        const s = await stat(fullPath);
        // Skip huge binary/media files (>1MB)
        if (s.size > 1024 * 1024) continue;

        try {
          const content = await readFile(fullPath, 'utf8');
          const fileFindings = scanText(content, fullPath);
          findings.push(...fileFindings);
        } catch {
          // Binary or unreadable
        }
      }
    }
  }

  await walk(dir);

  return {
    clean: findings.length === 0,
    findings,
    filesScanned
  };
}
