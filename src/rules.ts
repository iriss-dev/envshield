// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

import type { RuleDefinition } from './types.js';

export const BUILTIN_RULES: RuleDefinition[] = [
  {
    id: 'env-file',
    name: 'Unsafe Environment File (.env)',
    severity: 'critical',
    checkFilename: (filename: string) => {
      const base = filename.split(/[/\\]/).pop() || '';
      const lower = base.toLowerCase();
      if (
        lower.endsWith('.example') ||
        lower.endsWith('.template') ||
        lower.endsWith('.sample') ||
        lower.endsWith('.dist')
      ) {
        return false;
      }
      return /^\.env(\.[a-zA-Z0-9_-]+)?$/.test(lower);
    }
  },
  {
    id: 'private-key',
    name: 'Private Encryption Key (RSA/SSH/PGP)',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)? ?PRIVATE KEY-----/
  },
  {
    id: 'discord-token',
    name: 'Discord Bot / User Token',
    severity: 'critical',
    pattern: /(?:mfa\.[a-z0-9_-]{20,}|[a-z0-9_-]{23,28}\.[a-z0-9_-]{6}\.[a-z0-9_-]{27,38})/i
  },
  {
    id: 'openai-key',
    name: 'OpenAI API Secret Key',
    severity: 'critical',
    pattern: /sk-(?!ant-)(?:proj-)?[a-zA-Z0-9_-]{32,}/
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API Secret Key',
    severity: 'critical',
    pattern: /sk-ant-[a-zA-Z0-9_-]{32,}/
  },
  {
    id: 'github-token',
    name: 'GitHub Personal Access Token',
    severity: 'critical',
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}/
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    severity: 'high',
    pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe Live Secret Key',
    severity: 'critical',
    pattern: /(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}/
  },
  {
    id: 'slack-token',
    name: 'Slack Bot / User Token',
    severity: 'high',
    pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/
  }
];
