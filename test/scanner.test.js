// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

import test from 'node:test';
import assert from 'node:assert/strict';
import { scanText, calculateShannonEntropy, isHighEntropyToken } from '../dist/index.js';

test('scanner - detects unsafe .env filenames while permitting examples', () => {
  const f1 = scanText('', '.env');
  assert.equal(f1.length, 1);
  assert.equal(f1[0].rule, 'Unsafe Environment File (.env)');

  const f2 = scanText('', '.env.production');
  assert.equal(f2.length, 1);

  const f3 = scanText('', '.env.example');
  assert.equal(f3.length, 0);

  const f4 = scanText('', '.env.template');
  assert.equal(f4.length, 0);
});

test('scanner - detects Discord bot tokens', () => {
  // Built with concatenation so GitHub push protection doesn't flag test mocks
  const fakeToken = ['OTk5MTExMjIyMzMzNDQ0NTU1', 'GXxYyZ', '1234567890abcdef1234567890abcdef123456'].join('.');
  const sample = `const TOKEN = "${fakeToken}";`;
  const findings = scanText(sample, 'bot.js');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, 'Discord Bot / User Token');
  assert.equal(findings[0].line, 1);
  assert.ok(findings[0].preview.includes('...')); // masked
});

test('scanner - detects OpenAI and Anthropic API keys', () => {
  const fakeOpenAI = ['sk', 'proj', 'abcde123456789012345678901234567890'].join('-');
  const fakeClaude = ['sk', 'ant', '1234567890abcdef1234567890abcdef12'].join('-');
  const sample = `
    const openai = "${fakeOpenAI}";
    const claude = "${fakeClaude}";
  `;
  const findings = scanText(sample, 'config.ts');
  assert.equal(findings.length, 2);
  assert.equal(findings[0].rule, 'OpenAI API Secret Key');
  assert.equal(findings[1].rule, 'Anthropic API Secret Key');
});

test('scanner - detects AWS access keys and Stripe secret keys', () => {
  const fakeAws = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
  const fakeStripe = ['sk', 'live', '51A2B3C4D5E6F7G8H9I0J1K2L3M'].join('_');
  const sample = `
    const aws = "${fakeAws}";
    const stripe = "${fakeStripe}";
  `;
  const findings = scanText(sample, 'credentials.js');
  assert.equal(findings.length, 2);
  assert.equal(findings[0].rule, 'AWS Access Key ID');
  assert.equal(findings[1].rule, 'Stripe Live Secret Key');
});

test('scanner - detects private RSA / SSH key blocks', () => {
  const sample = `
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0...
    -----END RSA PRIVATE KEY-----
  `;
  const findings = scanText(sample, 'id_rsa');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, 'Private Encryption Key (RSA/SSH/PGP)');
});

test('entropy - flags high-entropy credential assignments', () => {
  const lowEntropy = calculateShannonEntropy('aaaaaaaaaaaaaaa');
  const highEntropy = calculateShannonEntropy('7f8a9b2c3d4e5f6a1b2c3d4e5f6a');

  assert.ok(highEntropy > lowEntropy);
  assert.equal(isHighEntropyToken('aaaaaaaaaaaaaaaaaaaaaaaaaa'), false);
  assert.equal(isHighEntropyToken('9f7a8b3c2d1e0f4a5b6c7d8e9f0a'), true);

  const sample = `
    const API_SECRET = "9f7a8b3c2d1e0f4a5b6c7d8e9f0a";
  `;
  const findings = scanText(sample, 'api.js');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, 'High Entropy Credential Assignment');
});
