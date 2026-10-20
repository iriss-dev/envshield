// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

export function isHighEntropyToken(candidate: string): boolean {
  const trimmed = candidate.trim();
  // Tokens are typically 24-120 chars without whitespace
  if (trimmed.length < 24 || trimmed.length > 120) return false;
  if (/[\s\r\n\t]/.test(trimmed)) return false;

  const entropy = calculateShannonEntropy(trimmed);
  const isHexOnly = /^[0-9a-fA-F]+$/.test(trimmed);
  return isHexOnly ? entropy >= 3.2 : entropy >= 4.3;
}
