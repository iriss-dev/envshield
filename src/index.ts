// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

export { scanText, scanStagedFiles, scanDirectory } from './scanner.js';
export { installHook, uninstallHook } from './hook.js';
export { calculateShannonEntropy, isHighEntropyToken } from './entropy.js';
export { BUILTIN_RULES } from './rules.js';
export type { RuleDefinition, ScanResult, SecretFinding, Severity } from './types.js';
