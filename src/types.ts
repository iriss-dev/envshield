// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

export type Severity = 'critical' | 'high' | 'medium';

export interface SecretFinding {
  file: string;
  line: number;
  rule: string;
  preview: string;
  severity: Severity;
}

export interface ScanResult {
  clean: boolean;
  findings: SecretFinding[];
  filesScanned: number;
}

export interface RuleDefinition {
  id: string;
  name: string;
  severity: Severity;
  pattern?: RegExp;
  checkFilename?: (filename: string) => boolean;
}
