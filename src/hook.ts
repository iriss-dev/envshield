// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Iris (@iriss-dev) <iriss.smith08@proton.me>

import { existsSync } from 'node:fs';
import { chmod, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const HOOK_SCRIPT = `#!/usr/bin/env sh
# envshield pre-commit hook
npx envshield check || exit 1
`;

export async function installHook(cwd: string = process.cwd()): Promise<{ ok: boolean; path?: string; message: string }> {
  const gitDir = join(cwd, '.git');
  if (!existsSync(gitDir)) {
    return { ok: false, message: 'No .git directory found. Run inside a git repository root.' };
  }

  const hooksDir = join(gitDir, 'hooks');
  const hookFile = join(hooksDir, 'pre-commit');

  try {
    await writeFile(hookFile, HOOK_SCRIPT, { mode: 0o755 });
    await chmod(hookFile, 0o755).catch(() => {});
    return { ok: true, path: hookFile, message: 'Pre-commit hook installed successfully.' };
  } catch (err) {
    return { ok: false, message: (err as Error).message };
  }
}

export async function uninstallHook(cwd: string = process.cwd()): Promise<{ ok: boolean; message: string }> {
  const hookFile = join(cwd, '.git', 'hooks', 'pre-commit');
  if (!existsSync(hookFile)) {
    return { ok: true, message: 'No envshield pre-commit hook found.' };
  }

  try {
    await unlink(hookFile);
    return { ok: true, message: 'Pre-commit hook removed successfully.' };
  } catch (err) {
    return { ok: false, message: (err as Error).message };
  }
}
