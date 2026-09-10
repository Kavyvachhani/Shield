/**
 * Fail the build when the frontend and backend disagree about what commands exist.
 *
 * Two directions, both silent:
 *
 * 1. A name in `invoke('...')` that no `generate_handler!` entry matches
 *    compiles, typechecks, and lints clean. It fails only when a user clicks
 *    the thing, with "command not found" in a console nobody has open.
 * 2. A command registered in Rust that no screen ever calls is a feature that
 *    was built, tested, and cannot be reached. This repository has shipped that
 *    twice — see "fix: two features the backend had and the UI could not reach"
 *    — and an audit found eleven more, including the only way to see or revoke
 *    a credential held in the OS keychain.
 *
 * The second is reported as a warning rather than a failure: a single-item
 * getter that the UI does not happen to need is untidy, not broken. What
 * matters is that it is visible, so the decision to leave it is deliberate.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const MAIN = join(ROOT, 'src-tauri/src/main.rs');
const BINDINGS = join(ROOT, 'src/lib/tauri.ts');

const main = readFileSync(MAIN, 'utf8');
const handler = main.slice(main.indexOf('generate_handler!['));
const registered = new Set(
  [...handler.slice(0, handler.indexOf(']')).matchAll(/commands::[a-z_]+::([a-z_0-9]+)/g)].map((m) => m[1]),
);

const bindings = readFileSync(BINDINGS, 'utf8');
const invoked = new Set(
  [...bindings.matchAll(/invoke(?:<[^>]*>)?\(\s*'([a-z_0-9]+)'/g)].map((m) => m[1]),
);

/** Every .tsx under src/, which is where a binding has to be used from. */
function screens(dir) {
  return readdirSync(dir).flatMap((e) => {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) return screens(full);
    return e.endsWith('.tsx') ? [readFileSync(full, 'utf8')] : [];
  });
}
const uiSource = screens(join(ROOT, 'src')).join('\n');

const errors = [];
for (const name of invoked) {
  if (!registered.has(name)) errors.push(name);
}

// An invoke() outside the wrapper escapes the check above entirely.
const strays = [];
for (const dir of ['src/screens', 'src/components']) {
  for (const text of screens(join(ROOT, dir))) {
    if (/\binvoke\s*\(/.test(text)) strays.push(dir);
  }
}

if (errors.length) {
  console.error(
    `\n${errors.length} command(s) the frontend calls that the backend does not register.\n` +
      `Each fails at runtime with "command not found", never at build time:\n\n  ` +
      errors.join('\n  ') +
      `\n\nAdd them to generate_handler! in src-tauri/src/main.rs, or correct the name.\n`,
  );
  process.exit(1);
}

if (strays.length) {
  console.error(
    `\ninvoke() is called directly from ${[...new Set(strays)].join(', ')}.\n` +
      `Route every backend call through src/lib/tauri.ts so it is typed and checked here.\n`,
  );
  process.exit(1);
}

// Warning, not failure — see the note at the top.
const unreachable = [...registered].filter((name) => {
  const camel = name.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
  // `api` and the method are often split across lines by the formatter, so a
  // literal "api.method" substring misses real call sites — it reported
  // getFindingDetail as unreachable while the findings workbench was calling it.
  return !new RegExp(String.raw`\bapi\s*\.\s*${camel}\b`).test(uiSource);
});

/**
 * Commands deliberately left uncalled, with the reason.
 *
 * Each is redundant rather than missing: the interface already has the data by
 * another route, so calling these would be a second source of truth for
 * something held in state. Listed by name so the set stays a decision rather
 * than a backlog — anything not named here is reported as a genuine gap.
 */
const DELIBERATELY_UNCALLED = {
  get_project: 'projects come from list_projects and are held in state',
  get_target: 'targets come from list_targets and are held in state',
  get_finding: 'the workbench uses the richer get_finding_detail',
  verify_authorization: 'the record is returned by create_scope_and_roe and kept in state',
  get_authorization_record: 'same — the signed record is already in state',
  record_exception: 'exceptions are recorded through triage_finding, which writes both',
  get_checklist_catalog: 'the coverage screen uses get_coverage, which embeds the catalog',
};

console.log(`command wiring ok — ${invoked.size} binding(s), all registered`);

const unexplained = unreachable.filter((n) => !(n in DELIBERATELY_UNCALLED));
const explained = unreachable.filter((n) => n in DELIBERATELY_UNCALLED);
if (explained.length) {
  console.log(`  ${explained.length} command(s) intentionally uncalled (redundant with state)`);
}
if (unexplained.length) {
  console.error(
    `\n${unexplained.length} registered command(s) that no screen calls and that are not\n` +
      `recorded as deliberate — a feature the backend has and the interface cannot reach:\n\n  ` +
      unexplained.join('\n  ') +
      `\n\nEither give it a path in the UI, or add it to DELIBERATELY_UNCALLED in this\nfile with the reason it is redundant.\n`,
  );
  process.exit(1);
}

// A name listed as deliberate that is now called, or no longer exists, is stale.
const stale = Object.keys(DELIBERATELY_UNCALLED).filter((n) => !unreachable.includes(n));
if (stale.length) {
  console.error(
    `\n${stale.length} entr(y/ies) in DELIBERATELY_UNCALLED are stale — now called, or gone:\n  ` +
      stale.join('\n  ') + '\nRemove them.\n',
  );
  process.exit(1);
}
