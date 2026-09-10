/**
 * Fail the build when a component references a CSS custom property that the
 * design system does not define.
 *
 * This is not a style preference. `color: var(--cyan)` where `--cyan` is
 * undefined and no fallback is given is invalid at computed-value time: the
 * declaration is dropped and the element inherits its colour instead. Nothing
 * warns — not the type checker, not the linter, not the browser console. The
 * page renders, and a severity that should be red is simply the colour of the
 * text around it.
 *
 * That is exactly what happened here: six legacy token names survived the move
 * to the design system and were referenced 63 times across four screens, so the
 * accent, success and danger colours silently did not apply on any of them.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const SRC = new URL('../src', import.meta.url).pathname;
const CSS = join(SRC, 'styles/design-system.css');

const defined = new Set(
  [...readFileSync(CSS, 'utf8').matchAll(/(?:^|[;{\s])(--[a-z0-9-]+)\s*:/gim)].map((m) => m[1]),
);

/** Every var() reference, minus the ones that supply their own fallback. */
function referencesIn(text) {
  return [...text.matchAll(/var\(\s*(--[a-z0-9-]+)\s*\)/gi)].map((m) => m[1]);
}

function walk(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return walk(full);
    return /\.(tsx?|css)$/.test(entry) ? [full] : [];
  });
}

const problems = [];
const literals = [];

/** A colour written directly into a component rather than taken from the palette. */
const COLOUR_LITERAL = /#[0-9a-fA-F]{3,8}\b|rgba?\(\s*\d/g;

for (const file of walk(SRC)) {
  const text = readFileSync(file, 'utf8');
  const lines = text.split('\n');

  for (const name of new Set(referencesIn(text))) {
    if (!defined.has(name)) {
      const line = lines.findIndex((l) => l.includes(`var(${name})`)) + 1;
      problems.push(`${relative(SRC, file)}:${line}  ${name}`);
    }
  }

  // Only components. The stylesheet is where literal colours belong — it is the
  // one place that defines them per theme.
  if (!/\.tsx?$/.test(file)) continue;
  lines.forEach((l, i) => {
    for (const hit of l.match(COLOUR_LITERAL) ?? []) {
      literals.push(`${relative(SRC, file)}:${i + 1}  ${hit}…`);
    }
  });
}

if (literals.length) {
  console.error(
    `\n${literals.length} hardcoded colour(s) in components.\n` +
      `A literal cannot follow the theme: it stays as written when the palette\n` +
      `switches, which is how the light theme ended up with white-on-dark borders.\n\n  ` +
      literals.join('\n  ') +
      `\n\nUse the token that owns the concept — --accent/--accent-soft/--accent-border,\n` +
      `--success/--warning/--danger and their -bg/-border pairs, the severity scale,\n` +
      `or --text-*/--bg-*. Add a token to styles/design-system.css if none fits.\n`,
  );
  process.exit(1);
}

if (problems.length) {
  console.error(
    `\n${problems.length} reference(s) to CSS variables the design system does not define.\n` +
      `Each one silently renders as an inherited colour rather than the intended one:\n\n  ` +
      problems.join('\n  ') +
      `\n\nEither define the token in styles/design-system.css or use the one that owns\n` +
      `that concept: --accent, --success, --warning, --danger, --critical/--high/\n` +
      `--medium/--low/--info, --text-primary/--text-secondary/--text-muted.\n`,
  );
  process.exit(1);
}
console.log(`design tokens ok — every var() resolves (${defined.size} defined)`);
