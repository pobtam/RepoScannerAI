/**
 * Build the layout probe and measure it in headless Chrome.
 *
 * No new dependency: esbuild already ships inside Vite, and Chrome is driven
 * with --dump-dom rather than a driver library. The probe is bundled to a
 * single self-contained HTML file so it loads over file:// with no server.
 *
 * Prints the measurements as JSON on stdout. Exits 2 if no browser is found,
 * which the test reports as a LOUD skip: a geometry check that quietly did
 * not run is worse than one that is absent, because it reads as a pass.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Resolved against this file rather than the working directory, so the probe
// behaves the same whether it is run by hand or from a test runner.
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const CANDIDATES = [
  process.env.CHROME_PATH,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].filter(Boolean);

export function findBrowser() {
  return CANDIDATES.find((p) => existsSync(p)) ?? null;
}

/**
 * probeLayout bundles one probe entry and measures it.
 *
 * The entry is a parameter because OQ-UI-04 asked for this to be pointed at
 * the other views: the findings table was the only one with a geometry guard,
 * and a defect of the same class could sit in any of them.
 */
export function probeLayout(entry = 'src/features/explorer/layout-probe.tsx') {
  const browser = findBrowser();
  if (!browser) return { skipped: 'no Chrome or Chromium found' };

  const dir = mkdtempSync(join(tmpdir(), 'vf-layout-'));
  const bundle = join(dir, 'probe.js');

  execFileSync(
    join(ROOT, 'node_modules/.bin/esbuild'),
    [
      join(ROOT, entry),
      '--bundle',
      '--format=iife',
      '--jsx=automatic',
      '--loader:.json=json',
      '--log-level=error',
      `--outfile=${bundle}`,
    ],
    { stdio: ['ignore', 'ignore', 'inherit'], cwd: ROOT },
  );

  // esbuild emits the imported stylesheet next to the bundle.
  const cssPath = bundle.replace(/\.js$/, '.css');
  const css = existsSync(cssPath) ? readFileSync(cssPath, 'utf8') : '';

  const html = join(dir, 'probe.html');
  writeFileSync(
    html,
    `<!doctype html><html><head><meta charset="utf-8"><style>${css}</style></head>` +
      `<body><div id="root"></div><pre id="layout-result"></pre>` +
      `<script>${readFileSync(bundle, 'utf8')}</script></body></html>`,
  );

  const dom = execFileSync(
    browser,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--window-size=1600,1200',
      '--force-device-scale-factor=1',
      '--virtual-time-budget=4000',
      '--dump-dom',
      `file://${html}`,
    ],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 32 * 1024 * 1024 },
  );

  const match = dom.match(/<pre id="layout-result">([\s\S]*?)<\/pre>/);
  if (!match || !match[1].trim()) {
    throw new Error(
      'the probe produced no measurements. The page did not render, which is a ' +
        'failure of the probe rather than a verdict on the layout — it must never ' +
        'be reported as a pass.',
    );
  }
  return JSON.parse(
    match[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>'),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(probeLayout(process.argv[2]), null, 2));
}
