// @ts-check
// ide.spec.js -- browser-level acceptance test for the rebuilt hosted
// PicoScript WebIDE (/ide/) and PicoWAL workspace (/ide/picowal.html).
// Starts a real picoweb process (with a fake PicoSTS authority) and drives
// it with a real Chromium browser via Playwright, verifying:
//   1. /ide/ is the ACTUAL vendored WebIDE (file sidebar, Monaco/editor
//      region, Compile & Run/Step/Reset, debug tabs with disassembly/
//      registers/watches) -- not the old rejected hand-rolled shell.
//   2. The top-level PicoWAL nav tab opens the rebuilt workspace and its
//      pack/card/schema/query controls are present and usable.
//   3. PicoSTS cookie login (Authorization Code + PKCE against a fake
//      /authorize+/token+/userinfo), then real pack/schema/card creation,
//      typed lookup rendering, a joined query, and a BSO1 save round trip.
//
// picoweb is Linux-only (see AGENTS.md); on a Windows dev box both the
// picoweb binary AND the fake PicoSTS authority (fake_picosts.py) run
// inside WSL so their mutual 127.0.0.1 traffic never has to cross the
// WSL/Windows network boundary -- only Playwright's Chromium (talking to
// picoweb's forwarded port) and picoweb's own outbound call to the fake
// STS (both loopback-local inside the SAME WSL VM) are involved. On a
// native Linux CI runner (WSL_DISTRO_NAME unset) everything just runs
// directly, no `wsl.exe` wrapping.
//
// Run from tools/tests:
//   npm install
//   npx playwright install --with-deps chromium
//   npx playwright test
const { test, expect } = require('@playwright/test');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PORT = 9491;
const STS_PORT = 9492;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const SCREENSHOT_DIR = path.join(__dirname, 'screenshots');
// In-repo scratch dir (never /tmp -- see AGENTS.md), cleaned up in afterAll.
const SCRATCH_DIR = path.join(__dirname, '.tmp');

const IS_WINDOWS = process.platform === 'win32';

/** Converts a Windows path (C:\a\b) to its WSL mount path (/mnt/c/a/b). */
function toWslPath(winPath) {
  const drive = winPath[0].toLowerCase();
  const rest = winPath.slice(2).replace(/\\/g, '/');
  return `/mnt/${drive}${rest}`;
}

/** Spawns `cmd` (already a single shell-ready string), transparently
 * wrapped with `wsl.exe -e bash -c` on Windows, or run directly via
 * `bash -c` elsewhere. */
function spawnShell(cmd) {
  if (IS_WINDOWS) return spawn('wsl.exe', ['-e', 'bash', '-c', cmd], { stdio: 'pipe' });
  return spawn('bash', ['-c', cmd], { stdio: 'pipe' });
}

function waitForHttp(url, deadlineMs) {
  const deadline = Date.now() + deadlineMs;
  return new Promise((resolve, reject) => {
    function attempt() {
      const req = http.get(url, (res) => { res.resume(); resolve(); });
      req.on('error', () => {
        if (Date.now() > deadline) reject(new Error(`timed out waiting for ${url}`));
        else setTimeout(attempt, 200);
      });
      req.setTimeout(1000, () => req.destroy());
    }
    attempt();
  });
}

/** @type {import('child_process').ChildProcess} */
let picowebProc;
/** @type {import('child_process').ChildProcess} */
let stsProc;
let picowalDirWin;
let wwwDirWin;
let bootLog = '';

test.beforeAll(async () => {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  fs.rmSync(SCRATCH_DIR, { recursive: true, force: true });
  picowalDirWin = path.join(SCRATCH_DIR, 'picowal-device');
  wwwDirWin = path.join(SCRATCH_DIR, 'www');
  fs.mkdirSync(picowalDirWin, { recursive: true });
  fs.mkdirSync(path.join(wwwDirWin, 'localhost'), { recursive: true });
  fs.writeFileSync(path.join(wwwDirWin, 'localhost', 'index.html'), 'ok\n');

  const picowalDir = IS_WINDOWS ? toWslPath(picowalDirWin) : picowalDirWin;
  const wwwDir = IS_WINDOWS ? toWslPath(wwwDirWin) : wwwDirWin;
  const repoDir = IS_WINDOWS ? toWslPath(REPO_ROOT) : REPO_ROOT;
  const issuer = `http://127.0.0.1:${STS_PORT}`;

  stsProc = spawnShell(
    `exec python3 '${IS_WINDOWS ? toWslPath(path.join(__dirname, 'fake_picosts.py')) : path.join(__dirname, 'fake_picosts.py')}' ${STS_PORT} api playwright-user`
  );
  stsProc.stdout.on('data', (d) => (bootLog += '[sts] ' + d.toString()));
  stsProc.stderr.on('data', (d) => (bootLog += '[sts] ' + d.toString()));

  const picowebCmd =
    `cd '${repoDir}' && exec ./picoweb ` +
    `--picowal-device='${picowalDir}' --picowal-format ` +
    `--picowal-static-card=1 --picowal-static-prefix=/site/ ` +
    `--picowal-code-card=2 --picowal-code-prefix=/app/ ` +
    `--ide-prefix=/ide/ ` +
    `--oidc-cookie-auth --picosts-issuer=${issuer} --picosts-audience=api ` +
    `--picosts-client-id=spa --picosts-cookie-key=playwright-test-cluster-secret ` +
    `${PORT} '${wwwDir}' 1 100 0 64`;
  picowebProc = spawnShell(picowebCmd);
  picowebProc.stdout.on('data', (d) => (bootLog += '[picoweb] ' + d.toString()));
  picowebProc.stderr.on('data', (d) => (bootLog += '[picoweb] ' + d.toString()));

  try {
    await waitForHttp(`${BASE_URL}/ide/config`, 15000);
  } catch (e) {
    throw new Error(String(e.message) + '\n--- boot log ---\n' + bootLog);
  }
});

test.afterAll(async () => {
  if (picowebProc) picowebProc.kill();
  if (stsProc) stsProc.kill();
  // Give WSL a moment to release the picowal device file before cleanup.
  await new Promise((r) => setTimeout(r, 300));
  fs.rmSync(SCRATCH_DIR, { recursive: true, force: true });
});


test.describe('WebIDE portal structure (GET /ide/)', () => {
  test('is the actual vendored WebIDE, not the old rejected shell', async ({ page }) => {
    await page.goto(`${BASE_URL}/ide/`);
    await expect(page).toHaveTitle(/PicoScript.*IDE, Guide.*Reference/);

    // Guide & Reference / WebIDE / Showcase top-level nav.
    await expect(page.locator('.tabs .tab', { hasText: 'Guide & Reference' })).toBeVisible();
    await expect(page.locator('.tabs .tab', { hasText: 'Code Editor' })).toBeVisible();
    await expect(page.locator('.tabs a.tab', { hasText: 'Showcase' })).toBeVisible();

    // Switch to the WebIDE view.
    await page.locator('.tabs .tab', { hasText: 'Code Editor' }).click();
    await expect(page.locator('#view-play')).toHaveClass(/active/);

    // File sidebar.
    await expect(page.locator('#fileSidebar')).toBeVisible();
    await expect(page.locator('#fileList')).toBeVisible();

    // Editor region (Monaco container, with textarea fallback behind it).
    await expect(page.locator('#monaco')).toBeVisible();

    // Compile & Run / Compile & Step / Step / Reset controls.
    const controls = page.locator('#view-play .controls');
    await expect(controls.getByText('Compile & Run', { exact: false })).toBeVisible();
    await expect(controls.getByText('Compile & Step', { exact: false })).toBeVisible();
    await expect(controls.getByText('Step', { exact: true })).toBeVisible();
    await expect(controls.getByText('Reset', { exact: true })).toBeVisible();

    // Debug tabs: disassembly / registers / watches.
    await expect(page.locator('#listing')).toBeAttached();
    await expect(page.locator('#regs')).toBeAttached();
    await expect(page.locator('#watches')).toBeAttached();

    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '01-webide-portal.png'), fullPage: false });
  });

  test('bridge adds deploy controls and a top-level PicoWAL tab', async ({ page }) => {
    await page.goto(`${BASE_URL}/ide/`);
    await page.locator('.tabs .tab', { hasText: 'Code Editor' }).click();
    const controls = page.locator('#view-play .controls');
    await expect(controls.getByText('Save Source')).toBeVisible();
    await expect(controls.getByText('Load Source')).toBeVisible();
    await expect(controls.getByText('Deploy Bytecode')).toBeVisible();
    await expect(controls.getByText('Publish Static')).toBeVisible();
    await expect(page.locator('#pwbridge-tab-picowal')).toBeVisible();
  });
});

test.describe('Unified portal with full PicoWAL tab', () => {
  test('opens the workspace as a full portal tab with one shell', async ({ page }) => {
    await page.goto(`${BASE_URL}/ide/`);
    await page.locator('#pwbridge-tab-picowal').click();
    await expect(page.locator('#view-picowal')).toHaveClass(/active/);
    await expect(page.locator('#view-play')).not.toHaveClass(/active/);
    await expect(page.locator('#picowalFrame')).toBeVisible();

    const frame = page.frameLocator('#picowalFrame');
    await expect(frame.locator('.pw-brand')).toContainText('PicoWAL');
    await expect(frame.locator('body')).toHaveClass(/pwx-embedded/);
    await expect(frame.locator('.pw-topbar')).toBeHidden();
    await expect(frame.locator('[data-tab="packs"]')).toBeVisible();
    await expect(frame.locator('[data-tab="cards"]')).toBeVisible();
    await expect(frame.locator('[data-tab="permissions"]')).toBeVisible();
    await expect(frame.locator('[data-tab="query"]')).toBeVisible();
    await expect(frame.locator('[data-tab="fastserial"]')).toBeVisible();
    await expect(frame.locator('#pw-schema-fields-table')).toBeVisible();

    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '02-picowal-tab.png'), fullPage: false });
  });

  test('uses one sign-in state for WebIDE and the full PicoWAL tab', async ({ page }) => {
    await page.goto(`${BASE_URL}/ide/`);
    await page.locator('#pwbridge-btn-login').click();
    await expect(page.locator('#pwbridge-principal')).toContainText('signed in as playwright-user', { timeout: 10000 });
    await page.locator('#pwbridge-tab-picowal').click();
    const frame = page.frameLocator('#picowalFrame');
    await expect(frame.locator('#pwx-principal')).toContainText('signed in as playwright-user', { timeout: 10000 });
    await expect(frame.locator('#pwx-btn-login')).toBeHidden();
    await expect(frame.locator('#pwx-btn-logout')).toBeHidden();
  });
});

test.describe('PicoWAL workspace end-to-end (real /wal/ backend)', () => {
  test('PicoSTS login, pack/schema/card creation, typed lookup, joined query, BSO1 save', async ({ page }) => {
    test.setTimeout(60000);

    // ---- 1. PicoSTS cookie login via the portal topbar widget ----
    await page.goto(`${BASE_URL}/ide/`);
    await page.locator('#pwbridge-btn-login').click();
    await expect(page.locator('#pwbridge-principal')).toContainText('signed in as playwright-user', { timeout: 10000 });
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '03-logged-in.png'), fullPage: false });

    // ---- 2. Open the PicoWAL workspace ----
    await page.locator('#pwbridge-tab-picowal').click();
    const frame = page.frameLocator('#picowalFrame');
    await expect(frame.locator('#pwx-principal')).toContainText('signed in', { timeout: 10000 });

    // ---- 3. Create a schema for a "parent" pack (id 50) ----
    await frame.locator('[data-tab="packs"]').click();
    await frame.locator('#pw-pack-id').fill('50');
    await frame.locator('#pw-field-name').fill('label');
    await frame.locator('#pw-field-type').selectOption('string');
    await frame.locator('button', { hasText: '+ field' }).click();
    await expect(frame.locator('#pw-schema-fields-table')).toContainText('label');
    await frame.locator('button', { hasText: 'Save schema' }).click();
    await expect(frame.locator('#pw-schema-msg')).toContainText('schema saved', { timeout: 10000 });

    // ---- 4. Create a card in the parent pack ----
    await frame.locator('[data-tab="cards"]').click();
    await frame.locator('#pw-card-pack').fill('50');
    await frame.locator('#pw-card-json').fill(JSON.stringify({ label: 'parent-one' }));
    await frame.locator('button', { hasText: 'Create (auto id)' }).click();
    await expect(frame.locator('#pw-card-msg')).toContainText('created', { timeout: 10000 });
    const parentRecord = await frame.locator('#pw-card-record').inputValue();
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '04-card-created.png'), fullPage: false });

    // ---- 5. Create a "child" pack (id 51) with a lookup field back to 50 ----
    await frame.locator('[data-tab="packs"]').click();
    await frame.locator('#pw-pack-id').fill('51');
    await frame.locator('#pw-field-name').fill('parent_id');
    await frame.locator('#pw-field-type').selectOption('lookup');
    await frame.locator('#pw-field-lookup-pack').fill('50');
    await frame.locator('button', { hasText: '+ field' }).click();
    await frame.locator('button', { hasText: 'Save schema' }).click();
    await expect(frame.locator('#pw-schema-msg')).toContainText('schema saved', { timeout: 10000 });

    // ---- 6. Create a card in the child pack, referencing the actual parent record id ----
    await frame.locator('[data-tab="cards"]').click();
    await frame.locator('#pw-card-pack').fill('51');
    await frame.locator('#pw-card-json').fill(JSON.stringify({ parent_id: Number(parentRecord) }));
    await frame.locator('button', { hasText: 'Create (auto id)' }).click();
    await expect(frame.locator('#pw-card-msg')).toContainText('created', { timeout: 10000 });
    const childRecord = await frame.locator('#pw-card-record').inputValue();

    // ---- 7. Typed lookup rendering: GET the child card (populates the
    // schema model), switch to the visual form, and confirm the lookup
    // field rendered a real <select>/<input> sourced from pack 50.
    await frame.locator('button[onclick="pwCardGet()"]').click();
    await expect(frame.locator('#pw-card-msg')).toContainText('loaded', { timeout: 10000 });
    await frame.locator('#pw-card-mode-btn').click();
    await expect(frame.locator('#pw-card-visual [data-field-name="parent_id"]')).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '05-typed-lookup.png'), fullPage: false });

    // ---- 8. Joined query across both packs (child pack 51, whose schema
    // declares the join back to 50, must be F's primary/first pack for the
    // query engine's schema_join_field auto-detection to merge rows) ----
    await frame.locator('[data-tab="query"]').click();
    await frame.locator('#pw-query-text').fill(`S:parent_id,50.label\nF:51,50\nW:parent_id|==|${parentRecord}`);
    await frame.locator('button', { hasText: 'Run query' }).click();
    await expect(frame.locator('#pw-query-status')).toContainText('count=', { timeout: 10000 });
    await expect(frame.locator('#pw-query-raw')).toContainText('parent-one', { timeout: 10000 });
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '06-joined-query.png'), fullPage: false });

    // ---- 9. Fast Serial (BSO1): derive schema from pack 50 and save it ----
    await frame.locator('[data-tab="cards"]').click();
    await frame.locator('#pw-card-pack').fill('50');
    await frame.locator('#pw-card-record').fill(parentRecord);
    await frame.locator('button[onclick="pwCardGet()"]').click();
    await expect(frame.locator('#pw-card-msg')).toContainText('loaded', { timeout: 10000 });

    await frame.locator('[data-tab="fastserial"]').click();
    await frame.locator('#fs-signing-key').fill('cGxheXdyaWdodC10ZXN0LWtleQ==');
    await frame.locator('button', { hasText: 'Set key' }).click();
    await frame.locator('#fs-schema-pack').fill('50');
    await frame.locator('button', { hasText: 'Derive BSO1 schema from rich schema' }).click();
    await expect(frame.locator('#fs-schema-preview')).toContainText('label', { timeout: 10000 });
    await frame.locator('button', { hasText: 'Serialize current card JSON' }).click();
    await expect(frame.locator('#fs-msg')).toContainText('serialized', { timeout: 10000 });
    await frame.locator('#fs-pack').fill('9');
    await frame.locator('#fs-record').fill('1');
    await frame.locator('button', { hasText: 'Save BSO1 (PUT)' }).click();
    await expect(frame.locator('#fs-msg')).toContainText('saved BSO1 bytes', { timeout: 10000 });
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '07-bso1-save.png'), fullPage: false });
  });
});
