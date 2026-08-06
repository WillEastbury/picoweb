// @ts-check
const { defineConfig } = require('@playwright/test');

/* playwright.config.js -- config for the browser-level /ide/ acceptance
 * tests. The picoweb binary is started/stopped by global setup in
 * ide.spec.js itself (not webServer here) because it needs
 * --picowal-device pointed at a fresh temp dir per run and a
 * fixed-but-free port; see ide.spec.js's test.beforeAll/afterAll. */
module.exports = defineConfig({
  testDir: '.',
  timeout: 30000,
  expect: { timeout: 5000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.PICOWEB_BASE_URL || 'http://127.0.0.1:9491',
    screenshot: 'only-on-failure',
  },
});
