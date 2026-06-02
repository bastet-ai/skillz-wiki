const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 120_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: 'http://127.0.0.1:4175',
    browserName: 'chromium'
  },
  webServer: {
    command: 'python3 -m venv /tmp/skillz-wiki-venv && /tmp/skillz-wiki-venv/bin/python -m pip install -q -r requirements.txt && /tmp/skillz-wiki-venv/bin/mkdocs build --strict && python3 -m http.server 4175 -d site',
    url: 'http://127.0.0.1:4175',
    reuseExistingServer: !process.env.CI,
    timeout: 240_000
  }
});
