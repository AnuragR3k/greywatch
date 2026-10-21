// Playwright end-to-end configuration for Greywatch.
// Launches the backend (isolated temp DB) + frontend dev server via
// scripts/e2e_servers.sh, then runs smoke tests against http://localhost:5173.

import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: 'list',

  // Start backend + frontend dev server once per worker file is too heavy; we
  // start them once globally via a single webServer and reuse across tests.
  webServer: {
    command: '../scripts/e2e_servers.sh',
    port: 5173,
    baseURL: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },

  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: devices['Desktop Chrome'],
    },
  ],
})
