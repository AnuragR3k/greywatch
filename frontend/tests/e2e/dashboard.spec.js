// Dashboard end-to-end smoke tests.
//
// Covers: dashboard loads, real telemetry panels render, and no uncaught page
// exceptions occur. Backend + frontend are started by scripts/e2e_servers.sh
// (isolated temp DB, never data/greywatch.db).
//
// Console errors are captured and printed for diagnostics but do not fail the
// suite on their own (dev-mode / third-party noise is common). Uncaught page
// exceptions (pageerror) are treated as failures.

import { test, expect } from '@playwright/test'

test.describe('Dashboard', () => {
  let pageErrors
  let consoleErrors

  test.beforeEach(async ({ page }) => {
    pageErrors = []
    consoleErrors = []
    page.on('pageerror', (err) => pageErrors.push(err))
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text())
    })
  })

  test.afterEach(async () => {
    if (consoleErrors.length) {
      // eslint-disable-next-line no-console
      console.log(`[e2e] captured ${consoleErrors.length} console error(s):`, consoleErrors)
    }
  })

  test('loads the dashboard and renders real telemetry panels', async ({
    page,
  }) => {
    await page.goto('/#/dashboard')
    await expect(page.locator('h1')).toContainText('Overview')

    // KPI card shells render (values may be "—" when empty).
    await expect(page.locator('text=Total events')).toBeVisible()
    await expect(page.locator('text=Open alerts')).toBeVisible()
    await expect(page.locator('text=High severity')).toBeVisible()
    await expect(page.locator('text=Active detections')).toBeVisible()

    // System health panel is present.
    await expect(page.locator('text=System health')).toBeVisible()
  })

  test('records no uncaught page exceptions on the dashboard', async ({
    page,
  }) => {
    await page.goto('/#/dashboard')
    await page.waitForTimeout(1200) // let initial polls settle
    expect(pageErrors).toEqual([])
  })
})
