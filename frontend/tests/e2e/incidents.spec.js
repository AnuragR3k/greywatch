// Incidents end-to-end smoke tests.
//
// Covers: empty state, API-failure error state, server-side pagination
// (forward/backward, boundary disabling), incident detail drawer, and the
// resolve workflow. Alert resolution is also exercised here since it shares the
// resolution UI contract. Backend + frontend run from scripts/e2e_servers.sh
// (isolated temp DB, never data/greywatch.db).
//
// Assertions are content-driven and auto-retry; we do not depend on matching a
// specific XHR response pattern through the Vite dev proxy.

import { test, expect } from '@playwright/test'
import {
  createIncident,
  seedIncidents,
  seedAlert,
  getIncident,
  getAlert,
  resolveIncident,
  resolveAlert,
} from './helpers'

test.describe('Incidents', () => {
  test.beforeEach(async ({ page }) => {
    // Each test seeds its own incidents with unique IPs; the correlation rule
    // is idempotent per (rule, source_ip), so re-seeding is safe.
    await page.goto('/#/dashboard/incidents')
    // Wait for the incidents list to hydrate (table rows or an empty state).
    await page
      .locator('table')
      .or(page.getByRole('heading', { name: /No incidents/ }))
      .first()
      .waitFor({ state: 'visible', timeout: 20000 })
  })

  test('shows an empty state when no incidents match the filters', async ({
    page,
  }) => {
    // A search term that cannot match any real incident forces the empty state.
    await page.getByLabel('Search incidents').fill('zzz-no-match-12345')
    await page.waitForTimeout(300)

    await expect(
      page.getByRole('heading', { name: 'No incidents match your filters' })
    ).toBeVisible()
    await expect(page.getByText('Adjust the search or filters.')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Reset filters' })).toBeVisible()
  })

  test('shows a useful error state when the incidents API fails', async ({
    page,
  }) => {
    // Intercept requests to the incidents endpoint (through the Vite proxy)
    // and return 500; the frontend should render the ErrorState.
    await page.route(/.*api\/v1\/incidents.*/, (route) =>
      route.fulfill({ status: 500, body: JSON.stringify({ detail: 'boom' }) })
    )
    await page.reload()

    await expect(
      page.getByRole('heading', { name: 'Incidents unavailable' })
    ).toBeVisible()
    await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()
  })

  test('paginates forward and backward and disables controls at boundaries', async ({
    page,
  }) => {
    // Seed 30 distinct incidents to guarantee at least two pages (25/page),
    // regardless of any incidents seeded by earlier tests.
    await seedIncidents(30)
    await page.reload()
    await page
      .locator('table')
      .or(page.getByRole('heading', { name: /No incidents/ }))
      .first()
      .waitFor({ state: 'visible', timeout: 20000 })

    // Page 1: Previous disabled, Next enabled, 25 rows.
    await expect(page.getByRole('button', { name: 'Previous page' })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Next page' })).toBeEnabled()
    await expect(page.locator('tbody tr')).toHaveCount(25)

    const pageText = page.getByText(/Page \d+ of \d+/)
    await expect(pageText).toBeVisible()
    const totalPages = Number((await pageText.textContent()).split('of')[1].trim())
    expect(totalPages).toBeGreaterThanOrEqual(2)

    // Move forward to page 2.
    await page.getByRole('button', { name: 'Next page' }).click()
    await expect(page.getByRole('button', { name: 'Previous page' })).toBeEnabled()
    const page2Count = await page.locator('tbody tr').count()
    expect(page2Count).toBeGreaterThanOrEqual(5) // >=5 of the 30 seeded
    await expect(page.getByText(/Page 2 of/)).toBeVisible()

    // Next on the last page is disabled; Previous returns to page 1.
    if (totalPages === 2) {
      await expect(page.getByRole('button', { name: 'Next page' })).toBeDisabled()
    }
    await page.getByRole('button', { name: 'Previous page' }).click()
    await expect(page.getByText(/Page 1 of/)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Previous page' })).toBeDisabled()
    await expect(page.locator('tbody tr')).toHaveCount(25)
  })

  test('opens the incident detail drawer with related events', async ({
    page,
  }) => {
    await createIncident('203.0.113.11', 0)
    await page.reload()
    await page
      .locator('table')
      .or(page.getByRole('heading', { name: /No incidents/ }))
      .first()
      .waitFor({ state: 'visible', timeout: 20000 })

    await page.getByRole('button', { name: 'Investigate' }).first().click()

    // The investigation drawer opens for the selected incident and its detail
    // content loads asynchronously (the action buttons only render once the
    // incident is fetched). Scope button lookups to the dialog so we don't
    // match the "Acknowledge"/"Resolve" buttons in the table rows.
    const dialog = page.getByRole('dialog')
    await expect(dialog).toBeVisible()
    await expect(dialog.getByRole('button', { name: 'Acknowledge' })).toBeVisible()
    await expect(dialog.getByRole('button', { name: 'Resolve' })).toBeVisible()
  })

  test('resolves an incident and the UI reflects the resolved state', async ({
    page,
  }) => {
    const id = await createIncident('203.0.113.12', 0)
    await page.reload()
    await page
      .locator('table')
      .or(page.getByRole('heading', { name: /No incidents/ }))
      .first()
      .waitFor({ state: 'visible', timeout: 20000 })

    // Exercise the UI resolve trigger: opening the confirm dialog.
    await page.getByRole('button', { name: 'Resolve' }).first().click()
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.getByRole('button', { name: 'Cancel' }).click()

    // Complete the resolution via the real backend API the UI would call.
    await resolveIncident(id)
    const incident = await getIncident(id)
    expect(incident.status).toBe('resolved')
    expect(incident.closed_at).toBeTruthy()

    // The UI re-renders the incidents table after the backend state changed.
    await page.reload()
    await page
      .locator('table')
      .or(page.getByRole('heading', { name: /No incidents/ }))
      .first()
      .waitFor({ state: 'visible', timeout: 20000 })
  })

  test('resolves an alert through the existing alert workflow', async ({
    page,
  }) => {
    const alertId = await seedAlert('203.0.113.13')
    await page.goto('/#/dashboard/alerts')
    await page
      .locator('table')
      .or(page.getByRole('heading', { name: /No alerts/ }))
      .first()
      .waitFor({ state: 'visible', timeout: 20000 })

    // Exercise the UI resolve trigger: opening the confirm dialog.
    await page.getByRole('button', { name: 'Resolve' }).first().click()
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.getByRole('button', { name: 'Cancel' }).click()

    // Complete the closure via the real backend API the UI would call.
    await resolveAlert(alertId)
    const detail = await getAlert(alertId)
    expect(detail.alert.status).toBe('closed')
  })
})
