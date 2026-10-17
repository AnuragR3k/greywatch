# Greywatch frontend

React + Vite frontend for the Greywatch SIEM. Two surfaces share one design
system: the marketing landing page (`/`) and the SOC dashboard
(`/#/dashboard`).

## Run

```bash
npm install
npm run dev      # Vite dev server; proxies /api and /health to 127.0.0.1:8000
```

Start the backend first (`uvicorn backend.app.main:app --host 127.0.0.1 --port 8000`)
so the dashboard can load real telemetry.

## Checks

```bash
npm run lint
npm run build
npm run check:contrast
```

## Structure

```
src/
  app/          # router + App/Dashboard containers + route/nav config
  components/
    layout/     # Shell, Sidebar, TopBar
    ui/         # Button, Badge, Panel, Dialog, Drawer, Field, SelectMenu, …
    motion/     # GSAP Reveal, CountUp, SpotlightCard, Lenis SmoothScroll
    icons/      # brand marks not provided by lucide
  features/
    overview/   # SystemHealth, KpiGrid, ActivityChart, RecentAlerts/Events, CollectorHealth
    alerts/     # list + investigation drawer (evidence, resolve)
    events/     # explorer with expandable rows
    collectors/ # journal + Suricata pages
    settings/   # live config + trust-boundary documentation
    landing/    # landing page + labelled SOC sample preview
  hooks/        # useResource, useTelemetry, usePolling, useMediaQuery
  lib/
    api/        # config, client, endpoints, errors
    format/     # datetime, network, values, telemetry presentation helpers
    motion/     # GSAP setup + reduced-motion helpers
  styles/       # design tokens + base/utilities
```

## Data layer

All HTTP access goes through `lib/api/client.js`:

- configurable base URL (Vite proxy by default)
- request timeouts + abort-signal cancellation
- bounded retries with backoff, `Retry-After` handling
- JSON parse guards and structured `ApiError` / `NetworkError`
- no secrets in the bundle

`hooks/useResource.js` prevents the historic request-loop bugs: stable callback
identities, cross-component de-duplication, coalesced overlapping polls, stale
last-known data retained on error, and cancellation of obsolete requests. The
dashboard polls on a visibility-aware interval and a single `gw-refresh` event
refreshes every mounted section.
