// Marketing landing page. Expressive where the dashboard is restrained.
// The embedded SOC preview is a clearly-labelled sample (see SocPreview.jsx).

import { ArrowRight, BookLock, Radar, ShieldCheck, Terminal } from 'lucide-react'
import { GithubIcon } from '@/components/icons/GithubIcon'
import { SmoothScroll } from '@/components/motion/SmoothScroll'
import { Reveal } from '@/components/motion/Reveal'
import { SpotlightCard } from '@/components/motion/SpotlightCard'
import { SocPreview } from './SocPreview'

const GITHUB_URL = 'https://github.com/AnuragR3k/greywatch'

const FEATURES = [
  { icon: Terminal, title: 'Unified event pipeline', body: 'Journal, Suricata EVE, and HTTP-ingested logs are normalized into one queryable event stream with provenance.' },
  { icon: ShieldCheck, title: 'Rule-based detection', body: 'SSH brute-force and Suricata IDS signatures raise investigated alerts with retained evidence — never duplicated endlessly.' },
  { icon: BookLock, title: 'Triage and resolve', body: 'Review severity, rule, source, and raw evidence, then resolve alerts through the real API with confirmation.' },
  { icon: Radar, title: 'Collector health', body: 'Journal and Suricata are reported independently — enabled, disabled, stale, or unavailable — never conflated.' },
]

const INTEGRATIONS = [
  {
    name: 'systemd journal',
    detail: 'Cursor-based collection of PAM, SSH, and sudo authentication events via journalctl -o json. Incremental and restart-safe.',
    types: 'ssh_login_failed · sudo_command · pam_auth_failed',
  },
  {
    name: 'Suricata EVE JSON',
    detail: 'Byte-offset, rotation-safe ingestion of IDS alerts, DNS, HTTP, TLS, and flow records. IDS signatures raise alerts with evidence.',
    types: 'suricata_alert · suricata_dns · suricata_tls',
  },
]

const WORKFLOW = [
  { step: '01', title: 'Collect', body: 'Journal and Suricata collectors ingest telemetry into SQLite with checkpoints.' },
  { step: '02', title: 'Normalize', body: 'Records are parsed into a consistent event schema with source provenance.' },
  { step: '03', title: 'Detect', body: 'Detection rules evaluate events and raise alerts with a bounded evidence window.' },
  { step: '04', title: 'Investigate', body: 'Analysts review evidence and resolve alerts from the dashboard.' },
]

function Nav({ onEnterDashboard }) {
  return (
    <header className="gw-chrome sticky top-0 z-40 border-b border-border-card">
      <div className="mx-auto flex h-16 w-full max-w-[1360px] items-center gap-4 px-5 lg:px-10">
        <a href="#/" className="flex items-center gap-2.5">
          <svg width="24" height="24" viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <path d="M16 2.5 27 7v9.2c0 6.3-4.4 10.9-11 13.3C9.4 27.1 5 22.5 5 16.2V7L16 2.5Z" fill="#0E1512" stroke="#34d399" strokeWidth="1.6" strokeLinejoin="round" />
            <circle cx="16" cy="16" r="3" fill="#a3e635" />
          </svg>
          <span className="text-sm font-semibold tracking-tight text-text-primary">Greywatch</span>
        </a>
        <nav className="ml-6 hidden items-center gap-6 text-xs font-medium text-text-secondary md:flex">
          <a href="#features" className="hover:text-text-primary">Features</a>
          <a href="#integrations" className="hover:text-text-primary">Integrations</a>
          <a href="#architecture" className="hover:text-text-primary">Architecture</a>
        </nav>
        <div className="ml-auto flex items-center gap-2">
          <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="flex items-center gap-1.5 rounded-md border border-border-card px-3 py-1.5 text-xs font-medium text-text-secondary hover:bg-card-hover hover:text-text-primary">
            <GithubIcon size={13} /> GitHub
          </a>
          <button type="button" onClick={onEnterDashboard} className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold text-[#04140c] hover:bg-accent-strong">
            Open dashboard
          </button>
        </div>
      </div>
    </header>
  )
}

export function LandingPage({ onEnterDashboard }) {
  return (
    <SmoothScroll>
      <div className="min-h-screen bg-background text-text-primary">
        <Nav onEnterDashboard={onEnterDashboard} />

        {/* Hero */}
        <section className="gw-grid-bg relative overflow-hidden">
          <div
            className="pointer-events-none absolute inset-x-0 -top-40 mx-auto h-[640px] max-w-[1100px]"
            style={{ background: 'radial-gradient(ellipse 700px 420px at 50% 40%, rgba(52,211,153,0.15), rgba(52,211,153,0.04) 45%, transparent 72%)' }}
            aria-hidden="true"
          />
          <div className="relative mx-auto flex max-w-[1360px] flex-col items-center px-5 pb-16 pt-20 text-center lg:px-10 lg:pt-24">
            <span className="inline-flex items-center gap-2 rounded-full border border-border-card bg-card/60 px-3 py-1 font-mono text-[11px] text-text-muted">
              Open-source · Linux · FastAPI + React
            </span>
            <h1 className="mt-6 max-w-[860px] text-balance text-[clamp(38px,6vw,64px)] font-semibold leading-[1.04] tracking-tight text-white">
              See the threats hiding in your logs.
            </h1>
            <p className="mt-5 max-w-[640px] text-[17px] leading-relaxed text-text-secondary">
              Greywatch collects Linux authentication and network telemetry, applies detection rules,
              and gives you a fast, focused console to investigate and resolve alerts.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
              <button type="button" onClick={onEnterDashboard} className="inline-flex items-center gap-2 rounded-md bg-accent px-5 py-2.5 text-sm font-semibold text-[#04140c] hover:bg-accent-strong">
                Explore dashboard <ArrowRight size={15} />
              </button>
              <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-md border border-border-card px-5 py-2.5 text-sm font-medium text-text-secondary hover:bg-card-hover hover:text-text-primary">
                <GithubIcon size={15} /> View on GitHub
              </a>
            </div>

            <div className="mt-14 w-full max-w-[1160px]">
              <SocPreview />
            </div>
          </div>
        </section>

        {/* Features */}
        <section id="features" className="mx-auto max-w-[1360px] px-5 py-24 lg:px-10">
          <Reveal>
            <h2 className="max-w-[640px] text-[clamp(26px,3.2vw,38px)] font-semibold leading-tight tracking-tight text-white">
              A focused console for Linux detection and response.
            </h2>
          </Reveal>
          <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map((f, i) => (
              <Reveal key={f.title} delay={i * 0.05}>
                <SpotlightCard className="h-full p-5">
                  <f.icon size={18} className="text-accent" aria-hidden="true" />
                  <h3 className="mt-3 text-sm font-semibold text-text-primary">{f.title}</h3>
                  <p className="mt-2 text-xs leading-relaxed text-text-muted">{f.body}</p>
                </SpotlightCard>
              </Reveal>
            ))}
          </div>
        </section>

        {/* Integrations */}
        <section id="integrations" className="border-y border-border-card bg-[#0c1014]">
          <div className="mx-auto grid max-w-[1360px] grid-cols-1 gap-10 px-5 py-24 lg:grid-cols-2 lg:px-10">
            <Reveal>
              <h2 className="text-[clamp(26px,3.2vw,38px)] font-semibold leading-tight tracking-tight text-white">
                Telemetry from the host and the wire.
              </h2>
              <p className="mt-4 max-w-[520px] text-sm leading-relaxed text-text-secondary">
                Both integrations are optional and disabled by default. Greywatch records provenance so
                journal, Suricata, and ingested events are always distinguishable.
              </p>
            </Reveal>
            <div className="flex flex-col gap-4">
              {INTEGRATIONS.map((it) => (
                <Reveal key={it.name}>
                  <div className="rounded-panel border border-border-card bg-card p-5">
                    <h3 className="text-sm font-semibold text-text-primary">{it.name}</h3>
                    <p className="mt-2 text-xs leading-relaxed text-text-secondary">{it.detail}</p>
                    <p className="mt-3 font-mono text-[11px] text-text-muted">{it.types}</p>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        {/* Architecture */}
        <section id="architecture" className="mx-auto max-w-[1360px] px-5 py-24 lg:px-10">
          <Reveal>
            <h2 className="text-[clamp(26px,3.2vw,38px)] font-semibold leading-tight tracking-tight text-white">How it works.</h2>
          </Reveal>
          <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {WORKFLOW.map((w, i) => (
              <Reveal key={w.step} delay={i * 0.05}>
                <div className="rounded-panel border border-border-card bg-card p-5">
                  <span className="font-mono text-xs text-accent">{w.step}</span>
                  <h3 className="mt-2 text-sm font-semibold text-text-primary">{w.title}</h3>
                  <p className="mt-2 text-xs leading-relaxed text-text-muted">{w.body}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        {/* Footer */}
        <footer className="border-t border-border-card bg-[#0c1014]">
          <div className="mx-auto flex max-w-[1360px] flex-col items-start justify-between gap-6 px-5 py-12 sm:flex-row sm:items-center lg:px-10">
            <div>
              <div className="flex items-center gap-2.5">
                <svg width="22" height="22" viewBox="0 0 32 32" fill="none" aria-hidden="true">
                  <path d="M16 2.5 27 7v9.2c0 6.3-4.4 10.9-11 13.3C9.4 27.1 5 22.5 5 16.2V7L16 2.5Z" fill="#0E1512" stroke="#34d399" strokeWidth="1.6" strokeLinejoin="round" />
                  <circle cx="16" cy="16" r="3" fill="#a3e635" />
                </svg>
                <span className="text-sm font-semibold text-text-primary">Greywatch</span>
              </div>
              <p className="mt-2 max-w-md text-xs text-text-muted">
                Open-source SIEM for Linux security monitoring and threat investigation. Active development — not yet production-ready.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-5 text-xs text-text-secondary">
              <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="hover:text-text-primary">Repository</a>
              <a href={`${GITHUB_URL}#readme`} target="_blank" rel="noreferrer" className="hover:text-text-primary">Documentation</a>
              <a href={`${GITHUB_URL}/issues`} target="_blank" rel="noreferrer" className="hover:text-text-primary">Issues</a>
              <button type="button" onClick={onEnterDashboard} className="font-medium text-[#6ee7b7] hover:text-accent">Open dashboard</button>
            </div>
          </div>
        </footer>
      </div>
    </SmoothScroll>
  )
}
