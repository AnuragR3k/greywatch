// Marketing landing page. Expressive where the dashboard is restrained.
// The embedded SOC preview is a clearly-labelled sample (see SocPreview.jsx).

import { useEffect, useState } from 'react'
import { ArrowRight, BookLock, Radar, ShieldCheck, Terminal } from 'lucide-react'
import { GithubIcon } from '@/components/icons/GithubIcon'
import { GreywatchMark } from '@/components/icons/GreywatchMark'
import PillNav from '@/components/navigation/PillNav'
import { SmoothScroll } from '@/components/motion/SmoothScroll'
import { AnimatedContent } from '@/components/motion/AnimatedContent'
import { SpotlightCard } from '@/components/motion/SpotlightCard'
import GradientASCII from '@/components/motion/GradientASCII'
import { SocPreview } from './SocPreview'

const GITHUB_URL = 'https://github.com/AnuragR3k/greywatch'

// In-page sections. Kept as real anchors (no dead links); the active item is
// driven by the scroll-spy in <Nav>.
const LANDING_SECTIONS = ['top', 'features', 'integrations', 'architecture']
const LANDING_NAV = [
  { label: 'Overview', href: '#top' },
  { label: 'Features', href: '#features' },
  { label: 'Integrations', href: '#integrations' },
  { label: 'Architecture', href: '#architecture' },
]

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
  const [scrolled, setScrolled] = useState(false)
  const [activeHref, setActiveHref] = useState('#top')

  // Single passive listener drives both the frosted-on-scroll surface and the
  // section scroll-spy that highlights the active pill item.
  useEffect(() => {
    const onScroll = () => {
      setScrolled(window.scrollY > 8)
      let current = LANDING_SECTIONS[0]
      for (const id of LANDING_SECTIONS) {
        const el = document.getElementById(id)
        if (el && el.getBoundingClientRect().top <= 96) current = id
      }
      setActiveHref(`#${current}`)
    }
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
    }
  }, [])

  return (
    <header
      className={`fixed inset-x-0 top-0 z-40 border-b transition-[background-color,backdrop-filter,border-color] duration-300 ${
        scrolled ? 'border-border-card bg-[#0a0d10]/80 backdrop-blur-md' : 'border-transparent bg-transparent'
      }`}
    >
      <div className="mx-auto flex h-16 w-full max-w-[1360px] items-center gap-3 px-5 lg:px-10">
        <div className="min-w-0 flex-1">
          <PillNav
            logo={<GreywatchMark size={22} />}
            logoAlt="Greywatch home"
            logoHref="#top"
            items={LANDING_NAV}
            activeHref={activeHref}
            onItemClick={(item) => setActiveHref(item.href)}
            theme="dark"
            layout="split"
            surface="glass"
            size="md"
            itemStyle="pill"
            hoverEffect="fill"
            indicator="dot"
            barColor="rgba(17, 22, 27, 0.72)"
            highlightColor="#34d399"
            bounce={0.3}
            stretch={0.5}
            collapse="auto"
            intro
            ariaLabel="Sections"
          />
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className="hidden items-center gap-1.5 rounded-md border border-border-card px-3 py-1.5 text-xs font-medium text-text-secondary hover:bg-card-hover hover:text-text-primary sm:flex"
          >
            <GithubIcon size={13} /> GitHub
          </a>
          <button
            type="button"
            onClick={onEnterDashboard}
            className="rounded-md bg-accent px-3.5 py-1.5 text-xs font-semibold whitespace-nowrap text-[#04140c] hover:bg-accent-strong"
          >
            Launch dashboard
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
        <section id="top" className="gw-grid-bg relative overflow-hidden">
          <div className="pointer-events-none absolute inset-0" aria-hidden="true">
            <GradientASCII
              colors={['#04140c', '#0d3d2a', '#10b981', '#34d399', '#a3e635']}
              shape="horizon"
              characters=" =+xX0S8#@"
              cellSize={18}
              density={0.7}
              glow={0.22}
              speed={0.55}
              flow={0.6}
              softness={0.6}
              gradientOpacity={0.85}
              grain={0.07}
              variation={1}
              fontFamily='"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace'
            />
            <div
              className="absolute inset-0"
              style={{ background: 'linear-gradient(180deg, rgba(10,13,16,0.4) 0%, rgba(10,13,16,0) 34%, rgba(10,13,16,0.55) 76%, #0a0d10 100%)' }}
            />
          </div>
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
          <AnimatedContent distance={30} duration={0.7} threshold={0.2}>
            <h2 className="max-w-[640px] text-[clamp(26px,3.2vw,38px)] font-semibold leading-tight tracking-tight text-white">
              A focused console for Linux detection and response.
            </h2>
          </AnimatedContent>
          <AnimatedContent
            className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4"
            distance={50}
            duration={0.7}
            stagger={0.08}
            threshold={0.15}
          >
            {FEATURES.map((f) => (
              <SpotlightCard key={f.title} className="h-full p-5">
                <f.icon size={18} className="text-accent" aria-hidden="true" />
                <h3 className="mt-3 text-sm font-semibold text-text-primary">{f.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-text-muted">{f.body}</p>
              </SpotlightCard>
            ))}
          </AnimatedContent>
        </section>

        {/* Integrations */}
        <section id="integrations" className="border-y border-border-card bg-[#0c1014]">
          <div className="mx-auto grid max-w-[1360px] grid-cols-1 gap-10 px-5 py-24 lg:grid-cols-2 lg:px-10">
            <AnimatedContent distance={30} duration={0.7} threshold={0.2}>
              <h2 className="text-[clamp(26px,3.2vw,38px)] font-semibold leading-tight tracking-tight text-white">
                Telemetry from the host and the wire.
              </h2>
              <p className="mt-4 max-w-[520px] text-sm leading-relaxed text-text-secondary">
                Both integrations are optional and disabled by default. Greywatch records provenance so
                journal, Suricata, and ingested events are always distinguishable.
              </p>
            </AnimatedContent>
            <AnimatedContent
              className="flex flex-col gap-4"
              direction="horizontal"
              distance={40}
              duration={0.7}
              stagger={0.1}
              threshold={0.15}
            >
              {INTEGRATIONS.map((it) => (
                <div key={it.name} className="rounded-panel border border-border-card bg-card p-5">
                  <h3 className="text-sm font-semibold text-text-primary">{it.name}</h3>
                  <p className="mt-2 text-xs leading-relaxed text-text-secondary">{it.detail}</p>
                  <p className="mt-3 font-mono text-[11px] text-text-muted">{it.types}</p>
                </div>
              ))}
            </AnimatedContent>
          </div>
        </section>

        {/* Architecture */}
        <section id="architecture" className="mx-auto max-w-[1360px] px-5 py-24 lg:px-10">
          <AnimatedContent distance={30} duration={0.7} threshold={0.2}>
            <h2 className="text-[clamp(26px,3.2vw,38px)] font-semibold leading-tight tracking-tight text-white">How it works.</h2>
          </AnimatedContent>
          <AnimatedContent
            className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4"
            distance={50}
            duration={0.7}
            stagger={0.08}
            threshold={0.15}
          >
            {WORKFLOW.map((w) => (
              <div key={w.step} className="rounded-panel border border-border-card bg-card p-5">
                <span className="font-mono text-xs text-accent">{w.step}</span>
                <h3 className="mt-2 text-sm font-semibold text-text-primary">{w.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-text-muted">{w.body}</p>
              </div>
            ))}
          </AnimatedContent>
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
