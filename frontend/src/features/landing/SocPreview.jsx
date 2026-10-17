// Landing-page SOC preview.
//
// IMPORTANT: this is an illustrative product preview with example data — it is
// NOT connected to live telemetry, and is visibly labelled as a sample. Nothing
// here is fetched from the API; the real dashboard renders actual data.

const SAMPLE = {
  totalEvents: '184,203',
  openAlerts: '6',
  highSeverity: '3',
  collectors: '1 / 2',
  alerts: [
    { severity: 'HIGH', rule: 'SSH brute-force detected', meta: 'SSH_BRUTE_FORCE · 42 attempts', source: '203.0.113.10', time: '14:38', status: 'open' },
    { severity: 'HIGH', rule: 'ET SCAN suspicious inbound', meta: 'SURICATA_ALERT · sig 2010935', source: '185.220.101.4', time: '14:21', status: 'open' },
    { severity: 'MED', rule: 'SSH invalid user attempts', meta: 'ssh_invalid_user · 7 attempts', source: '198.51.100.23', time: '13:57', status: 'open' },
    { severity: 'MED', rule: 'ET DNS query to known C2', meta: 'SURICATA_ALERT · sig 2027869', source: '45.155.205.9', time: '13:40', status: 'open' },
  ],
  volume: 'M0 104 L33 98 L66 88 L99 96 L132 82 L165 90 L198 74 L231 86 L264 60 L297 84 L330 78 L363 92 L396 70 L429 76 L462 88 L495 72 L528 96 L561 84 L594 66 L627 42 L660 58 L693 90 L726 74 L759 96 L792 110',
}

const SEV = {
  HIGH: 'text-[#fca5a5] bg-[#f87171]/10 border-[#f87171]/25',
  MED: 'text-[#fcd34d] bg-[#fbbf24]/10 border-[#fbbf24]/25',
}

function Kpi({ label, value, valueClass = 'text-text-primary', sub }) {
  return (
    <div className="flex flex-1 flex-col gap-2 px-4 py-3.5">
      <span className="font-mono text-[10px] tracking-widest text-text-muted">{label}</span>
      <span className={`text-2xl font-semibold leading-none tracking-tight ${valueClass}`}>{value}</span>
      {sub && <span className="text-[11px] text-text-muted">{sub}</span>}
    </div>
  )
}

export function SocPreview() {
  return (
    <div className="w-full overflow-hidden rounded-2xl border border-white/10 bg-[#0c1014] shadow-[0_40px_120px_rgba(0,0,0,0.6)]">
      {/* Chrome */}
      <div className="flex items-center justify-between border-b border-white/[0.07] bg-white/[0.015] px-4 py-3">
        <div className="flex items-center gap-2.5">
          <svg width="18" height="18" viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <path d="M16 2.5 27 7v9.2c0 6.3-4.4 10.9-11 13.3C9.4 27.1 5 22.5 5 16.2V7L16 2.5Z" fill="#0E1512" stroke="#34d399" strokeWidth="1.8" strokeLinejoin="round" />
            <circle cx="16" cy="16" r="3" fill="#a3e635" />
          </svg>
          <span className="text-[13px] font-semibold text-text-primary">Security Operations</span>
        </div>
        <span className="rounded-full border border-severity-medium/30 bg-severity-medium/10 px-2.5 py-0.5 font-mono text-[10px] font-semibold tracking-wide text-severity-medium">
          SAMPLE PREVIEW
        </span>
      </div>

      <div className="flex flex-col gap-3 p-3.5">
        <div className="flex items-center gap-2 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-2 text-[11px] text-text-muted">
          Illustrative interface with example data — not connected to live telemetry.
        </div>

        {/* KPI strip */}
        <div className="flex items-stretch rounded-xl border border-white/[0.07] bg-white/[0.02]">
          <Kpi label="TOTAL EVENTS · 24H" value={SAMPLE.totalEvents} sub="journal 128,440 · suricata 55,763" />
          <div className="w-px bg-white/[0.06]" />
          <Kpi label="OPEN ALERTS" value={SAMPLE.openAlerts} valueClass="text-severity-medium" sub="4 ssh · 2 suricata" />
          <div className="hidden w-px bg-white/[0.06] sm:block" />
          <div className="hidden flex-1 sm:block"><Kpi label="HIGH SEVERITY" value={SAMPLE.highSeverity} valueClass="text-severity-critical" sub="ssh brute-force" /></div>
          <div className="hidden w-px bg-white/[0.06] lg:block" />
          <div className="hidden flex-1 lg:block"><Kpi label="COLLECTORS" value={SAMPLE.collectors} sub="journal active" /></div>
        </div>

        {/* Chart + distribution */}
        <div className="flex flex-col gap-3 lg:flex-row">
          <div className="flex flex-1 flex-col gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[13px] font-semibold text-text-primary">Event volume</span>
              <span className="rounded bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px] text-text-muted">24H</span>
            </div>
            <svg viewBox="0 0 792 132" className="h-32 w-full" fill="none" preserveAspectRatio="none" aria-hidden="true">
              <defs>
                <linearGradient id="lp-area" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#34d399" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#34d399" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path d={`${SAMPLE.volume} L792,131 L0,131 Z`} fill="url(#lp-area)" />
              <path d={SAMPLE.volume} stroke="#34d399" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
            </svg>
          </div>
          <div className="flex flex-col gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3.5 lg:w-[260px] lg:shrink-0">
            <span className="text-[13px] font-semibold text-text-primary">Event distribution</span>
            <div className="flex h-2 gap-0.5 overflow-hidden rounded">
              <div className="rounded" style={{ width: '69.7%', background: 'linear-gradient(90deg,#10b981,#34d399)' }} />
              <div className="flex-1 rounded bg-accent-lime/85" />
            </div>
            <div className="flex items-center gap-2.5 text-[12px]">
              <span className="h-2 w-2 rounded-[2px] bg-accent" />
              <span className="flex-1 text-text-primary">systemd journal</span>
              <span className="font-mono text-text-secondary">69.7%</span>
            </div>
            <div className="flex items-center gap-2.5 text-[12px]">
              <span className="h-2 w-2 rounded-[2px] bg-accent-lime" />
              <span className="flex-1 text-text-primary">suricata eve</span>
              <span className="font-mono text-text-secondary">30.3%</span>
            </div>
          </div>
        </div>

        {/* Alerts */}
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3.5">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[13px] font-semibold text-text-primary">Recent alerts</span>
            <span className="text-[11px] text-text-muted">6 open</span>
          </div>
          {SAMPLE.alerts.map((a, i) => (
            <div key={i} className="flex items-center gap-3 border-t border-white/[0.05] py-2.5 first:border-t-0">
              <span className={`w-[52px] shrink-0 rounded-full border px-2 py-0.5 text-center font-mono text-[10px] font-semibold ${SEV[a.severity]}`}>{a.severity}</span>
              <div className="flex min-w-0 flex-1 flex-col">
                <span className="truncate text-[12.5px] font-medium text-text-primary">{a.rule}</span>
                <span className="truncate font-mono text-[10px] text-text-muted">{a.meta}</span>
              </div>
              <span className="hidden w-[120px] shrink-0 font-mono text-[11px] text-text-secondary md:block">{a.source}</span>
              <span className="hidden w-12 shrink-0 font-mono text-[11px] text-text-secondary sm:block">{a.time}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
