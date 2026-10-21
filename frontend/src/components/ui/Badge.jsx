import { cn } from '@/lib/utils'

// Tone -> tailwind classes. Kept in one place so severity and status badges
// stay visually consistent everywhere. Color is never the only signal: every
// badge also carries a text label.
const TONE = {
  critical: 'bg-[#7f1d1d]/25 text-[#fca5a5] border-[#7f1d1d]/50',
  high: 'bg-[#7c2d12]/25 text-[#fdba74] border-[#7c2d12]/50',
  medium: 'bg-[#78350f]/25 text-[#fcd34d] border-[#78350f]/50',
  low: 'bg-[#0c4a6e]/30 text-[#7dd3fc] border-[#0c4a6e]/50',
  info: 'bg-[#1e3a5f]/30 text-[#93c5fd] border-[#1e3a5f]/50',
  healthy: 'bg-[#064e3b]/30 text-[#6ee7b7] border-[#064e3b]/50',
  degraded: 'bg-[#78350f]/25 text-[#fcd34d] border-[#78350f]/50',
  disabled: 'bg-[#334155]/25 text-[#94a3b8] border-[#334155]/50',
  unavailable: 'bg-[#7f1d1d]/25 text-[#fca5a5] border-[#7f1d1d]/50',
  unknown: 'bg-[#334155]/25 text-[#94a3b8] border-[#334155]/50',
  neutral: 'bg-[#334155]/25 text-[#94a3b8] border-[#334155]/50',
  teal: 'bg-[#134e4a]/30 text-[#5eead4] border-[#134e4a]/50',
  violet: 'bg-[#3b0764]/25 text-[#d8b4fe] border-[#3b0764]/50',
  amber: 'bg-[#78350f]/25 text-[#fcd34d] border-[#78350f]/50',
}

const STATUS_TONE = {
  open: 'critical',
  acknowledged: 'degraded',
  closed: 'healthy',
  healthy: 'healthy',
  degraded: 'degraded',
  disabled: 'disabled',
  unavailable: 'unavailable',
  unknown: 'unknown',
}

function toneClasses(tone) {
  return TONE[tone] || TONE.unknown
}

export function Badge({ tone = 'neutral', className, children, ...props }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide whitespace-nowrap',
        toneClasses(tone),
        className,
      )}
      {...props}
    >
      {children}
    </span>
  )
}

export function SeverityBadge({ severity = 'unknown', label, className }) {
  const tone = String(severity || 'unknown').toLowerCase()
  const text = label || String(severity || 'unrated').replace(/_/g, ' ')
  return (
    <Badge tone={tone} className={className} title={`Severity: ${text}`}>
      {text}
    </Badge>
  )
}

export function StatusBadge({ status = 'unknown', label, className }) {
  const tone = STATUS_TONE[status] || status
  const text = label || String(status || 'unknown')
  return (
    <Badge tone={tone} className={className} title={`Status: ${text}`}>
      {text}
    </Badge>
  )
}
