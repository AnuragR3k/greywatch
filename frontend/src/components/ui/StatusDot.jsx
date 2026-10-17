import { cn } from '@/lib/utils'

const DOT = {
  healthy: 'bg-severity-healthy',
  degraded: 'bg-severity-medium',
  disabled: 'bg-severity-unknown',
  unavailable: 'bg-severity-critical',
  unknown: 'bg-severity-unknown',
}

/** Small colored status dot; always paired with a text label elsewhere. */
export function StatusDot({ tone = 'unknown', pulse = false, className }) {
  return (
    <span
      className={cn('inline-block h-2 w-2 shrink-0 rounded-full', DOT[tone] || DOT.unknown, pulse && 'gw-pulse', className)}
      aria-hidden="true"
    />
  )
}
