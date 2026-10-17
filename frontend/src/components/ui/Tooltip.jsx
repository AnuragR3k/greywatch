import { cn } from '@/lib/utils'

/**
 * Lightweight tooltip. Renders a label on hover/focus using CSS, and keeps the
 * native `title` attribute as a fallback for assistive tech and touch.
 */
export function Tooltip({ label, side = 'right', className, children }) {
  const position =
    side === 'right'
      ? 'left-full top-1/2 ml-2 -translate-y-1/2'
      : side === 'bottom'
        ? 'top-full left-1/2 mt-2 -translate-x-1/2'
        : 'bottom-full left-1/2 mb-2 -translate-x-1/2'

  return (
    <span className={cn('group/tt relative inline-flex', className)}>
      {children}
      <span
        role="tooltip"
        className={cn(
          'pointer-events-none absolute z-50 hidden whitespace-nowrap rounded-md border border-border-card bg-raised px-2 py-1 text-[11px] text-text-primary shadow-lg group-hover/tt:block group-focus-within/tt:block',
          position,
        )}
      >
        {label}
      </span>
    </span>
  )
}
