import { cn } from '@/lib/utils'
import { Button } from './Button'

/** Bordered surface used for every dashboard panel. */
export function Panel({ className, children, ...props }) {
  return (
    <section
      className={cn('rounded-panel border border-border-card bg-card', className)}
      {...props}
    >
      {children}
    </section>
  )
}

export function PanelHeader({ title, subtitle, icon: Icon, actions, className }) {
  return (
    <div className={cn('flex items-center gap-2.5 border-b border-border-card px-4 py-3', className)}>
      {Icon && <Icon size={15} className="shrink-0 text-text-muted" aria-hidden="true" />}
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
        {subtitle && <p className="truncate text-[11px] text-text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="ml-auto flex shrink-0 items-center gap-1.5">{actions}</div>}
    </div>
  )
}

export function PanelBody({ className, children }) {
  return <div className={cn('p-4', className)}>{children}</div>
}

/** Small ghost refresh button for panel headers. */
export function RefreshButton({ onClick, label = 'Refresh', className }) {
  return (
    <Button variant="ghost" size="icon" onClick={onClick} aria-label={label} className={className}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
        <path d="M21 3v5h-5" />
      </svg>
    </Button>
  )
}
