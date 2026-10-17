import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from './Button'

/** Empty collection state. */
export function EmptyState({ title, description, icon: Icon = Inbox, action, actionLabel, className }) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 px-6 py-10 text-center', className)}>
      <span className="flex h-11 w-11 items-center justify-center rounded-full border border-border-card bg-raised text-text-muted">
        <Icon size={18} aria-hidden="true" />
      </span>
      <div className="space-y-1">
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        {description && <p className="mx-auto max-w-sm text-xs leading-relaxed text-text-muted">{description}</p>}
      </div>
      {action && actionLabel && (
        <Button variant="outline" size="sm" onClick={action}>
          {actionLabel}
        </Button>
      )}
    </div>
  )
}

/** Failure state with an optional retry. Never shows a fake zero. */
export function ErrorState({ title = 'Could not load', message, onRetry, className }) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 px-6 py-10 text-center', className)} role="alert">
      <span className="flex h-11 w-11 items-center justify-center rounded-full border border-[#7f1d1d]/50 bg-[#7f1d1d]/15 text-[#fca5a5]">
        <AlertTriangle size={18} aria-hidden="true" />
      </span>
      <div className="space-y-1">
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        {message && <p className="mx-auto max-w-sm text-xs leading-relaxed text-[#fca5a5]">{message}</p>}
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw size={13} aria-hidden="true" /> Retry
        </Button>
      )}
    </div>
  )
}

/** Inline "value unknown" notice so a failed metric never renders as 0. */
export function UnknownValue({ className }) {
  return <span className={cn('text-text-muted', className)} title="Value unavailable">—</span>
}
