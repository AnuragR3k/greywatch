import { cn } from '@/lib/utils'
import { hasValue } from '@/lib/format/values'

/** A labelled description-list value, used across detail views. */
export function Field({ label, value, mono = false, className }) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-1', className)}>
      <dt className="text-[10px] font-medium uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className={cn('truncate text-sm text-text-primary', mono && 'font-mono text-xs')} title={hasValue(value) ? String(value) : undefined}>
        {hasValue(value) ? String(value) : '—'}
      </dd>
    </div>
  )
}

export function FieldGrid({ fields, className }) {
  return (
    <dl className={cn('grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2', className)}>
      {fields.map((f) => (
        <Field key={f.label} label={f.label} value={f.value} mono={f.mono} />
      ))}
    </dl>
  )
}
