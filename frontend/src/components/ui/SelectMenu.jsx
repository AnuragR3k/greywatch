import { useEffect, useRef, useState } from 'react'
import { Check, ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * Accessible dropdown selector. Options: [{ value, label }].
 * Closes on outside click, Escape, or selection; keyboard operable.
 */
export function SelectMenu({ value, onChange, options, label, className, align = 'left' }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const selected = options.find((o) => o.value === value) || options[0]

  useEffect(() => {
    if (!open) return undefined
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={ref} className={cn('relative', className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={label}
        className="flex h-8 w-full items-center gap-2 rounded-md border border-border-card bg-card px-2.5 text-xs text-text-secondary hover:bg-card-hover hover:text-text-primary"
      >
        <span className="truncate">{selected?.label}</span>
        <ChevronDown size={13} className="ml-auto shrink-0 text-text-muted" aria-hidden="true" />
      </button>
      {open && (
        <ul
          role="listbox"
          aria-label={label}
          className={cn(
            'absolute z-50 mt-1 min-w-[12rem] overflow-hidden rounded-md border border-border-card bg-raised p-1 shadow-xl',
            align === 'right' ? 'right-0' : 'left-0',
          )}
        >
          {options.map((o) => (
            <li key={String(o.value)}>
              <button
                type="button"
                role="option"
                aria-selected={o.value === value}
                onClick={() => { onChange(o.value); setOpen(false) }}
                className={cn(
                  'flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs',
                  o.value === value ? 'text-accent' : 'text-text-secondary hover:bg-card-hover hover:text-text-primary',
                )}
              >
                <span className="truncate">{o.label}</span>
                {o.value === value && <Check size={12} className="ml-auto shrink-0" aria-hidden="true" />}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
