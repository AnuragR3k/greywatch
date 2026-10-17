import { useRef } from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useModalBehavior } from './useModalBehavior'

const SIZES = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-3xl',
}

/** Centered modal dialog. */
export function Dialog({ open, onClose, title, description, children, footer, size = 'sm', destructive = false }) {
  const ref = useRef(null)
  useModalBehavior(open, ref, onClose)

  if (!open) return null

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/65 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          'relative z-10 w-full rounded-panel border border-border-card bg-card shadow-2xl',
          SIZES[size] || SIZES.sm,
        )}
      >
        <div className="flex items-start gap-3 border-b border-border-card px-4 py-3">
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
            {description && <p className="mt-1 text-xs leading-relaxed text-text-secondary">{description}</p>}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="-mr-1 -mt-1 flex h-7 w-7 items-center justify-center rounded-md text-text-muted hover:bg-card-hover hover:text-text-primary"
          >
            <X size={15} />
          </button>
        </div>
        {children && <div className="px-4 py-4">{children}</div>}
        {footer && (
          <div className={cn('flex justify-end gap-2 border-t border-border-card px-4 py-3', destructive && 'bg-[#7f1d1d]/5')}>
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}
