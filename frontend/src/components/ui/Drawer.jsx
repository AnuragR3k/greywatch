import { useRef } from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useModalBehavior } from './useModalBehavior'

/** Right-side sliding panel used for alert investigation. */
export function Drawer({ open, onClose, title, subtitle, children, footer, widthClass = 'w-full sm:w-[560px]' }) {
  const ref = useRef(null)
  useModalBehavior(open, ref, onClose)

  if (!open) return null

  return (
    <div className="fixed inset-0 z-[100]">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          'absolute right-0 top-0 flex h-full max-w-full flex-col border-l border-border-card bg-card shadow-2xl',
          widthClass,
        )}
      >
        <div className="flex items-start gap-3 border-b border-border-card px-4 py-3">
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-sm font-semibold text-text-primary">{title}</h2>
            {subtitle && <p className="truncate text-[11px] text-text-muted">{subtitle}</p>}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="-mr-1 -mt-1 flex h-7 w-7 items-center justify-center rounded-md text-text-muted hover:bg-card-hover hover:text-text-primary"
          >
            <X size={15} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-4 py-4">{children}</div>
        {footer && <div className="border-t border-border-card px-4 py-3">{footer}</div>}
      </div>
    </div>
  )
}
