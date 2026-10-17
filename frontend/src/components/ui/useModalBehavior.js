import { useEffect, useRef } from 'react'

/** Close on Escape and move focus into the panel while it is open. */
export function useModalBehavior(open, containerRef, onClose) {
  const lastFocused = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    lastFocused.current = typeof document !== 'undefined' ? document.activeElement : null

    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onClose?.()
        return
      }
      if (e.key !== 'Tab') return
      const root = containerRef.current
      if (!root) return
      const focusable = root.querySelectorAll(
        'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown, true)
    const t = setTimeout(() => {
      const root = containerRef.current
      const target = root?.querySelector('[data-autofocus]') || root?.querySelector('button, [href], input')
      target?.focus?.()
    }, 0)

    return () => {
      document.removeEventListener('keydown', onKeyDown, true)
      clearTimeout(t)
      if (lastFocused.current?.focus) lastFocused.current.focus()
    }
  }, [open, containerRef, onClose])
}
