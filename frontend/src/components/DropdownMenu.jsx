import {
  createContext,
  cloneElement,
  isValidElement,
  useCallback,
  useContext,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { createPortal } from 'react-dom'
import { motion } from 'motion/react'
import { cn } from '@/lib/utils'

/*
 * DropdownMenu — a small, dependency-free (React + Motion only) re-implementation
 * of the Radix-style `DropdownMenu` API, used as the single dropdown convention
 * across the Greywatch dashboard:
 *
 *   <DropdownMenu>
 *     <DropdownMenuTrigger asChild>...</DropdownMenuTrigger>
 *     <DropdownMenuContent>
 *       <DropdownMenuGroup>
 *         <DropdownMenuItem onSelect={...}>...</DropdownMenuItem>
 *       </DropdownMenuGroup>
 *       <DropdownMenuSeparator />
 *     </DropdownMenuContent>
 *   </DropdownMenu>
 *
 * Shared by every dropdown on the dashboard:
 *  - fade + scale (0.96 -> 1) + 4px slide-up open/close animation
 *  - fixed-position portal render (no clipping by overflow containers,
 *    always stacks above panels/charts)
 *  - viewport collision handling (flip to the open side)
 *  - keyboard navigation (Arrow/Home/End, Enter to select, Escape/Tab to close)
 *  - click-away dismissal and focus restore on close
 *  - respects prefers-reduced-motion (matchMedia + CSS @media fallback)
 *
 * No new dependencies are introduced: `motion` is already a dependency
 * (used by components/Dock.jsx).
 */

const SIDE_OFFSET = 8
const MIN_WIDTH = 170

const DropdownMenuContext = createContext(null)

// Self-contained prefers-reduced-motion query (avoids coupling to a specific
// Motion/Framer re-export, which varies across installs).
function useReducedMotion() {
  const [reduced, setReduced] = useState(
    () =>
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  )
  const handler = useCallback(() => {
    if (typeof window === 'undefined') return
    setReduced(window.matchMedia('(prefers-reduced-motion: reduce)').matches)
  }, [])
  useLayoutEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    mq.addEventListener?.('change', handler)
    return () => mq.removeEventListener?.('change', handler)
  }, [handler])
  return reduced
}

export function DropdownMenu({
  open: controlledOpen,
  defaultOpen = false,
  onOpenChange,
  children,
}) {
  const [openState, setOpenState] = useState(defaultOpen)
  const controlled = controlledOpen !== undefined
  const open = controlled ? controlledOpen : openState
  const onOpenChangeProp = useRef(onOpenChange)
  const triggerRef = useRef(null)
  const contentId = `gw-dropdown-content-${useId()}`

  const ctx = useMemo(
    () => ({
      open,
      onOpenChange(next) {
        const nextVal = typeof next === 'boolean' ? next : !open
        if (!controlled) setOpenState(nextVal)
        onOpenChangeProp.current?.(nextVal)
      },
      triggerRef,
      contentId,
    }),
    [open, controlled, contentId],
  )

  return (
    <DropdownMenuContext.Provider value={ctx}>{children}</DropdownMenuContext.Provider>
  )
}

export function DropdownMenuTrigger({ asChild = false, children, ...props }) {
  const ctx = useContext(DropdownMenuContext)
  if (!ctx)
    throw new Error('DropdownMenuTrigger must be used inside <DropdownMenu>')

  const { open, onOpenChange, triggerRef, contentId } = ctx

  const toggle = (e) => {
    e.stopPropagation()
    onOpenChange(!open)
  }

  const onKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      onOpenChange(true)
    }
  }

  if (asChild && isValidElement(children)) {
    return cloneElement(children, {
      ...props,
      ref: triggerRef,
      'aria-haspopup': 'menu',
      'aria-expanded': open,
      'aria-controls': open ? contentId : undefined,
      onClick: (e) => {
        children.props?.onClick?.(e)
        toggle(e)
      },
      onKeyDown: (e) => {
        children.props?.onKeyDown?.(e)
        onKeyDown(e)
      },
      tabIndex: children.props.tabIndex ?? 0,
      role: children.props.role ?? 'button',
    })
  }

  return (
    <button
      type="button"
      {...props}
      ref={triggerRef}
      aria-haspopup="menu"
      aria-expanded={open}
      aria-controls={open ? contentId : undefined}
      onClick={toggle}
      onKeyDown={onKeyDown}
      tabIndex={0}
      role="button"
    >
      {children}
    </button>
  )
}

// The content panel is kept mounted (hidden when closed) so Motion can play its
// exit animation and so the rendered box is measurable for positioning.
export function DropdownMenuContent({
  children,
  align = 'start',
  sideOffset = SIDE_OFFSET,
  className,
  style,
  ...props
}) {
  const ctx = useContext(DropdownMenuContext)
  if (!ctx)
    throw new Error('DropdownMenuContent must be used inside <DropdownMenu>')

  const { open, onOpenChange, triggerRef, contentId } = ctx
  const contentRef = useRef(null)
  const reduced = useReducedMotion()
  const [pos, setPos] = useState({ top: 0, left: 0, minWidth: MIN_WIDTH })
  const restoreFocusRef = useRef(null)

  // Position by measuring the trigger and the (always-mounted) content box.
  useLayoutEffect(() => {
    if (!open) return
    const trigger = triggerRef?.current
    const content = contentRef.current
    if (!trigger || !content) return

    const tr = trigger.getBoundingClientRect()
    const cr = content.getBoundingClientRect()
    const estWidth = Math.max(cr.width, MIN_WIDTH)

    const fitsBelow = tr.bottom + sideOffset + cr.height + 12 <= window.innerHeight
    const top = fitsBelow
      ? tr.bottom + sideOffset
      : Math.max(sideOffset, tr.top - cr.height - sideOffset)

    let left
    if (align === 'end') left = tr.right - estWidth
    else if (align === 'center') left = tr.left + (tr.width - estWidth) / 2
    else left = tr.left
    if (left < 12) left = 12
    if (left + estWidth + 12 > window.innerWidth) {
      left = Math.max(12, window.innerWidth - estWidth - 12)
    }

    setPos({
      top: Math.round(top),
      left: Math.round(left),
      minWidth: Math.round(Math.max(tr.width, MIN_WIDTH)),
    })
  }, [open, triggerRef, align, sideOffset])

  // Focus management: focus the selected (or first) item on open; restore on
  // close so the trigger regains focus (keyboard + click-away friendly).
  useLayoutEffect(() => {
    if (!open) {
      restoreFocusRef.current?.focus?.()
      restoreFocusRef.current = null
      return
    }
    restoreFocusRef.current = document.activeElement
    const content = contentRef.current
    const t = window.setTimeout(() => {
      const selected = content?.querySelector(
        '[role="menuitem"][aria-selected="true"]:not([disabled])',
      )
      const first = content?.querySelector('[role="menuitem"]:not([disabled])')
      ;(selected || first)?.focus()
    }, reduced ? 0 : 10)
    return () => window.clearTimeout(t)
  }, [open, reduced])

  // Click-away + Escape dismissal.
  useLayoutEffect(() => {
    if (!open) return
    const trigger = triggerRef?.current
    const onPointerDown = (e) => {
      if (
        contentRef.current?.contains(e.target) ||
        (trigger && trigger.contains(e.target)) ||
        e.button === 1
      )
        return
      onOpenChange(false)
    }
    const onKeyDownDoc = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onOpenChange(false)
      }
    }
    document.addEventListener('pointerdown', onPointerDown, { capture: true })
    document.addEventListener('keydown', onKeyDownDoc)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, { capture: true })
      document.removeEventListener('keydown', onKeyDownDoc)
    }
  }, [open, triggerRef, onOpenChange])

  const onKeyDown = (e) => {
    // Activate the focused item with Enter/Space (keyboards may not synthesize
    // a click for <button> inside a menu the way browsers do natively).
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      const items = contentRef.current?.querySelectorAll(
        '[role="menuitem"]:not([disabled])',
      )
      const idx = Array.from(items || []).findIndex((it) => it === document.activeElement)
      if (idx >= 0) items[idx].click()
      return
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return
    const items = contentRef.current?.querySelectorAll(
      '[role="menuitem"]:not([disabled])',
    )
    if (!items || items.length === 0) return
    const idx = Array.from(items).findIndex((it) => it === document.activeElement)
    let next = idx
    if (e.key === 'ArrowDown') next = (idx + 1) % items.length
    else if (e.key === 'ArrowUp') next = (idx - 1 + items.length) % items.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = items.length - 1
    e.preventDefault()
    items[next].focus()
  }

  const variants = {
    open: { opacity: 1, scale: 1, y: 0 },
    closed: { opacity: 0, scale: 0.96, y: 4 },
  }
  const transition = reduced
    ? { duration: 0.01 }
    : { duration: 0.18, ease: [0.25, 0.1, 0.25, 1] }

  return createPortal(
    <motion.div
      ref={contentRef}
      id={open ? contentId : undefined}
      role="menu"
      tabIndex={-1}
      aria-orientation="vertical"
      aria-hidden={!open}
      className={cn('gw-dropdown-content', className)}
      style={{
        position: 'fixed',
        top: pos.top,
        left: pos.left,
        minWidth: pos.minWidth,
        maxWidth: 'calc(100vw - 24px)',
        maxHeight: 'calc(100vh - 24px)',
        pointerEvents: open ? 'auto' : 'none',
        ...style,
      }}
      variants={variants}
      initial="closed"
      animate={open ? 'open' : 'closed'}
      transition={transition}
      onKeyDown={onKeyDown}
      {...props}
    >
      {children}
    </motion.div>,
    document.body,
  )
}

export function DropdownMenuGroup({ children, ...props }) {
  return (
    <div role="group" {...props}>
      {children}
    </div>
  )
}

export function DropdownMenuItem({
  children,
  onSelect,
  disabled,
  selected,
  className,
  destructive,
  ...props
}) {
  const ctx = useContext(DropdownMenuContext)
  if (!ctx)
    throw new Error('DropdownMenuItem must be used inside <DropdownMenu>')

  const onClick = (e) => {
    if (disabled) {
      e.preventDefault()
      e.stopPropagation()
      return
    }
    e.preventDefault()
    onSelect?.()
    ctx.onOpenChange(false)
  }

  return (
    <button
      type="button"
      role="menuitem"
      tabIndex={-1}
      aria-selected={selected ? 'true' : 'false'}
      disabled={disabled || undefined}
      className={cn(
        'gw-dropdown-item',
        selected && 'gw-dropdown-item--selected',
        destructive && 'gw-dropdown-item--destructive',
        className,
      )}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  )
}

export function DropdownMenuSeparator({ className, ...props }) {
  return (
    <div className={cn('gw-dropdown-separator', className)} role="separator" {...props} />
  )
}

/* ==========================================================================
   Shared generic value selector
   - A small convenience component built on the DropdownMenu primitives.
   - `children` is rendered as the trigger (via DropdownMenuTrigger asChild),
     so each call-site keeps its own visual style (toolbar pill, header meta,
     teal header, mobile compact) while sharing one menu behavior/animation.
   ========================================================================== */
export function RangeSelect({ value, onChange, options, children }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>{children}</DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        {options.map((o) => (
          <DropdownMenuItem
            key={o.value}
            selected={value === o.value}
            onSelect={() => onChange(o.value)}
          >
            {o.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
