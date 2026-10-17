import { useCallback, useRef } from 'react'
import { cn } from '@/lib/utils'
import { prefersReducedMotion } from '@/lib/motion/gsap'

/**
 * Card with a restrained pointer spotlight. Disabled under reduced motion
 * (the card simply renders without tracking). Inspired by React Bits
 * "SpotlightCard".
 */
export function SpotlightCard({ className, children, spotlightColor = 'rgba(52,211,153,0.14)', ...props }) {
  const ref = useRef(null)

  const onPointerMove = useCallback((e) => {
    const el = ref.current
    if (!el || prefersReducedMotion()) return
    const rect = el.getBoundingClientRect()
    el.style.setProperty('--mx', `${e.clientX - rect.left}px`)
    el.style.setProperty('--my', `${e.clientY - rect.top}px`)
  }, [])

  return (
    <div
      ref={ref}
      onPointerMove={onPointerMove}
      className={cn('group/spot relative overflow-hidden rounded-panel border border-border-card bg-card', className)}
      {...props}
    >
      <span
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover/spot:opacity-100"
        style={{ background: `radial-gradient(320px circle at var(--mx, 50%) var(--my, 0%), ${spotlightColor}, transparent 70%)` }}
        aria-hidden="true"
      />
      <div className="relative">{children}</div>
    </div>
  )
}
