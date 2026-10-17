import { useEffect, useRef } from 'react'
import { gsap, prefersReducedMotion } from '@/lib/motion/gsap'
import { cn } from '@/lib/utils'

/**
 * Animated integer. Shows a real value; renders an em dash (or the caller's
 * fallback) when the value is unknown rather than animating to zero.
 * Inspired by React Bits "CountUp".
 */
export function CountUp({ value, fallback = '—', className, duration = 0.5, format = (n) => n.toLocaleString() }) {
  const ref = useRef(null)
  const proxy = useRef({ v: 0 })

  useEffect(() => {
    const el = ref.current
    if (!el) return undefined
    const numeric = value == null ? null : Number(value)
    if (numeric == null || Number.isNaN(numeric)) {
      el.textContent = fallback
      return undefined
    }
    if (prefersReducedMotion()) {
      el.textContent = format(numeric)
      return undefined
    }
    const proxyState = proxy.current
    const tween = gsap.to(proxyState, {
      v: numeric,
      duration,
      ease: 'power2.out',
      snap: { v: 1 },
      onUpdate: () => { el.textContent = format(Math.round(proxyState.v)) },
      onComplete: () => { el.textContent = format(numeric) },
    })
    return () => { tween.kill(); proxyState.v = numeric }
  }, [value, fallback, duration, format])

  return (
    <span ref={ref} className={cn('tabular-nums', className)}>
      {value == null ? fallback : format(Number(value))}
    </span>
  )
}
