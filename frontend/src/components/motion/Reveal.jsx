import { useRef } from 'react'
import { gsap, useGSAP, prefersReducedMotion } from '@/lib/motion/gsap'
import { cn } from '@/lib/utils'

/**
 * Transform-only reveal. Content is always visible (never opacity-from-zero),
 * so an animation failure or reduced-motion preference can never hide it. The
 * tween plays once when the element scrolls into view.
 */
export function Reveal({ delay = 0, y = 12, duration = 0.5, className, children, ...props }) {
  const ref = useRef(null)

  useGSAP(() => {
    const el = ref.current
    if (!el || prefersReducedMotion()) return undefined

    gsap.set(el, { y })
    let tween
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            tween = gsap.to(el, {
              y: 0,
              duration,
              delay,
              ease: 'power2.out',
              clearProps: 'transform',
            })
            io.disconnect()
          }
        }
      },
      { rootMargin: '0px 0px -8% 0px' },
    )
    io.observe(el)
    return () => {
      io.disconnect()
      tween?.kill()
    }
  }, { scope: ref })

  return <div ref={ref} className={cn(className)} {...props}>{children}</div>
}
