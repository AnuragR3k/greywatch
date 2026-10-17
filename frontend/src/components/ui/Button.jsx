import { forwardRef } from 'react'
import { cva } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const button = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md border font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        primary: 'border-accent bg-accent text-[#04140c] hover:bg-accent-strong',
        outline: 'border-border-card bg-transparent text-text-secondary hover:bg-card-hover hover:text-text-primary',
        ghost: 'border-transparent bg-transparent text-text-secondary hover:bg-card-hover hover:text-text-primary',
        danger: 'border-[#7f1d1d] bg-[#7f1d1d] text-[#fecaca] hover:bg-[#9b2226]',
      },
      size: {
        sm: 'h-8 px-3 text-xs',
        md: 'h-9 px-3.5 text-sm',
        lg: 'h-10 px-4 text-sm',
        icon: 'h-8 w-8',
      },
    },
    defaultVariants: { variant: 'outline', size: 'md' },
  },
)

export const Button = forwardRef(function Button(
  { className, variant, size, disabled, loading, children, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type="button"
      className={cn(button({ variant, size }), className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <span className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" />
      )}
      {children}
    </button>
  )
})
