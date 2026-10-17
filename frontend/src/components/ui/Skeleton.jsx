import { cn } from '@/lib/utils'

export function Skeleton({ className }) {
  return <div className={cn('gw-skeleton', className)} aria-hidden="true" />
}

export function SkeletonText({ lines = 3, className }) {
  return (
    <div className={cn('flex flex-col gap-2', className)} aria-hidden="true">
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn('h-3.5', i === lines - 1 ? 'w-1/2' : 'w-full')} />
      ))}
    </div>
  )
}
