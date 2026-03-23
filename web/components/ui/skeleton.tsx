import { cn } from '@/lib/utils'

function Skeleton({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      className={cn('animate-pulse rounded bg-[#1E293B]', className)}
      {...props}
    />
  )
}

export { Skeleton }
