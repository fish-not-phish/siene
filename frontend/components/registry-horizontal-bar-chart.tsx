'use client'

import * as React from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

export interface HBarRow {
  label: string
  sublabel?: string
  value: number
  /** Optional second metric shown as a dimmer segment (e.g. pushes alongside pulls) */
  value2?: number
  href?: string
}

export interface RegistryHorizontalBarChartProps {
  title: string
  subtitle?: string
  primaryLabel?: string
  secondaryLabel?: string
  data?: HBarRow[]
  loading?: boolean
  className?: string
  formatValue?: (v: number) => string
}

export function RegistryHorizontalBarChart({
  title,
  subtitle,
  primaryLabel = 'Pulls',
  secondaryLabel = 'Pushes',
  data,
  loading = false,
  className,
  formatValue,
}: RegistryHorizontalBarChartProps) {
  const fmt = formatValue ?? ((v: number) => v.toLocaleString())
  const rows = data ?? []
  const isEmpty = !loading && rows.length === 0

  // normalise widths against the max combined value
  const maxVal = rows.reduce((m, r) => Math.max(m, r.value + (r.value2 ?? 0)), 0)

  return (
    <div className={cn('flex flex-col gap-4 rounded-xl border bg-card p-4 sm:p-5', className)}>
      <div className='space-y-0.5'>
        <p className='text-xs font-semibold tracking-[0.16em] text-muted-foreground uppercase'>{title}</p>
        {subtitle && <p className='text-xs text-muted-foreground'>{subtitle}</p>}
      </div>

      {/* Legend */}
      {!loading && !isEmpty && (
        <div className='flex items-center gap-4 text-xs text-muted-foreground'>
          <span className='flex items-center gap-1.5'>
            <span className='size-2 rounded-full bg-[var(--chart-1)]' />{primaryLabel}
          </span>
          {rows.some(r => (r.value2 ?? 0) > 0) && (
            <span className='flex items-center gap-1.5'>
              <span className='size-2 rounded-full bg-[var(--chart-2)]' />{secondaryLabel}
            </span>
          )}
        </div>
      )}

      <div className='space-y-3'>
        {loading
          ? Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className='space-y-1.5'>
                <div className='flex items-center justify-between gap-3'>
                  <Skeleton className='h-3.5 w-32' />
                  <Skeleton className='h-3.5 w-12' />
                </div>
                <Skeleton className='h-2 w-full rounded-full' />
              </div>
            ))
          : isEmpty
            ? <p className='py-8 text-center text-sm text-muted-foreground'>No data</p>
            : rows.map((row, i) => {
                const primaryPct = maxVal > 0 ? (row.value / maxVal) * 100 : 0
                const secondaryPct = maxVal > 0 ? ((row.value2 ?? 0) / maxVal) * 100 : 0
                return (
                  <div key={i} className='group'>
                    <div className='mb-1 flex items-center justify-between gap-3'>
                      <div className='min-w-0 flex-1'>
                        <span className='block truncate text-sm font-medium'>{row.label}</span>
                        {row.sublabel && <span className='block truncate text-[11px] text-muted-foreground'>{row.sublabel}</span>}
                      </div>
                      <span className='shrink-0 text-xs tabular-nums text-muted-foreground'>{fmt(row.value)}</span>
                    </div>
                    {/* Track */}
                    <div className='relative h-2 w-full overflow-hidden rounded-full bg-muted'>
                      {/* Primary */}
                      <div
                        className='absolute left-0 top-0 h-full rounded-full bg-[var(--chart-1)] transition-all duration-500'
                        style={{ width: `${primaryPct}%` }}
                      />
                      {/* Secondary (offset) */}
                      {(row.value2 ?? 0) > 0 && (
                        <div
                          className='absolute top-0 h-full rounded-full bg-[var(--chart-2)] opacity-70 transition-all duration-500'
                          style={{ left: `${primaryPct}%`, width: `${secondaryPct}%` }}
                        />
                      )}
                    </div>
                  </div>
                )
              })
        }
      </div>
    </div>
  )
}
