'use client'

import * as React from 'react'
import { useMemo } from 'react'
import { CartesianGrid, Line, LineChart, Tooltip, type TooltipProps, XAxis, YAxis } from 'recharts'
import { type ChartConfig, ChartContainer } from '@/components/ui/chart'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { ActivityDay } from '@/services/registry'

// ── Types ─────────────────────────────────────────────────────────────────────

type ActivityPoint = {
  key: string          // unique point key
  date: string         // YYYY-MM-DD (real) or '' (empty bucket)
  dateLabel: string    // "Jun 18, 2025"
  xLabel: string       // month label shown on x-axis tick, e.g. "JAN"
  pushes: number
  pulls: number
  total: number
}

// ── Constants ─────────────────────────────────────────────────────────────────

const BARS_PER_MONTH = 6   // ~5 weeks per month, show 6 data points

const chartConfig = {
  pushes: { label: 'Pushes', color: 'var(--primary)' },
  pulls:  { label: 'Pulls',  color: 'var(--chart-2)' },
} satisfies ChartConfig

const MONTH_SHORT = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC']
const MONTH_LONG  = ['January','February','March','April','May','June','July','August','September','October','November','December']

// ── Data builder ──────────────────────────────────────────────────────────────

/**
 * Pick a clean Y-axis ceiling just above `peak`.
 *
 * Computes a nice step size (1, 2, 5, 10, 20, 50, …) so the chart has 4
 * equal intervals and the top tick is always strictly above the peak bar.
 * Minimum ceiling of 8 so the grid never looks completely flat.
 */
function niceMax(peak: number): number {
  if (peak <= 0) return 8
  // Target 4 intervals → rough step size
  const roughStep = peak / 4
  // Round roughStep up to the nearest "nice" magnitude: 1, 2, 5, × 10^n
  const mag = Math.pow(10, Math.floor(Math.log10(roughStep)))
  const norm = roughStep / mag
  const niceStep = norm <= 1 ? mag : norm <= 2 ? 2 * mag : norm <= 5 ? 5 * mag : 10 * mag
  // Ceiling = smallest multiple of niceStep strictly above peak
  const ceiling = Math.ceil((peak + 1) / niceStep) * niceStep
  return Math.max(ceiling, 8)
}

/**
 * Bucket raw daily rows into BARS_PER_MONTH columns per month for the last 12
 * calendar months.  Each column aggregates ~5 days of data.
 */
function buildChartPoints(data: ActivityDay[]): ActivityPoint[] {
  const now = new Date()
  const points: ActivityPoint[] = []

  // Build a lookup: date string → { pushes, pulls }
  const byDate = new Map<string, { pushes: number; pulls: number }>()
  for (const d of data) byDate.set(d.date, { pushes: d.pushes, pulls: d.pulls })

  // Walk backwards 12 months from current month
  for (let mOffset = 11; mOffset >= 0; mOffset--) {
    const year  = now.getMonth() - mOffset < 0
      ? now.getFullYear() - 1
      : now.getFullYear()
    const month = ((now.getMonth() - mOffset) % 12 + 12) % 12

    const daysInMonth = new Date(year, month + 1, 0).getDate()
    const bucketSize  = daysInMonth / BARS_PER_MONTH

    for (let b = 0; b < BARS_PER_MONTH; b++) {
      const dayStart = Math.floor(b * bucketSize) + 1
      const dayEnd   = b === BARS_PER_MONTH - 1 ? daysInMonth : Math.floor((b + 1) * bucketSize)

      let pushes = 0
      let pulls  = 0
      let firstDate = ''

      for (let d = dayStart; d <= dayEnd; d++) {
        const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`
        if (!firstDate) firstDate = dateStr
        const entry = byDate.get(dateStr)
        if (entry) { pushes += entry.pushes; pulls += entry.pulls }
      }

      const key = `${year}-${month}-${b}`
      // Format date range label for tooltip: "Jun 1–5, 2025"
      const startFmt = `${MONTH_LONG[month]} ${dayStart}`
      const endFmt   = dayStart === dayEnd ? '' : `–${dayEnd}`
      const dateLabel = `${startFmt}${endFmt}, ${year}`

      points.push({
        key,
        date: firstDate,
        dateLabel,
        xLabel: b === 0 ? MONTH_SHORT[month] : '',
        pushes,
        pulls,
        total: pushes + pulls,
      })
    }
  }

  return points
}

// ── SVG sub-components ────────────────────────────────────────────────────────

function ChartTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null
  const row = payload[0]?.payload as ActivityPoint | undefined
  if (!row) return null
  return (
    <div className='min-w-[180px] rounded-xl border bg-popover/95 p-3 shadow-xl backdrop-blur-sm'>
      <p className='mb-3 rounded-md border bg-muted/35 px-2.5 py-1 text-sm font-medium'>{row.dateLabel}</p>
      <div className='space-y-2 text-sm'>
        <div className='flex items-center justify-between gap-5'>
          <span className='flex items-center gap-2 text-muted-foreground'><span className='size-1.5 rounded-full bg-[var(--color-pushes)]' />Pushes</span>
          <span className='font-semibold'>{row.pushes}</span>
        </div>
        <div className='flex items-center justify-between gap-5'>
          <span className='flex items-center gap-2 text-muted-foreground'><span className='size-1.5 rounded-full bg-[var(--color-pulls)]' />Pulls</span>
          <span className='font-semibold'>{row.pulls}</span>
        </div>
      </div>
    </div>
  )
}

// ── Exported component ────────────────────────────────────────────────────────

export interface RegistryActivityChartProps {
  /** Raw daily data from the API. Pass undefined while loading. */
  data?: ActivityDay[]
  loading?: boolean
  className?: string
}

export function RegistryActivityChart({ data, loading = false, className }: RegistryActivityChartProps) {
  const chartData = useMemo(() => buildChartPoints(data ?? []), [data])

  const chartMax = useMemo(() => {
    const peak = chartData.reduce((m, p) => Math.max(m, p.pushes, p.pulls), 0)
    return niceMax(peak)
  }, [chartData])

  const totals = useMemo(() => {
    const t = chartData.reduce((acc, p) => { acc.pushes += p.pushes; acc.pulls += p.pulls; return acc }, { pushes: 0, pulls: 0 })
    const total = t.pushes + t.pulls
    return { ...t, total, pushShare: total > 0 ? Math.round((t.pushes / total) * 100) : 0, pullShare: total > 0 ? Math.round((t.pulls / total) * 100) : 0 }
  }, [chartData])

  return (
    <div className={cn('flex min-w-0 flex-1 flex-col gap-4 rounded-xl border bg-card p-4 sm:gap-5 sm:p-5', className)}>
      <div className='space-y-3 pb-3'>
        <div className='flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between'>
          <div className='min-w-0 space-y-1.5'>
            <p className='text-xs font-semibold tracking-[0.16em] text-muted-foreground uppercase'>Registry Activity</p>
            <div className='flex flex-wrap items-end gap-3'>
              {loading
                ? <Skeleton className='h-10 w-24' />
                : <>
                    <span className='text-4xl leading-none font-semibold tabular-nums'>{totals.total.toLocaleString()}</span>
                    <span className='pb-1 text-sm text-muted-foreground'>operations · last 12 months</span>
                  </>
              }
            </div>
          </div>
          <div className='flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted-foreground lg:justify-end'>
            <div className='flex items-center gap-2'>
              <span className='size-2 rounded-full bg-[var(--color-pushes)]' />
              <span className='font-medium text-foreground'>Pushes</span>
              {loading ? <Skeleton className='h-4 w-10' /> : <><span className='tabular-nums'>{totals.pushes.toLocaleString()}</span><span>{totals.pushShare}%</span></>}
            </div>
            <div className='flex items-center gap-2'>
              <span className='size-2 rounded-full bg-[var(--color-pulls)]' />
              <span className='font-medium text-foreground'>Pulls</span>
              {loading ? <Skeleton className='h-4 w-10' /> : <><span className='tabular-nums'>{totals.pulls.toLocaleString()}</span><span>{totals.pullShare}%</span></>}
            </div>
          </div>
        </div>
      </div>

      <div className='h-[260px] w-full min-w-0 sm:h-[300px]'>
        {loading
          ? <Skeleton className='h-full w-full rounded-lg' />
          : (
            <ChartContainer config={chartConfig} className='h-full w-full [&_.recharts-cartesian-axis-line]:stroke-transparent [&_.recharts-cartesian-axis-tick_line]:stroke-transparent'>
              <LineChart data={chartData} margin={{ top: 8, right: 8, left: -6, bottom: 10 }}>
                <CartesianGrid strokeDasharray='3 3' vertical={false} />
                <XAxis dataKey='xLabel' axisLine={false} tickLine={false} interval={0} tick={{ fontSize: 11, fontWeight: 500 }} dy={8} />
                <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 11 }} ticks={[0, Math.round(chartMax * 0.25), Math.round(chartMax * 0.5), Math.round(chartMax * 0.75), chartMax]} domain={[0, chartMax]} width={36} />
                <Tooltip content={<ChartTooltip />} />
                <Line
                  type='monotone'
                  dataKey='pushes'
                  stroke='var(--color-pushes)'
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, strokeWidth: 0 }}
                />
                <Line
                  type='monotone'
                  dataKey='pulls'
                  stroke='var(--color-pulls)'
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, strokeWidth: 0 }}
                />
              </LineChart>
            </ChartContainer>
          )
        }
      </div>
    </div>
  )
}
