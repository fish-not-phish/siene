'use client'

import * as React from 'react'
import { ShieldAlertIcon } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface VulnCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface RegistryVulnVennProps {
  counts?: VulnCounts
  loading?: boolean
  className?: string
}

// ── Severity config ───────────────────────────────────────────────────────────

const SEVERITIES = [
  {
    key: 'critical' as const,
    label: 'Critical',
    color: 'oklch(0.577 0.245 27.325)',   // red-600
    textColor: 'text-red-600 dark:text-red-400',
  },
  {
    key: 'high' as const,
    label: 'High',
    color: 'oklch(0.705 0.213 47.604)',   // orange-500
    textColor: 'text-orange-500 dark:text-orange-400',
  },
  {
    key: 'medium' as const,
    label: 'Medium',
    color: 'oklch(0.795 0.184 86.047)',   // amber-400
    textColor: 'text-amber-500 dark:text-amber-400',
  },
  {
    key: 'low' as const,
    label: 'Low',
    color: 'oklch(0.623 0.214 259.815)',  // blue-500
    textColor: 'text-blue-500 dark:text-blue-400',
  },
]

// ── Bubble positions (viewBox 280×200) ────────────────────────────────────────
// Four bubbles arranged so they visually overlap: critical (top-right, largest
// when non-zero), high (left), medium (bottom-right), low (top-left, smallest).

const POSITIONS = [
  { cx: 170, cy: 80  },   // critical
  { cx: 100, cy: 120 },   // high
  { cx: 160, cy: 145 },   // medium
  { cx:  95, cy:  70 },   // low
]

// ── Bubble chart ──────────────────────────────────────────────────────────────

function VulnBubbleChart({
  counts,
  activeIndex,
  onHover,
}: {
  counts: VulnCounts
  activeIndex: number | null
  onHover: (i: number | null) => void
}) {
  const values = SEVERITIES.map(s => counts[s.key])
  const total  = values.reduce((a, b) => a + b, 0)
  const maxVal = Math.max(...values, 1)
  const maxRadius = 68

  return (
    <svg
      viewBox='0 0 280 200'
      preserveAspectRatio='xMidYMid meet'
      className='h-full w-full'
      onMouseLeave={() => onHover(null)}
    >
      {SEVERITIES.map((sev, i) => {
        const val     = values[i]
        const baseR   = Math.sqrt(val / maxVal) * maxRadius
        const isActive  = activeIndex === i
        const isDimmed  = activeIndex !== null && activeIndex !== i
        const r = isActive ? baseR * 1.08 : baseR

        // Always show a minimum circle even for zero counts so the diagram
        // still renders when there are no vulnerabilities.
        const displayR = Math.max(r, 12)

        return (
          <g
            key={sev.key}
            onMouseEnter={() => onHover(i)}
            style={{ transition: 'opacity 150ms ease-out', cursor: 'default' }}
          >
            <circle
              cx={POSITIONS[i].cx}
              cy={POSITIONS[i].cy}
              r={displayR}
              fill={sev.color}
              fillOpacity={isActive ? 0.45 : isDimmed ? 0.1 : 0.25}
              stroke={sev.color}
              strokeWidth={1}
              strokeOpacity={isActive ? 0.75 : isDimmed ? 0.15 : 0.4}
              style={{ transition: 'all 150ms ease-out' }}
            />
            {/* Count */}
            <text
              x={POSITIONS[i].cx}
              y={isActive ? POSITIONS[i].cy - 8 : POSITIONS[i].cy}
              textAnchor='middle'
              dominantBaseline='central'
              fill='currentColor'
              fontSize={val >= 1000 ? 11 : 14}
              fontWeight={600}
              style={{ opacity: isDimmed ? 0.35 : 1, transition: 'all 150ms ease-out' }}
            >
              {val.toLocaleString()}
            </text>
            {/* Label shown on hover */}
            {isActive && (
              <text
                x={POSITIONS[i].cx}
                y={POSITIONS[i].cy + 10}
                textAnchor='middle'
                dominantBaseline='central'
                fill='currentColor'
                fontSize={10}
                style={{ opacity: 0.65 }}
              >
                {sev.label}
              </text>
            )}
          </g>
        )
      })}

      {/* Zero-state label */}
      {total === 0 && (
        <text
          x={140}
          y={160}
          textAnchor='middle'
          fill='currentColor'
          fontSize={10}
          opacity={0.4}
        >
          No vulnerabilities found
        </text>
      )}
    </svg>
  )
}

// ── Exported component ────────────────────────────────────────────────────────

export function RegistryVulnVenn({ counts, loading = false, className }: RegistryVulnVennProps) {
  const [activeIndex, setActiveIndex] = React.useState<number | null>(null)

  const total = counts ? counts.critical + counts.high + counts.medium + counts.low : 0

  return (
    <div className={cn('flex min-w-0 flex-col gap-4 rounded-xl border bg-card p-4 sm:gap-5 sm:p-5', className)}>
      {/* Header */}
      <div className='space-y-1.5'>
        <p className='text-xs font-semibold tracking-[0.16em] text-muted-foreground uppercase'>
          Vulnerability Exposure
        </p>
        <div className='flex flex-wrap items-end gap-3'>
          {loading
            ? <Skeleton className='h-10 w-24' />
            : (
              <>
                <span className='text-4xl leading-none font-semibold tabular-nums'>
                  {total.toLocaleString()}
                </span>
                <span className='pb-1 text-sm text-muted-foreground'>
                  total CVEs detected
                </span>
              </>
            )
          }
        </div>
      </div>

      {/* Bubble diagram */}
      <div className='h-[200px] w-full min-w-0'>
        {loading
          ? <Skeleton className='h-full w-full rounded-lg' />
          : counts
            ? (
              <VulnBubbleChart
                counts={counts}
                activeIndex={activeIndex}
                onHover={setActiveIndex}
              />
            )
            : (
              <div className='flex h-full items-center justify-center'>
                <div className='flex flex-col items-center gap-2 text-muted-foreground'>
                  <ShieldAlertIcon className='size-8 opacity-30' />
                  <p className='text-xs'>No scan data available</p>
                </div>
              </div>
            )
        }
      </div>

      {/* Legend rows */}
      {!loading && counts && (
        <div className='flex flex-col gap-2.5'
          onMouseLeave={() => setActiveIndex(null)}
        >
          {SEVERITIES.map((sev, i) => {
            const val      = counts[sev.key]
            const isActive = activeIndex === i
            const isDimmed = activeIndex !== null && activeIndex !== i
            return (
              <div
                key={sev.key}
                className='flex items-center justify-between'
                style={{ opacity: isDimmed ? 0.4 : 1, transition: 'opacity 150ms ease-out' }}
                onMouseEnter={() => setActiveIndex(i)}
              >
                <div className='flex items-center gap-2'>
                  <span
                    className='inline-block size-2 rounded-full'
                    style={{ backgroundColor: sev.color }}
                  />
                  <span className={cn(
                    'text-sm text-muted-foreground transition-all',
                    isActive && 'font-medium text-foreground',
                  )}>
                    {sev.label}
                  </span>
                </div>
                <span className={cn('text-sm font-semibold tabular-nums', sev.textColor)}>
                  {val.toLocaleString()}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
