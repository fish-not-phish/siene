'use client'

import * as React from 'react'
import { Cell, Pie, PieChart } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

// ── Single ring ───────────────────────────────────────────────────────────────

interface MiniRingProps {
  total: number
  scanned: number
  label: string
  color: string
}

function MiniRing({ total, scanned, label, color }: MiniRingProps) {
  const pct = total > 0 ? Math.round((scanned / total) * 100) : 0
  const unscanned = Math.max(0, total - scanned)
  const emptyColor = 'color-mix(in oklch, var(--foreground) 7%, var(--background))'

  const ringData = total === 0
    ? [{ value: 1, empty: true }]
    : [
        { value: scanned,   empty: false },
        { value: unscanned, empty: true  },
      ]

  return (
    <div className='flex flex-col items-center gap-1.5'>
      <div className='relative'>
        <PieChart width={72} height={72}>
          <Pie
            data={ringData}
            cx={33}
            cy={33}
            innerRadius={23}
            outerRadius={34}
            paddingAngle={total === 0 ? 0 : 2}
            dataKey='value'
            startAngle={90}
            endAngle={-270}
            strokeWidth={0}
          >
            {ringData.map((entry, i) => (
              <Cell key={i} fill={entry.empty ? emptyColor : color} />
            ))}
          </Pie>
        </PieChart>
        <div className='pointer-events-none absolute inset-0 flex flex-col items-center justify-center'>
          <span className='text-[13px] font-semibold tabular-nums leading-none'>{pct}%</span>
        </div>
      </div>
      <p className='text-[11px] text-muted-foreground text-center leading-tight'>{label}</p>
      <p className='text-xs font-medium tabular-nums'>{scanned.toLocaleString()} / {total.toLocaleString()}</p>
    </div>
  )
}

// ── Public component ──────────────────────────────────────────────────────────

export interface RegistryScanCoverageProps {
  /** Vuln scan counts */
  total?: number
  scanned?: number
  /** Secret scan counts */
  secretTotal?: number
  secretScanned?: number
  /** Misconfig scan counts */
  misconfigTotal?: number
  misconfigScanned?: number
  loading?: boolean
  className?: string
}

export function RegistryScanCoverage({
  total = 0,
  scanned = 0,
  secretTotal,
  secretScanned,
  misconfigTotal,
  misconfigScanned,
  loading = false,
  className,
}: RegistryScanCoverageProps) {
  const showExtended = secretTotal !== undefined || misconfigTotal !== undefined

  // For the legacy single-ring view (no extra props passed)
  const pct = total > 0 ? Math.round((scanned / total) * 100) : 0
  const unscanned = Math.max(0, total - scanned)
  const coverageColor = pct >= 80 ? 'oklch(0.6 0.17 162)' : pct >= 50 ? 'oklch(0.72 0.18 55)' : 'oklch(0.62 0.22 27)'
  const emptyColor = 'color-mix(in oklch, var(--foreground) 7%, var(--background))'

  const ringData = total === 0
    ? [{ value: 1, empty: true }]
    : [
        { value: scanned,   empty: false },
        { value: unscanned, empty: true  },
      ]

  return (
    <div className={cn('flex flex-col gap-4 rounded-xl border bg-card p-4 sm:p-5', className)}>
      <div className='space-y-0.5'>
        <p className='text-xs font-semibold tracking-[0.16em] text-muted-foreground uppercase'>Scan Coverage</p>
        <p className='text-xs text-muted-foreground'>
          {showExtended ? 'Tags scanned by type' : 'Tags with completed vulnerability scans'}
        </p>
      </div>

      {loading ? (
        showExtended ? (
          <div className='flex items-center justify-around gap-2'>
            {[0, 1, 2].map(i => (
              <div key={i} className='flex flex-col items-center gap-1.5'>
                <Skeleton className='size-[72px] rounded-full' />
                <Skeleton className='h-3 w-12' />
                <Skeleton className='h-3 w-10' />
              </div>
            ))}
          </div>
        ) : (
          <div className='flex items-center gap-5'>
            <Skeleton className='size-[100px] rounded-full shrink-0' />
            <div className='flex-1 space-y-3'>
              <Skeleton className='h-5 w-16' />
              <Skeleton className='h-3.5 w-28' />
              <Skeleton className='h-3.5 w-24' />
            </div>
          </div>
        )
      ) : showExtended ? (
        // ── Three-ring layout ─────────────────────────────────────────────────
        <div className='flex items-start justify-around gap-2'>
          <MiniRing
            total={total}
            scanned={scanned}
            label='Vuln'
            color={pct >= 80 ? 'oklch(0.6 0.17 162)' : pct >= 50 ? 'oklch(0.72 0.18 55)' : 'oklch(0.62 0.22 27)'}
          />
          <MiniRing
            total={secretTotal ?? 0}
            scanned={secretScanned ?? 0}
            label='Secrets'
            color={
              (secretTotal ?? 0) === 0 ? 'oklch(0.62 0.22 27)' :
              Math.round(((secretScanned ?? 0) / (secretTotal ?? 1)) * 100) >= 80 ? 'oklch(0.6 0.17 162)' :
              Math.round(((secretScanned ?? 0) / (secretTotal ?? 1)) * 100) >= 50 ? 'oklch(0.72 0.18 55)' :
              'oklch(0.62 0.22 27)'
            }
          />
          <MiniRing
            total={misconfigTotal ?? 0}
            scanned={misconfigScanned ?? 0}
            label='Misconfigs'
            color={
              (misconfigTotal ?? 0) === 0 ? 'oklch(0.62 0.22 27)' :
              Math.round(((misconfigScanned ?? 0) / (misconfigTotal ?? 1)) * 100) >= 80 ? 'oklch(0.6 0.17 162)' :
              Math.round(((misconfigScanned ?? 0) / (misconfigTotal ?? 1)) * 100) >= 50 ? 'oklch(0.72 0.18 55)' :
              'oklch(0.62 0.22 27)'
            }
          />
        </div>
      ) : (
        // ── Legacy single-ring layout ─────────────────────────────────────────
        <div className='flex items-center gap-5'>
          <div className='relative shrink-0'>
            <PieChart width={100} height={100}>
              <Pie
                data={ringData}
                cx={46}
                cy={46}
                innerRadius={32}
                outerRadius={46}
                paddingAngle={total === 0 ? 0 : 2}
                dataKey='value'
                startAngle={90}
                endAngle={-270}
                strokeWidth={0}
              >
                {ringData.map((entry, i) => (
                  <Cell key={i} fill={entry.empty ? emptyColor : coverageColor} />
                ))}
              </Pie>
            </PieChart>
            <div className='pointer-events-none absolute inset-0 flex flex-col items-center justify-center'>
              <span className='text-lg font-semibold tabular-nums leading-none'>{pct}%</span>
            </div>
          </div>
          <div className='space-y-2'>
            <div>
              <p className='text-2xl font-semibold tabular-nums leading-none'>{scanned.toLocaleString()}</p>
              <p className='mt-0.5 text-xs text-muted-foreground'>scanned</p>
            </div>
            <div className='text-xs text-muted-foreground space-y-0.5'>
              <p>{total.toLocaleString()} total tags</p>
              {total > 0 && unscanned > 0 && (
                <p className='text-amber-600 dark:text-amber-400'>{unscanned.toLocaleString()} unscanned</p>
              )}
              {total > 0 && unscanned === 0 && (
                <p className='text-emerald-600 dark:text-emerald-400'>All tags scanned</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
