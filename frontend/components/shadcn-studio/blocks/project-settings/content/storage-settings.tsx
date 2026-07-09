'use client'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Progress } from '@/components/ui/progress'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent } from '@/components/ui/card'

function fmt(bytes: number) {
  if (bytes === 0) return '0 B'
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

export interface StorageSettingsProps {
  usedBytes: number
  quotaBytes: number | null
  limited: boolean
  quotaGb: string
  saving: boolean
  diskFreeBytes?: number | null
  onLimitedChange: (v: boolean) => void
  onQuotaGbChange: (v: string) => void
  onSave: () => void
}

const StorageSettings = ({
  usedBytes,
  quotaBytes,
  limited,
  quotaGb,
  saving,
  diskFreeBytes,
  onLimitedChange,
  onQuotaGbChange,
  onSave,
}: StorageSettingsProps) => {
  const pct = quotaBytes ? Math.min(Math.round((usedBytes / quotaBytes) * 100), 100) : 0
  const over = quotaBytes !== null && usedBytes > quotaBytes

  return (
    <div className='grid grid-cols-1 gap-10 lg:grid-cols-3'>
      <div className='flex flex-col space-y-1'>
        <h3 className='font-semibold'>Storage</h3>
        <p className='text-muted-foreground text-sm'>
          Monitor usage and set a storage quota for this project. Pushes that would
          exceed the limit will be rejected.
        </p>
      </div>

      <div className='space-y-6 lg:col-span-2'>
        {/* Usage card */}
        <Card>
          <CardContent className='space-y-3 pt-5'>
            <div className='flex items-baseline justify-between'>
              <p className='text-sm font-medium'>Storage usage</p>
              <p className='text-muted-foreground text-xs'>
                {fmt(usedBytes)}
                {quotaBytes !== null ? ` / ${fmt(quotaBytes)}` : ' — no quota set'}
              </p>
            </div>
            {quotaBytes !== null ? (
              <>
                <Progress
                  value={pct}
                  className={`h-2 ${over ? '[&>div]:bg-destructive' : ''}`}
                />
                <p className={`text-xs ${over ? 'font-medium text-destructive' : 'text-muted-foreground'}`}>
                  {over ? `Over quota by ${fmt(usedBytes - quotaBytes)}` : `${pct}% used`}
                </p>
              </>
            ) : (
              <p className='text-xs text-muted-foreground'>No limit enforced.</p>
            )}
          </CardContent>
        </Card>

        {/* Quota toggle + input */}
        <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
          <div className='space-y-0.5'>
            <Label htmlFor='quota-toggle' className='cursor-pointer text-sm font-medium'>
              Enable quota
            </Label>
            <p className='text-muted-foreground text-xs'>
              Restrict total storage for this project.
            </p>
          </div>
          <Switch id='quota-toggle' checked={limited} onCheckedChange={onLimitedChange} />
        </div>

        <div
          className={`space-y-1.5 transition-opacity ${
            limited ? 'opacity-100' : 'pointer-events-none opacity-40'
          }`}
        >
          <Label htmlFor='quota-gb'>Limit (GB)</Label>
          <div className='flex items-center gap-2'>
            <Input
              id='quota-gb'
              type='number'
              min='0.1'
              step='0.5'
              className='w-36'
              value={quotaGb}
              onChange={(e) => onQuotaGbChange(e.target.value)}
              disabled={!limited}
              placeholder='e.g. 10'
            />
            <span className='text-muted-foreground text-sm'>GB</span>
          </div>
          {diskFreeBytes != null && diskFreeBytes > 0 && (
            <p className='text-xs text-muted-foreground'>
              {fmt(diskFreeBytes)} free on registry volume
              {limited ? '' : (
                <button
                  type='button'
                  className='ml-1.5 underline underline-offset-2 hover:text-foreground transition-colors'
                  onClick={() => onQuotaGbChange(String(Math.floor(diskFreeBytes / 1024 ** 3)))}
                >
                  Use as limit
                </button>
              )}
            </p>
          )}
        </div>

        <div className='flex justify-end'>
          <Button type='button' disabled={saving} onClick={onSave} className='max-sm:w-full'>
            {saving ? 'Saving…' : 'Save quota'}
          </Button>
        </div>
      </div>
    </div>
  )
}

export default StorageSettings
