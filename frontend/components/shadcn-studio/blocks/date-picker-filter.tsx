'use client'

import { format, parseISO } from 'date-fns'
import { CalendarIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Calendar } from '@/components/ui/calendar'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { cn } from '@/lib/utils'

interface DatePickerFilterProps {
  label: string
  value: string          // YYYY-MM-DD or ''
  onChange: (v: string) => void
  min?: string           // YYYY-MM-DD — disables days before this
  max?: string           // YYYY-MM-DD — disables days after this
}

export function DatePickerFilter({ label, value, onChange, min, max }: DatePickerFilterProps) {
  const selected = value ? parseISO(value) : undefined
  const minDate  = min ? parseISO(min) : undefined
  const maxDate  = max ? parseISO(max) : undefined

  return (
    <div className='flex items-center gap-1.5'>
      <span className='text-xs text-muted-foreground'>{label}</span>
      <Popover>
        <PopoverTrigger asChild>
          <Button
            variant='outline'
            size='sm'
            className={cn(
              'h-8 w-32 justify-start gap-1.5 text-sm font-normal',
              !selected && 'text-muted-foreground',
            )}
          >
            <CalendarIcon className='size-3.5 shrink-0' />
            {selected ? format(selected, 'MMM d, yyyy') : <span>Pick date</span>}
          </Button>
        </PopoverTrigger>
        <PopoverContent className='w-auto p-0' align='start'>
          <Calendar
            mode='single'
            selected={selected}
            onSelect={(day) => onChange(day ? format(day, 'yyyy-MM-dd') : '')}
            disabled={(day) => {
              if (minDate && day < minDate) return true
              if (maxDate && day > maxDate) return true
              return false
            }}
            captionLayout='dropdown'
            initialFocus
          />
          {selected && (
            <div className='border-t px-3 py-2'>
              <Button
                variant='ghost'
                size='sm'
                className='h-7 w-full text-xs text-muted-foreground'
                onClick={() => onChange('')}
              >
                Clear date
              </Button>
            </div>
          )}
        </PopoverContent>
      </Popover>
    </div>
  )
}
