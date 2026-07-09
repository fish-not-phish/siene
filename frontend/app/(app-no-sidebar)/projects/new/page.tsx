'use client'

import { useState, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { motion } from 'motion/react'
import { ChevronLeft, Plus, BoxesIcon } from 'lucide-react'
import Link from 'next/link'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { cn } from '@/lib/utils'
import { useAuthContext } from '@/store/AuthContext'
import { useProjects } from '@/providers/ProjectsContext'
import { createProject, checkProjectNameAvailable } from '@/services/projects'

// ── Registry illustration (reused from onboarding) ───────────────────────────

function RegistryIllustration({
  projectName,
  variant = 'zoomed-out',
}: {
  projectName?: string
  variant?: 'zoomed-in' | 'zoomed-out'
}) {
  const displayName = projectName || 'my-project'

  return (
    <motion.div
      style={{ transformOrigin: '-20% -10%' }}
      animate={{ scale: variant === 'zoomed-in' ? 1.4 : 1 }}
      transition={{ type: 'spring', stiffness: 300, damping: 40 }}
      className='flex h-full w-5xl overflow-hidden rounded-xl border'
    >
      <div className='h-full flex-[2/7] shrink-0 overflow-hidden bg-muted'>
        <div className='flex items-center justify-between gap-2 border-b p-4'>
          <div className='flex items-center gap-2 overflow-hidden'>
            <div className='flex size-8 shrink-0 items-center justify-center rounded-md bg-primary/10'>
              <BoxesIcon className='size-4 text-primary' />
            </div>
            <p className='truncate font-semibold'>{displayName}</p>
          </div>
          <ChevronLeft className='size-4' />
        </div>
        <ul className='space-y-2 p-4'>
          {['Repositories', 'Members', 'Robot Accounts', 'Settings'].map((label) => (
            <li
              key={label}
              className='flex h-9 items-center rounded-lg border bg-background/50 px-3 text-xs text-muted-foreground'
            >
              {label}
            </li>
          ))}
          {Array.from({ length: 5 }).map((_, i) => (
            <li key={i} className='h-9 rounded-lg border bg-background/50' />
          ))}
        </ul>
      </div>
      <div className='flex flex-[5/7] shrink-0 flex-col justify-between p-4'>
        <div className='space-y-4'>
          <div className='flex items-center justify-between gap-4'>
            <div className='flex items-center gap-4'>
              <div className='size-9 rounded-lg border bg-muted/50' />
              <div className='h-9 w-48 rounded-lg border bg-muted/50' />
            </div>
            <Button variant='outline' size='sm'>
              <span className='block h-4 w-16 rounded bg-muted/50' />
              <Plus className='size-4' />
            </Button>
          </div>
          <div className='overflow-hidden rounded-lg border'>
            <Table>
              <TableHeader>
                <TableRow className='bg-muted/50'>
                  {['Repository', 'Tags', 'Pulls', 'Last Push'].map((h) => (
                    <TableHead key={h} className='h-9 border-r text-xs last:border-r-0'>{h}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array.from({ length: 8 }).map((_, rowIndex) => (
                  <TableRow key={rowIndex} className='even:bg-muted/20'>
                    {Array.from({ length: 4 }).map((_, colIndex) => (
                      <TableCell key={colIndex} className='h-9 border-r last:border-r-0' />
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
        <div className='flex items-center gap-2'>
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className='size-9 rounded-lg border bg-muted/50' />
          ))}
        </div>
      </div>
    </motion.div>
  )
}

// ── Validation ────────────────────────────────────────────────────────────────

const SLUG_REGEX = /^[a-z0-9]+(?:[_-][a-z0-9]+)*$/

function validateName(value: string): string | null {
  if (!value) return null
  if (!/^[a-z0-9]/.test(value)) return 'Must start with a lowercase letter or digit'
  if (!SLUG_REGEX.test(value)) return 'Only lowercase letters, numbers, hyphens and underscores'
  if (value.length < 2) return 'Must be at least 2 characters'
  if (value.length > 64) return 'Must be 64 characters or fewer'
  return null
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function NewProjectPage() {
  const router = useRouter()
  const { user } = useAuthContext()
  const { refresh } = useProjects()

  const [name, setName] = useState('')
  const [isPublic, setIsPublic] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [availabilityError, setAvailabilityError] = useState<string | null>(null)
  const [isChecking, setIsChecking] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '')
    setName(raw)
    setAvailabilityError(null)

    const err = validateName(raw)
    setValidationError(err)

    if (debounceRef.current) clearTimeout(debounceRef.current)
    if (!err && raw.length >= 2) {
      setIsChecking(true)
      debounceRef.current = setTimeout(async () => {
        try {
          const available = await checkProjectNameAvailable(raw)
          setAvailabilityError(available ? null : 'A project with this name already exists')
        } catch {
          // ignore network errors during check
        } finally {
          setIsChecking(false)
        }
      }, 400)
    } else {
      setIsChecking(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name || validationError || availabilityError || isChecking) return

    setIsSubmitting(true)
    try {
      await createProject({ name, public: isPublic }, user.csrfToken)
      refresh()
      router.push(`/projects/${name}/repositories`)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create project'
      setAvailabilityError(message)
    } finally {
      setIsSubmitting(false)
    }
  }

  const hasError = !!(validationError || availabilityError)
  const canSubmit = name.length >= 2 && !hasError && !isChecking && !isSubmitting

  return (
    <>
      {/* Header */}
      <header className='sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-6 py-3 backdrop-blur'>
        <Button variant='ghost' size='icon-sm' asChild>
          <Link href='/projects'>
            <ChevronLeft className='size-4' />
          </Link>
        </Button>
        <span className='font-semibold text-sm'>New Project</span>
      </header>

      {/* Body — same two-column layout as onboarding */}
      <main className='flex flex-1 items-start'>
        <div className='flex w-full flex-col-reverse gap-10 md:min-h-[calc(100dvh-3.5rem)] md:flex-row'>

          {/* Left — form */}
          <div className='flex flex-1 justify-center px-8 py-10 md:py-20 lg:justify-start lg:pl-16'>
            <div className='flex h-full w-full max-w-sm flex-col gap-6'>
              <div>
                <h2 className='text-2xl font-semibold tracking-tight'>Create a project</h2>
                <p className='mt-1 text-sm text-muted-foreground'>
                  A project namespaces all your repositories under one access policy.
                </p>
              </div>

              <form onSubmit={handleSubmit} className='flex flex-col gap-6'>
                {/* Name */}
                <div className='space-y-2'>
                  <Label htmlFor='project-name'>Project name</Label>
                  <Input
                    id='project-name'
                    placeholder='my-project'
                    value={name}
                    onChange={handleNameChange}
                    autoComplete='off'
                    autoFocus
                    aria-invalid={hasError}
                    className={cn(hasError && 'border-destructive focus-visible:ring-destructive/20')}
                  />
                  <div className='min-h-5 text-xs'>
                    {validationError && (
                      <p className='text-destructive'>{validationError}</p>
                    )}
                    {!validationError && availabilityError && (
                      <p className='text-destructive'>{availabilityError}</p>
                    )}
                    {!validationError && !availabilityError && isChecking && (
                      <p className='text-muted-foreground'>Checking availability…</p>
                    )}
                    {!validationError && !availabilityError && !isChecking && name.length >= 2 && (
                      <p className='text-green-600 dark:text-green-400'>Name is available</p>
                    )}
                    {!name && (
                      <p className='text-muted-foreground'>
                        Lowercase letters, numbers, hyphens and underscores only
                      </p>
                    )}
                  </div>
                </div>

                {/* Visibility */}
                <div className='flex items-center justify-between rounded-md border px-4 py-3'>
                  <div>
                    <p className='text-sm font-medium'>Public project</p>
                    <p className='text-xs text-muted-foreground'>
                      Allow anonymous pulls without authentication.
                    </p>
                  </div>
                  <Switch checked={isPublic} onCheckedChange={setIsPublic} />
                </div>

                <div className='flex gap-3'>
                  <Button type='button' variant='outline' className='flex-1' asChild>
                    <Link href='/projects'>Cancel</Link>
                  </Button>
                  <Button type='submit' className='flex-1' disabled={!canSubmit}>
                    {isSubmitting ? 'Creating…' : 'Create project'}
                  </Button>
                </div>
              </form>
            </div>
          </div>

          {/* Right — illustration */}
          <div className='hidden flex-1 overflow-hidden bg-gradient-to-b from-background to-muted pt-10 md:pt-20 lg:block'>
            <RegistryIllustration
              projectName={name || undefined}
              variant={name.length >= 2 && !hasError ? 'zoomed-in' : 'zoomed-out'}
            />
          </div>
        </div>
      </main>
    </>
  )
}
