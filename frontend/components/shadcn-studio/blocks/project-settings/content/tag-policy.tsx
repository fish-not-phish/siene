'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { PlusIcon, EllipsisVerticalIcon, TagIcon, FlaskConicalIcon, RefreshCwIcon, Trash2Icon, CheckIcon } from 'lucide-react'
import type { TagRetentionRule, RetentionPreviewResult } from '@/services/registry'
import { previewRetentionRule } from '@/services/registry'

// ── Props ─────────────────────────────────────────────────────────────────────

export interface TagPolicyProps {
  projectName: string
  csrfToken: string

  tagImmutability: boolean
  onTagImmutabilityChange: (v: boolean) => void

  retentionRules: TagRetentionRule[]
  onRetentionRulesChange: (rules: TagRetentionRule[]) => void

  saving: boolean
  onSave: () => void
}

// ── Retention rule dialog ─────────────────────────────────────────────────────

interface RuleDialogProps {
  projectName: string
  csrfToken: string
  initial?: TagRetentionRule
  onConfirm: (rule: TagRetentionRule) => void
  /** For add mode: a trigger element. For edit mode: omit and control `open` externally. */
  trigger?: React.ReactNode
  open?: boolean
  onOpenChange?: (o: boolean) => void
}

function RuleDialog({ projectName, csrfToken, initial, onConfirm, trigger, open: controlledOpen, onOpenChange }: RuleDialogProps) {
  const blank: TagRetentionRule = { match: '**', keep_count: null, keep_days: null }
  const [internalOpen, setInternalOpen] = useState(false)
  const [form, setForm] = useState<TagRetentionRule>(initial ?? blank)

  const isControlled = controlledOpen !== undefined
  const open = isControlled ? controlledOpen : internalOpen

  const handleOpenChange = (o: boolean) => {
    if (!isControlled) setInternalOpen(o)
    onOpenChange?.(o)
    if (o) setForm(initial ?? blank)
    // reset preview when dialog closes
    if (!o) setPreview(null)
  }

  const [preview, setPreview] = useState<RetentionPreviewResult | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)

  const valid =
    form.match.trim() !== '' &&
    (form.keep_count !== null || form.keep_days !== null)

  const handleConfirm = () => {
    if (!valid) return
    onConfirm({
      match: form.match.trim(),
      keep_count: form.keep_count !== null ? Number(form.keep_count) : null,
      keep_days: form.keep_days !== null ? Number(form.keep_days) : null,
    })
    handleOpenChange(false)
  }

  const handlePreview = async () => {
    if (!valid) return
    setPreviewing(true)
    setPreview(null)
    setPreviewError(null)
    try {
      const result = await previewRetentionRule(
        projectName,
        {
          match: form.match.trim(),
          keep_count: form.keep_count !== null ? Number(form.keep_count) : null,
          keep_days: form.keep_days !== null ? Number(form.keep_days) : null,
        },
        csrfToken
      )
      setPreview(result)
    } catch (e: unknown) {
      setPreviewError(e instanceof Error ? e.message : 'Preview failed')
    } finally {
      setPreviewing(false)
    }
  }

  const dialogContent = (
    <DialogContent className='sm:max-w-lg flex flex-col max-h-[90vh]'>
      <DialogHeader className='space-y-1 shrink-0'>
        <DialogTitle>{initial ? 'Edit retention rule' : 'New retention rule'}</DialogTitle>
        <DialogDescription>
          Tags matching the pattern will be kept according to the criteria below. At least one
          criterion (count or days) is required. Use <strong>Test rule</strong> to preview which
          tags would be deleted before saving.
        </DialogDescription>
      </DialogHeader>

      <div className='space-y-4 overflow-y-auto flex-1 pr-1 min-h-0'>
        {/* Tag glob pattern */}
        <div className='space-y-2'>
          <Label htmlFor='rule-match'>
            Tag pattern<span className='text-destructive'>*</span>
          </Label>
          <Input
            id='rule-match'
            value={form.match}
            onChange={(e) => { setForm({ ...form, match: e.target.value }); setPreview(null) }}
            placeholder='e.g. v* or release-** or **'
          />
          <p className='text-muted-foreground text-xs'>
            Glob pattern — use <span className='font-mono'>**</span> to match all tags,{' '}
            <span className='font-mono'>v*</span> for versioned tags, etc.
          </p>
        </div>

        {/* Keep count */}
        <div className='space-y-2'>
          <Label htmlFor='rule-count'>Keep most recent (count)</Label>
          <div className='flex items-center gap-2'>
            <Input
              id='rule-count'
              type='number'
              min='1'
              step='1'
              className='w-28'
              value={form.keep_count ?? ''}
              onChange={(e) => {
                setForm({ ...form, keep_count: e.target.value === '' ? null : Number(e.target.value) })
                setPreview(null)
              }}
              placeholder='e.g. 10'
            />
            <span className='text-muted-foreground text-sm'>tags</span>
          </div>
          <p className='text-muted-foreground text-xs'>
            Retain the N most recently pushed matching tags. Leave blank to not enforce a count limit.
          </p>
        </div>

        {/* Keep days */}
        <div className='space-y-2'>
          <Label htmlFor='rule-days'>Keep tags pushed within (days)</Label>
          <div className='flex items-center gap-2'>
            <Input
              id='rule-days'
              type='number'
              min='1'
              step='1'
              className='w-28'
              value={form.keep_days ?? ''}
              onChange={(e) => {
                setForm({ ...form, keep_days: e.target.value === '' ? null : Number(e.target.value) })
                setPreview(null)
              }}
              placeholder='e.g. 30'
            />
            <span className='text-muted-foreground text-sm'>days</span>
          </div>
          <p className='text-muted-foreground text-xs'>
            Retain matching tags pushed within the last N days. Leave blank to not enforce a time limit.
          </p>
        </div>

        {!valid && (form.keep_count === null && form.keep_days === null) && form.match.trim() !== '' && (
          <p className='text-xs text-destructive'>Set at least one of: count or days.</p>
        )}

        {/* ── Preview results ── */}
        {(preview || previewing || previewError) && (
          <div className='rounded-lg border bg-muted/40 p-3 space-y-2 overflow-hidden'>
            <p className='text-xs font-semibold text-muted-foreground uppercase tracking-wide flex items-center gap-1.5'>
              <FlaskConicalIcon className='size-3.5' />
              Dry-run result
            </p>

            {previewing && (
              <p className='text-xs text-muted-foreground flex items-center gap-1.5'>
                <RefreshCwIcon className='size-3 animate-spin' /> Running…
              </p>
            )}

            {previewError && (
              <p className='text-xs text-destructive'>{previewError}</p>
            )}

            {preview && !previewing && (
              <>
                <div className='flex items-center gap-3 text-xs'>
                  <span className='text-muted-foreground'>
                    <span className='font-medium text-foreground'>{preview.total_matched}</span> tag{preview.total_matched !== 1 ? 's' : ''} matched
                  </span>
                  <span className='text-muted-foreground'>·</span>
                  {preview.total_deleted > 0 ? (
                    <span className='font-medium text-destructive flex items-center gap-1'>
                      <Trash2Icon className='size-3' />
                      {preview.total_deleted} would be deleted
                    </span>
                  ) : (
                    <span className='font-medium text-green-600 flex items-center gap-1'>
                      <CheckIcon className='size-3' />
                      No tags would be deleted
                    </span>
                  )}
                </div>

                {preview.repos.length > 0 && (
                  <ScrollArea className='h-36'>
                    <div className='space-y-1 pr-2'>
                      {preview.repos.map((r) => [
                        ...r.kept.map((t) => (
                          <Badge key={`${r.repo}:${t}:kept`} variant='secondary' className='flex w-full justify-start text-xs font-mono font-normal'>
                            <span className='text-muted-foreground'>{r.repo}:</span>{t}
                          </Badge>
                        )),
                        ...r.deleted.map((t) => (
                          <Badge key={`${r.repo}:${t}:deleted`} variant='destructive' className='flex w-full justify-start text-xs font-mono font-normal opacity-80'>
                            <span className='opacity-75'>{r.repo}:</span>{t}
                          </Badge>
                        )),
                      ])}
                    </div>
                  </ScrollArea>
                )}

                {preview.total_matched === 0 && (
                  <p className='text-xs text-muted-foreground'>No tags match this pattern in any repository.</p>
                )}
              </>
            )}
          </div>
        )}
      </div>

      <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-between'>
        <Button
          variant='outline'
          onClick={handlePreview}
          disabled={!valid || previewing}
          className='gap-1.5'
        >
          {previewing
            ? <><RefreshCwIcon className='size-3.5 animate-spin' /> Testing…</>
            : <><FlaskConicalIcon className='size-3.5' /> Test rule</>
          }
        </Button>
      </div>

      <div className='flex flex-col-reverse gap-3 sm:flex-row shrink-0 pt-2'>
        {trigger ? (
          <DialogClose asChild>
            <Button variant='outline'>Cancel</Button>
          </DialogClose>
        ) : (
          <Button variant='outline' onClick={() => handleOpenChange(false)}>Cancel</Button>
        )}
        <Button onClick={handleConfirm} disabled={!valid}>
          {initial ? 'Update rule' : 'Add rule'}
        </Button>
      </div>
    </DialogContent>
  )

  if (trigger) {
    return (
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogTrigger asChild>{trigger}</DialogTrigger>
        {dialogContent}
      </Dialog>
    )
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      {dialogContent}
    </Dialog>
  )
}

// ── Rule row summary ──────────────────────────────────────────────────────────

function ruleLabel(rule: TagRetentionRule): string {
  const parts: string[] = []
  if (rule.keep_count !== null) parts.push(`keep ${rule.keep_count} most recent`)
  if (rule.keep_days !== null) parts.push(`pushed within ${rule.keep_days}d`)
  return parts.join(' · ')
}

// ── Main component ────────────────────────────────────────────────────────────

const TagPolicy = ({
  projectName,
  csrfToken,
  tagImmutability,
  onTagImmutabilityChange,
  retentionRules,
  onRetentionRulesChange,
  saving,
  onSave,
}: TagPolicyProps) => {
  const [editIdx, setEditIdx] = useState<number | null>(null)

  const addRule = (rule: TagRetentionRule) => {
    onRetentionRulesChange([...retentionRules, rule])
  }

  const updateRule = (idx: number, rule: TagRetentionRule) => {
    const next = [...retentionRules]
    next[idx] = rule
    onRetentionRulesChange(next)
  }

  const removeRule = (idx: number) => {
    onRetentionRulesChange(retentionRules.filter((_, i) => i !== idx))
  }

  return (
    <div className='grid grid-cols-1 gap-10 lg:grid-cols-3'>
      <div className='flex flex-col space-y-1'>
        <h3 className='font-semibold'>Tag Policies</h3>
        <p className='text-muted-foreground text-sm'>
          Configure tag immutability and retention rules to keep your registry tidy.
        </p>
      </div>

      <div className='space-y-6 lg:col-span-2'>

        {/* Immutability */}
        <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Immutability</p>
        <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
          <div className='space-y-0.5 pr-4'>
            <Label htmlFor='tag-immutability' className='cursor-pointer text-sm font-medium'>
              Immutable tags
            </Label>
            <p className='text-muted-foreground text-xs'>
              Prevent existing tags from being overwritten. Pushes to an existing tag name will be rejected.
            </p>
          </div>
          <Switch
            id='tag-immutability'
            checked={tagImmutability}
            onCheckedChange={onTagImmutabilityChange}
          />
        </div>

        <Separator />

        {/* Retention rules */}
        <div className='flex items-center justify-between'>
          <p className='text-xs font-medium uppercase tracking-wider text-muted-foreground'>Tag Retention</p>
          <RuleDialog
            projectName={projectName}
            csrfToken={csrfToken}
            onConfirm={addRule}
            trigger={
              <Button variant='outline' size='sm'>
                <PlusIcon />
                Add rule
              </Button>
            }
          />
        </div>

        <p className='text-muted-foreground text-xs'>
          Retention rules are applied during garbage collection. Tags not matched by any rule are kept.
          Rules are evaluated in order — the first match wins.
        </p>

        {retentionRules.length === 0 ? (
          <div className='flex flex-col items-center gap-2 rounded-lg border border-dashed py-10 text-center text-muted-foreground'>
            <TagIcon className='size-8 opacity-30' />
            <p className='text-sm'>No retention rules. All tags will be kept.</p>
          </div>
        ) : (
          <div>
            {retentionRules.map((rule, idx) => (
              <div key={idx}>
                <div className='flex items-center justify-between gap-4 py-1'>
                  <div className='flex min-w-0 items-center gap-3'>
                    <div className='flex size-8 shrink-0 items-center justify-center rounded-full border'>
                      <TagIcon className='size-3.5 text-muted-foreground' />
                    </div>
                    <div className='min-w-0'>
                      <p className='font-mono text-sm font-medium'>{rule.match}</p>
                      <p className='text-xs text-muted-foreground'>{ruleLabel(rule)}</p>
                    </div>
                  </div>

                  {/* Edit + delete */}
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant='ghost' size='icon' className='rounded-full'>
                        <EllipsisVerticalIcon />
                        <span className='sr-only'>Rule actions</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent className='w-24' align='end'>
                      <DropdownMenuGroup>
                        <DropdownMenuItem onClick={() => setEditIdx(idx)}>Edit</DropdownMenuItem>
                        <DropdownMenuItem
                          className='text-destructive transition-colors duration-200 hover:bg-destructive/10! hover:text-destructive!'
                          onClick={() => removeRule(idx)}
                        >
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuGroup>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>

                {idx !== retentionRules.length - 1 && <Separator className='my-2' />}
              </div>
            ))}
          </div>
        )}

        {/* Edit dialog */}
        {editIdx !== null && retentionRules[editIdx] && (
          <RuleDialog
            projectName={projectName}
            csrfToken={csrfToken}
            initial={retentionRules[editIdx]}
            open={true}
            onOpenChange={(o) => { if (!o) setEditIdx(null) }}
            onConfirm={(rule) => {
              updateRule(editIdx, rule)
              setEditIdx(null)
            }}
          />
        )}

        <div className='flex justify-end pt-2'>
          <Button type='button' disabled={saving} onClick={onSave} className='max-sm:w-full'>
            {saving ? 'Saving…' : 'Save tag policy'}
          </Button>
        </div>
      </div>
    </div>
  )
}

export default TagPolicy
