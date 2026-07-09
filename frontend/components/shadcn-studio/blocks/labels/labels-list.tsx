'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
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
import { PlusIcon, EllipsisVerticalIcon, TagIcon } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface LabelRow {
  id: number
  name: string
  description: string
  color: string
}

export interface LabelsListProps {
  labels: LabelRow[]
  loading: boolean
  onCreate: (data: { name: string; description: string; color: string }) => Promise<void>
  onUpdate: (id: number, data: { name: string; description: string; color: string }) => Promise<void>
  onDelete: (id: number) => Promise<void>
}

// ── Color picker ──────────────────────────────────────────────────────────────

const PRESET_COLORS = [
  '#6366f1', '#8b5cf6', '#ec4899', '#ef4444',
  '#f97316', '#eab308', '#22c55e', '#06b6d4',
  '#3b82f6', '#64748b',
]

function ColorPicker({ value, onChange }: { value: string; onChange: (c: string) => void }) {
  return (
    <div className='flex flex-wrap items-center gap-2'>
      {PRESET_COLORS.map((c) => (
        <button
          key={c}
          type='button'
          onClick={() => onChange(c)}
          className={`size-6 rounded-full border-2 transition-transform hover:scale-110 ${
            value === c ? 'scale-110 border-foreground' : 'border-transparent'
          }`}
          style={{ backgroundColor: c }}
        />
      ))}
      <input
        type='color'
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className='size-6 cursor-pointer rounded-full border-0 bg-transparent p-0'
        title='Custom colour'
      />
    </div>
  )
}

// ── Label form dialog ─────────────────────────────────────────────────────────

interface LabelFormDialogProps {
  trigger: React.ReactNode
  title: string
  description?: string
  initial?: Partial<LabelRow>
  onSave: (data: { name: string; description: string; color: string }) => Promise<void>
}

function LabelFormDialog({ trigger, title, description, initial, onSave }: LabelFormDialogProps) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState(initial?.name ?? '')
  const [desc, setDesc] = useState(initial?.description ?? '')
  const [color, setColor] = useState(initial?.color ?? '#6366f1')
  const [saving, setSaving] = useState(false)

  const reset = () => {
    setName(initial?.name ?? '')
    setDesc(initial?.description ?? '')
    setColor(initial?.color ?? '#6366f1')
  }

  const handleOpenChange = (o: boolean) => {
    setOpen(o)
    if (!o) reset()
  }

  const handleSave = async () => {
    if (!name.trim()) return
    setSaving(true)
    try {
      await onSave({ name: name.trim(), description: desc.trim(), color })
      setOpen(false)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className='sm:max-w-sm'>
        <DialogHeader className='space-y-1'>
          <DialogTitle>{title}</DialogTitle>
          {description && (
            <DialogDescription>{description}</DialogDescription>
          )}
        </DialogHeader>

        <div className='space-y-4'>
          {/* Name */}
          <div className='space-y-2'>
            <Label htmlFor='label-name'>
              Name<span className='text-destructive'>*</span>
            </Label>
            <Input
              id='label-name'
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder='e.g. stable'
              autoFocus
            />
          </div>

          {/* Description */}
          <div className='space-y-2'>
            <Label htmlFor='label-desc'>
              Description{' '}
              <span className='font-normal text-muted-foreground'>(optional)</span>
            </Label>
            <Input
              id='label-desc'
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              placeholder='What this label means'
            />
          </div>

          {/* Color */}
          <div className='space-y-2'>
            <Label>Colour</Label>
            <ColorPicker value={color} onChange={setColor} />
          </div>

          {/* Preview */}
          <div className='space-y-1.5'>
            <Label className='text-muted-foreground text-xs'>Preview</Label>
            <div>
              <span
                className='inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium text-white'
                style={{ backgroundColor: color }}
              >
                {name || 'label'}
              </span>
            </div>
          </div>
        </div>

        <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
          <DialogClose asChild>
            <Button variant='outline'>Cancel</Button>
          </DialogClose>
          <Button onClick={handleSave} disabled={!name.trim() || saving}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Delete confirm dialog ─────────────────────────────────────────────────────

interface DeleteDialogProps {
  label: LabelRow
  open: boolean
  onOpenChange: (o: boolean) => void
  onConfirm: () => Promise<void>
}

function DeleteDialog({ label, open, onOpenChange, onConfirm }: DeleteDialogProps) {
  const [deleting, setDeleting] = useState(false)

  const handleDelete = async () => {
    setDeleting(true)
    try {
      await onConfirm()
      onOpenChange(false)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className='sm:max-w-sm'>
        <DialogHeader className='space-y-2'>
          <DialogTitle>Delete label?</DialogTitle>
          <DialogDescription>
            The label{' '}
            <span
              className='inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium text-white'
              style={{ backgroundColor: label.color }}
            >
              {label.name}
            </span>{' '}
            will be permanently removed from this project.
          </DialogDescription>
        </DialogHeader>
        <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
          <DialogClose asChild>
            <Button variant='outline'>Cancel</Button>
          </DialogClose>
          <Button variant='destructive' disabled={deleting} onClick={handleDelete}>
            {deleting ? 'Deleting…' : 'Delete'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const LabelsList = ({ labels, loading, onCreate, onUpdate, onDelete }: LabelsListProps) => {
  const [deleteTarget, setDeleteTarget] = useState<LabelRow | null>(null)

  return (
    <section className='py-3'>
      <div className='mx-auto max-w-7xl'>
        {/* Header */}
        <div className='mb-6 flex flex-wrap items-center justify-between gap-4'>
          <div className='space-y-1'>
            <h3 className='font-semibold'>Labels</h3>
            <p className='text-muted-foreground text-sm'>
              Labels help organise and categorise repositories within this project.
            </p>
          </div>

          <LabelFormDialog
            trigger={
              <Button className='max-sm:w-full'>
                <PlusIcon />
                New label
              </Button>
            }
            title='Create label'
            description='Labels help organise repositories within this project.'
            onSave={onCreate}
          />
        </div>

        {/* Rows */}
        {loading ? (
          <div className='space-y-3'>
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className='h-12 w-full rounded-lg' />
            ))}
          </div>
        ) : labels.length === 0 ? (
          <div className='flex flex-col items-center gap-3 py-24 text-center text-muted-foreground'>
            <TagIcon className='size-10 opacity-30' />
            <p className='text-sm'>No labels yet. Create one to organise repositories.</p>
          </div>
        ) : (
          labels.map((lbl, idx) => (
            <div key={lbl.id}>
              <div className='flex items-center justify-between gap-4 py-1'>
                {/* Left: swatch + name + description */}
                <div className='flex min-w-0 items-center gap-3'>
                  <span
                    className='inline-flex shrink-0 items-center rounded-full px-2.5 py-0.5 text-xs font-medium text-white'
                    style={{ backgroundColor: lbl.color }}
                  >
                    {lbl.name}
                  </span>
                  <p className='truncate text-sm text-muted-foreground'>
                    {lbl.description || <span className='italic'>No description</span>}
                  </p>
                </div>

                {/* Right: actions */}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant='ghost' size='icon' className='shrink-0 rounded-full'>
                      <EllipsisVerticalIcon />
                      <span className='sr-only'>Label actions</span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent className='w-28' align='end'>
                    <DropdownMenuGroup>
                      <LabelFormDialog
                        trigger={
                          <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
                            Edit
                          </DropdownMenuItem>
                        }
                        title='Edit label'
                        initial={lbl}
                        onSave={(data) => onUpdate(lbl.id, data)}
                      />
                      <DropdownMenuItem
                        className='text-destructive transition-colors duration-200 hover:bg-destructive/10! hover:text-destructive!'
                        onClick={() => setDeleteTarget(lbl)}
                      >
                        Delete
                      </DropdownMenuItem>
                    </DropdownMenuGroup>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>

              {idx !== labels.length - 1 && <Separator className='my-2' />}
            </div>
          ))
        )}

        {/* Delete confirm */}
        {deleteTarget && (
          <DeleteDialog
            label={deleteTarget}
            open={deleteTarget !== null}
            onOpenChange={(o) => !o && setDeleteTarget(null)}
            onConfirm={() => onDelete(deleteTarget.id)}
          />
        )}
      </div>
    </section>
  )
}

export default LabelsList
