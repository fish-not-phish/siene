'use client'

import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogClose,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Trash2Icon } from 'lucide-react'
import { useState } from 'react'

export interface DangerZoneProps {
  projectSlug: string
  isAdmin: boolean
  onDelete: () => void
  deleting: boolean
}

const DangerZone = ({ projectSlug, isAdmin, onDelete, deleting }: DangerZoneProps) => {
  const [confirm, setConfirm] = useState('')

  return (
    <div className='grid grid-cols-1 gap-10 lg:grid-cols-3'>
      <div className='flex flex-col space-y-1'>
        <h3 className='font-semibold'>Danger zone</h3>
        <p className='text-muted-foreground text-sm'>
          Irreversible actions for this project. Proceed with caution.
        </p>
      </div>

      <div className='space-y-6 lg:col-span-2'>
        {/* Delete project — admin only */}
        {isAdmin ? (
          <Card>
            <CardContent className='space-y-0 pt-5'>
              <div className='flex justify-between gap-4 max-lg:flex-col lg:items-center'>
                <div className='space-y-1'>
                  <h3 className='text-sm font-medium'>Delete project</h3>
                  <p className='text-muted-foreground text-sm'>
                    Permanently delete <span className='font-mono font-medium'>{projectSlug}</span> and
                    all its repositories, tags, and scan data. This cannot be undone.
                  </p>
                </div>
                <Dialog onOpenChange={() => setConfirm('')}>
                  <DialogTrigger asChild>
                    <Button
                      variant='outline'
                      className='border-destructive! text-destructive! hover:bg-destructive/10! focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 max-lg:w-full'
                    >
                      <Trash2Icon />
                      Delete project
                    </Button>
                  </DialogTrigger>
                  <DialogContent className='sm:max-w-md'>
                    <DialogHeader className='space-y-2'>
                      <DialogTitle>Delete project</DialogTitle>
                      <div className='text-muted-foreground text-sm'>
                        This will permanently delete{' '}
                        <span className='font-mono font-semibold text-foreground'>{projectSlug}</span> and
                        all its data. Type the project slug to confirm.
                      </div>
                    </DialogHeader>
                    <div className='space-y-3'>
                      <div className='space-y-1.5'>
                        <Label htmlFor='delete-confirm'>
                          Type <span className='font-mono font-semibold'>{projectSlug}</span> to confirm
                        </Label>
                        <Input
                          id='delete-confirm'
                          value={confirm}
                          onChange={(e) => setConfirm(e.target.value)}
                          placeholder={projectSlug}
                          autoComplete='off'
                        />
                      </div>
                      <div className='flex flex-col-reverse gap-3 sm:flex-row sm:justify-end'>
                        <DialogClose asChild>
                          <Button variant='outline'>Cancel</Button>
                        </DialogClose>
                        <Button
                          variant='destructive'
                          disabled={confirm !== projectSlug || deleting}
                          onClick={onDelete}
                        >
                          {deleting ? 'Deleting…' : 'Delete project'}
                        </Button>
                      </div>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className='cursor-not-allowed opacity-60'>
            <CardContent className='flex justify-between gap-4 max-lg:flex-col lg:items-center pt-5'>
              <div className='space-y-1'>
                <h3 className='text-sm font-medium'>Delete project</h3>
                <p className='text-muted-foreground text-sm'>
                  Permanently delete this project and all its data.
                </p>
              </div>
              <Button
                variant='outline'
                className='border-destructive! text-destructive! hover:bg-destructive/10! max-lg:w-full'
                disabled
              >
                <Trash2Icon />
                Delete project
              </Button>
            </CardContent>
            <CardContent>
              <Separator />
            </CardContent>
            <CardContent>
              <p className='text-muted-foreground text-sm'>
                Only system administrators can delete projects.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}

export default DangerZone
