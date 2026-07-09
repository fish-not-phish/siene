'use client'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'

export interface GeneralSettingsProps {
  slug: string
  displayName: string
  description: string
  isPublic: boolean
  saving: boolean
  onDisplayNameChange: (v: string) => void
  onDescriptionChange: (v: string) => void
  onPublicChange: (v: boolean) => void
  onSave: () => void
}

const GeneralSettings = ({
  slug,
  displayName,
  description,
  isPublic,
  saving,
  onDisplayNameChange,
  onDescriptionChange,
  onPublicChange,
  onSave,
}: GeneralSettingsProps) => {
  return (
    <div className='grid grid-cols-1 gap-10 lg:grid-cols-3'>
      <div className='flex flex-col space-y-1'>
        <h3 className='font-semibold'>General</h3>
        <p className='text-muted-foreground text-sm'>
          Manage your project name, description, and visibility.
        </p>
      </div>

      <div className='space-y-6 lg:col-span-2'>
        {/* Slug — read-only */}
        <div className='space-y-2'>
          <Label htmlFor='project-slug'>Project slug</Label>
          <Input
            id='project-slug'
            value={slug}
            readOnly
            className='read-only:bg-muted font-mono'
          />
          <p className='text-muted-foreground text-xs'>
            The slug is set at creation and cannot be changed.
          </p>
        </div>

        {/* Display name */}
        <div className='space-y-2'>
          <Label htmlFor='display-name'>Display name</Label>
          <Input
            id='display-name'
            value={displayName}
            onChange={(e) => onDisplayNameChange(e.target.value)}
            placeholder='My Project'
          />
        </div>

        {/* Description */}
        <div className='space-y-2'>
          <Label htmlFor='project-description'>Description</Label>
          <Textarea
            id='project-description'
            value={description}
            onChange={(e) => onDescriptionChange(e.target.value)}
            placeholder='A short description of this project.'
            rows={3}
          />
        </div>

        {/* Visibility */}
        <div className='flex items-center justify-between rounded-lg border px-4 py-3'>
          <div className='space-y-0.5'>
            <Label htmlFor='public-toggle' className='cursor-pointer text-sm font-medium'>
              Public project
            </Label>
            <p className='text-muted-foreground text-xs'>
              Allow anonymous pulls without authentication.
            </p>
          </div>
          <Switch
            id='public-toggle'
            checked={isPublic}
            onCheckedChange={onPublicChange}
          />
        </div>

        <div className='flex justify-end'>
          <Button type='button' disabled={saving} onClick={onSave} className='max-sm:w-full'>
            {saving ? 'Saving…' : 'Save changes'}
          </Button>
        </div>
      </div>
    </div>
  )
}

export default GeneralSettings
