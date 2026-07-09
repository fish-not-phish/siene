import { Separator } from '@/components/ui/separator'

import GeneralSettings, { type GeneralSettingsProps } from './content/general-settings'
import StorageSettings, { type StorageSettingsProps } from './content/storage-settings'
import SecurityPolicy, { type SecurityPolicyProps } from './content/security-policy'
import TagPolicy, { type TagPolicyProps } from './content/tag-policy'
import DangerZone, { type DangerZoneProps } from './content/danger-zone'

export interface ProjectSettingsProps {
  general: GeneralSettingsProps
  storage: StorageSettingsProps
  security: SecurityPolicyProps
  tags: TagPolicyProps
  danger: DangerZoneProps
}

const ProjectSettings = ({ general, storage, security, tags, danger }: ProjectSettingsProps) => {
  return (
    <section className='py-3'>
      <div className='mx-auto max-w-7xl'>
        <GeneralSettings {...general} />
        <Separator className='my-10' />
        <StorageSettings {...storage} />
        <Separator className='my-10' />
        <SecurityPolicy {...security} />
        <Separator className='my-10' />
        <TagPolicy {...tags} />
        <Separator className='my-10' />
        <DangerZone {...danger} />
      </div>
    </section>
  )
}

export default ProjectSettings
