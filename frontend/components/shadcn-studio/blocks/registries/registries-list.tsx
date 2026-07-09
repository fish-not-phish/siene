'use client'

import { useState } from 'react'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'
import {
  CheckIcon, LinkIcon, Trash2Icon, WifiIcon, WifiOffIcon,
  RefreshCwIcon, PlusCircleIcon, PencilIcon,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface RemoteRegistry {
  id: number
  name: string
  description: string
  registry_type: string
  endpoint: string
  username: string
  insecure: boolean
  verified: boolean
  created_at: string
  updated_at: string
}

interface RegistriesListProps {
  registries: RemoteRegistry[]
  loading: boolean
  pinging: number | null
  onCreate: (data: Record<string, unknown>) => Promise<void>
  onEdit:   (id: number, data: Record<string, unknown>) => Promise<void>
  onDelete: (id: number) => Promise<void>
  onPing:   (id: number) => Promise<void>
}

// ── Provider catalogue ────────────────────────────────────────────────────────

// Endpoint mode for each provider:
//   'fixed'    — single immutable URL, no input shown
//   'editable' — free-text input, placeholder is shown
//   'select'   — dropdown of predefined options (endpointOptions required)
//   'select+edit' — dropdown + editable text field that the user can override

type EndpointMode = 'fixed' | 'editable' | 'select' | 'select+edit'

interface Provider {
  type: string
  name: string
  description: string
  bgColor: string
  defaultEndpoint: string        // used when mode=fixed or as initial value
  endpointMode: EndpointMode
  endpointOptions?: { label: string; value: string }[]  // for select / select+edit
  endpointPlaceholder?: string   // hint shown inside editable inputs
  credentialLabel: string
  passwordLabel: string
  icon: React.ReactNode
}

// Simple helper: renders a simple-icons-style 24×24 viewBox path at size-5
function SI({ path, color }: { path: string; color: string }) {
  return (
    <svg viewBox='0 0 24 24' className='size-5' fill={color} xmlns='http://www.w3.org/2000/svg'>
      <path d={path} />
    </svg>
  )
}

// ── ECR regions ───────────────────────────────────────────────────────────────

const ECR_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'af-south-1',
  'ap-east-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
  'ap-southeast-1', 'ap-southeast-2',
  'ca-central-1',
  'cn-north-1', 'cn-northwest-1',
  'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3',
  'eu-south-1', 'eu-north-1',
  'me-south-1',
  'sa-east-1',
]

// ECR endpoint options — the account-id portion is always user-supplied so we
// produce a templated URL; the user edits the account-id part after selecting.
const ECR_ENDPOINT_OPTIONS = ECR_REGIONS.map((r) => ({
  label: r,
  value: `https://<account-id>.dkr.ecr.${r}.amazonaws.com`,
}))

// ── GCR hostnames ─────────────────────────────────────────────────────────────

const GCR_ENDPOINT_OPTIONS = [
  { label: 'gcr.io (global)',      value: 'https://gcr.io' },
  { label: 'us.gcr.io',           value: 'https://us.gcr.io' },
  { label: 'eu.gcr.io',           value: 'https://eu.gcr.io' },
  { label: 'asia.gcr.io',         value: 'https://asia.gcr.io' },
]

// ── Provider definitions ──────────────────────────────────────────────────────

const PROVIDERS: Provider[] = [
  {
    type: 'ecr',
    name: 'Amazon ECR',
    description: 'Push and pull images to/from AWS Elastic Container Registry.',
    bgColor: 'bg-[#FF9900]/10',
    defaultEndpoint: 'https://<account-id>.dkr.ecr.us-east-1.amazonaws.com',
    endpointMode: 'select+edit',
    endpointOptions: ECR_ENDPOINT_OPTIONS,
    endpointPlaceholder: 'https://<account-id>.dkr.ecr.<region>.amazonaws.com',
    credentialLabel: 'AWS Access Key ID',
    passwordLabel: 'AWS Secret Access Key',
    icon: (
      <svg viewBox='0 0 24 24' className='size-5' fill='none' xmlns='http://www.w3.org/2000/svg'>
        <path d='M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576a.37.37 0 0 1 .056.192.345.345 0 0 1-.168.28l-.552.368a.43.43 0 0 1-.224.072.408.408 0 0 1-.264-.112 2.726 2.726 0 0 1-.32-.416 6.897 6.897 0 0 1-.272-.528c-.68.8-1.536 1.2-2.568 1.2-.736 0-1.32-.208-1.752-.624-.432-.416-.648-.968-.648-1.656 0-.736.256-1.328.776-1.776.52-.448 1.208-.672 2.08-.672.288 0 .584.024.896.064.312.04.632.104.968.176v-.616c0-.64-.136-1.088-.4-1.352-.272-.264-.728-.392-1.376-.392-.296 0-.6.04-.912.112a6.62 6.62 0 0 0-.912.296 2.42 2.42 0 0 1-.296.112.52.52 0 0 1-.128.016c-.112 0-.168-.08-.168-.248v-.392c0-.128.016-.224.056-.28a.6.6 0 0 1 .224-.168 5.58 5.58 0 0 1 1.04-.368 5.02 5.02 0 0 1 1.288-.16c.984 0 1.704.224 2.168.672.456.448.688 1.128.688 2.04v2.688zm-3.544 1.328c.28 0 .568-.056.872-.168.304-.112.576-.304.8-.568.136-.16.232-.336.28-.536.048-.2.08-.44.08-.72v-.344a7.19 7.19 0 0 0-.776-.072 7.19 7.19 0 0 0-.776-.024c-.552 0-.96.112-1.232.344-.272.232-.4.56-.4.984 0 .4.104.696.32.904.208.2.504.2.832.2zm6.64.88c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.312L7.8 7.116a1.45 1.45 0 0 1-.072-.32c0-.128.064-.2.192-.2h.784c.152 0 .256.024.312.08.064.048.112.16.16.312l1.336 5.272 1.24-5.272c.04-.16.088-.264.152-.312.064-.048.176-.08.32-.08h.64c.152 0 .256.024.32.08.064.048.12.16.152.312l1.256 5.336 1.376-5.336c.048-.16.104-.264.16-.312.064-.048.16-.08.304-.08h.744c.128 0 .2.064.2.2 0 .04-.008.08-.016.128a1.226 1.226 0 0 1-.056.2l-1.712 5.736c-.048.16-.104.264-.168.312-.064.048-.168.08-.304.08h-.688c-.152 0-.256-.024-.32-.08-.064-.056-.12-.16-.152-.32l-1.232-5.168-1.224 5.16c-.04.16-.088.264-.152.32-.064.056-.176.08-.32.08zm9.112.192c-.44 0-.88-.048-1.304-.152-.424-.104-.752-.216-.968-.344-.136-.08-.224-.168-.256-.248a.63.63 0 0 1-.048-.24v-.408c0-.168.064-.248.184-.248.048 0 .096.008.144.024.048.016.12.048.2.08.272.12.568.216.88.28.32.064.632.096.952.096.504 0 .896-.088 1.168-.264.272-.176.416-.432.416-.76 0-.224-.072-.408-.216-.56-.144-.152-.416-.288-.808-.416l-1.16-.368c-.584-.184-1.016-.456-1.288-.816a1.956 1.956 0 0 1-.408-1.208c0-.352.072-.664.224-.928.152-.264.36-.496.608-.68.248-.192.536-.336.864-.432.328-.096.672-.144 1.032-.144.184 0 .376.008.56.04.192.024.368.064.536.104.16.048.312.096.456.152.144.056.256.112.336.168a.692.692 0 0 1 .24.232.6.6 0 0 1 .072.296v.376c0 .168-.064.256-.184.256a.83.83 0 0 1-.304-.096 3.636 3.636 0 0 0-1.528-.312c-.456 0-.816.072-1.072.224-.256.152-.384.384-.384.704 0 .224.08.416.24.568.16.152.456.304.88.44l1.136.36c.576.184.992.44 1.248.776.256.336.376.72.376 1.144 0 .36-.072.688-.216.976a2.238 2.238 0 0 1-.608.72 2.7 2.7 0 0 1-.912.448 3.908 3.908 0 0 1-1.136.152z' fill='#FF9900'/>
        <path d='M21.596 18.04c-2.608 1.928-6.4 2.952-9.664 2.952-4.568 0-8.68-1.688-11.784-4.496-.248-.224-.024-.528.272-.352 3.352 1.952 7.496 3.12 11.776 3.12 2.888 0 6.064-.6 8.984-1.84.44-.192.808.288.416.616z' fill='#FF9900'/>
        <path d='M22.664 16.824c-.336-.432-2.224-.208-3.08-.104-.256.032-.296-.192-.064-.36 1.504-1.056 3.976-.752 4.264-.4.288.36-.08 2.84-1.488 4.024-.216.184-.424.088-.328-.152.32-.8 1.032-2.576.696-3.008z' fill='#FF9900'/>
      </svg>
    ),
  },
  {
    type: 'acr-azure',
    name: 'Azure Container Registry',
    description: 'Store and manage container images in Microsoft Azure.',
    bgColor: 'bg-[#0078D4]/10',
    defaultEndpoint: '',
    endpointMode: 'editable',
    endpointPlaceholder: 'https://<registry-name>.azurecr.io',
    credentialLabel: 'Service Principal ID',
    passwordLabel: 'Service Principal Password',
    icon: (
      <svg viewBox='0 0 24 24' className='size-5' xmlns='http://www.w3.org/2000/svg'>
        <path d='M13.05 4.24L6.56 18.05l-2.17.03 5.32-8.75-3.01-4.8zm.7-.55 3.57 2.05.39 12.38-9.56.01z' fill='#0078D4'/>
        <path d='M17.57 18.14H7.44l-1.05 1.64h12.12z' fill='#0078D4' opacity='.7'/>
      </svg>
    ),
  },
  {
    type: 'docker-hub',
    name: 'Docker Hub',
    description: 'The world\'s largest library of container images.',
    bgColor: 'bg-[#2496ED]/10',
    defaultEndpoint: 'https://hub.docker.com',
    endpointMode: 'fixed',
    credentialLabel: 'Docker Hub Username',
    passwordLabel: 'Password / Access Token',
    icon: <SI color='#2496ED' path='M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z' />,
  },
  {
    type: 'docker-registry',
    name: 'Docker Registry',
    description: 'A self-hosted Docker Registry v2 / OCI Distribution endpoint.',
    bgColor: 'bg-[#2496ED]/10',
    defaultEndpoint: '',
    endpointMode: 'editable',
    endpointPlaceholder: 'http(s)://192.168.1.1',
    credentialLabel: 'Username',
    passwordLabel: 'Password',
    icon: (
      <svg viewBox='0 0 24 24' className='size-5 opacity-70' xmlns='http://www.w3.org/2000/svg' fill='#2496ED'>
        <path d='M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z'/>
      </svg>
    ),
  },
  {
    type: 'ghcr',
    name: 'GitHub GHCR',
    description: 'GitHub Container Registry — host images alongside your source code.',
    bgColor: 'bg-primary/10',
    defaultEndpoint: 'https://ghcr.io',
    endpointMode: 'fixed',
    credentialLabel: 'GitHub Username',
    passwordLabel: 'Personal Access Token (PAT)',
    icon: <SI color='currentColor' path='M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12' />,
  },
  {
    type: 'gcr',
    name: 'Google GCR',
    description: 'Google Container Registry and Artifact Registry for GCP workloads.',
    bgColor: 'bg-[#4285F4]/10',
    defaultEndpoint: 'https://gcr.io',
    endpointMode: 'select',
    endpointOptions: GCR_ENDPOINT_OPTIONS,
    credentialLabel: 'Service Account Email',
    passwordLabel: 'Service Account JSON Key',
    icon: <SI color='#4285F4' path='M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-2.821-4.552l-.043.043.006-.05A9.344 9.344 0 0 0 12.19 2.38zm-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.186 5.186 0 0 1 1.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.59 2.59 0 0 1-1.067-.23h.001a2.597 2.597 0 1 1 3.437-3.437l3.013-3.012A6.747 6.747 0 0 0 8.11 8.24c.018-.01.04-.026.054-.023a5.186 5.186 0 0 1 3.67-1.69z' />,
  },
  {
    type: 'harbor',
    name: 'Harbor',
    description: 'Connect to another Harbor instance for cross-registry replication.',
    bgColor: 'bg-[#60B932]/10',
    defaultEndpoint: '',
    endpointMode: 'editable',
    endpointPlaceholder: 'http(s)://192.168.1.1',
    credentialLabel: 'Username',
    passwordLabel: 'Password',
    icon: <SI color='#60B932' path='m7.006 15.751 4.256 1.876.066.805-4.388-1.934.066-.747zm.304-3.435h-.605V11.21h.381V8.95h-.381v-.649l2.118-2.073v-.146c0-.11.09-.2.2-.2.11 0 .2.09.2.2v.146l2.12 2.073v.65h-.382v2.259h.381v1.106h-.514l.27 3.313L7.17 13.9l.14-1.583zm.39-1.106h.628v-.965c0-.383.313-.696.695-.696s.696.313.696.696v.965h.628V8.95H7.7v2.26zM6.89 17.05l-.066.747 4.618 2.035-.066-.805-4.486-1.977zm.23-2.6-.066.747 4.158 1.832-.065-.805-4.026-1.774zM24 12c0 6.617-5.383 12-12 12S0 18.617 0 12 5.383 0 12 0s12 5.383 12 12zm-2.43-.715a9.682 9.682 0 0 0-.223-1.523l-9.751.332 8.801-2.828-.019-.037A9.802 9.802 0 0 0 19.23 5.59l-7.786 4.03 5.712-5.941a9.675 9.675 0 0 0-5.14-1.474c-5.371 0-9.74 4.369-9.74 9.74 0 3.38 1.73 6.362 4.35 8.11l.151-1.704 4.715 2.078.102 1.246c.14.006.28.01.422.01 4.646 0 8.54-3.27 9.507-7.63l-10.08-3.497 10.128.727' />,
  },
  {
    type: 'jfrog',
    name: 'JFrog Artifactory',
    description: 'Universal artifact repository supporting Docker images and OCI.',
    bgColor: 'bg-[#40BE46]/10',
    defaultEndpoint: '',
    endpointMode: 'editable',
    endpointPlaceholder: 'http(s)://192.168.1.1',
    credentialLabel: 'Username',
    passwordLabel: 'API Key / Password',
    icon: <SI color='#40BE46' path='M10.655 15.631l-1.268.353c.11.32.2.893.2 1.665v3.795h1.421v-4.015c.265-.32.552-.474.86-.474.156 0 .277.033.409.11l.386-1.312a1.05 1.05 0 00-.53-.122 1.22 1.22 0 00-.463.09c-.265.131-.596.43-.805.715 0-.32-.077-.573-.21-.805zM5.76 13.757h-.154v7.676h1.477v-3.398h1.864v-1.268H7.082v-1.764H9.41l.088-.673c-1.4-.1-2.668-.32-3.738-.573zm-3.452 8.7l.684.796c.662-.265 1.49-.86 1.71-1.81.077-.308.1-.506.1-1.51v-6.165H3.308v6.33c0 .828-.032 1.136-.142 1.423-.144.32-.486.695-.86.938zm13.422-3.892c0 1.346-.264 1.92-.871 1.92a.782.782 0 01-.717-.464c-.11-.286-.176-.773-.176-1.434 0-.563.055-.96.143-1.268.11-.353.386-.574.728-.574.254 0 .474.11.606.298.199.265.287.76.287 1.522zm.87 2.206c.465-.551.674-1.225.674-2.195 0-.916-.187-1.544-.617-2.073-.464-.574-1.06-.85-1.831-.85-1.456 0-2.426 1.18-2.426 2.967 0 1.787.96 2.934 2.426 2.934.827.01 1.367-.297 1.775-.783zm4.038-3.177c0 .52-.31.805-.86.805-.497 0-.828-.23-.828-.805 0-.529.31-.838.838-.838.53 0 .85.31.85.838zm2.503-1.213l-.585-.937c-.33.31-.727.485-1.113.485-.177 0-.276-.022-.662-.12a3.282 3.282 0 00-.97-.145c-1.38 0-2.272.75-2.272 1.92 0 .837.375 1.367 1.158 1.576-.32.077-.662.243-.816.43a.79.79 0 00-.166.52c0 .176.044.33.11.463a.68.68 0 00.31.275c.253.1.66.166 1.29.177.33 0 .529.01.595.01.386.023.584.09.739.166.143.089.253.287.253.508 0 .22-.132.44-.341.573-.188.132-.497.188-.894.188-.65 0-1.014-.243-1.014-.695 0-.2.022-.243.066-.364h-1.301c-.055.11-.122.265-.122.573 0 .386.144.717.442 1.004.485.474 1.279.606 2.04.606.838 0 1.654-.198 2.128-.727.298-.331.43-.695.43-1.17 0-.507-.143-.893-.463-1.212-.375-.364-.805-.497-1.632-.508l-.761-.01c-.143 0-.232-.056-.232-.133 0-.154.199-.288.563-.464.11.01.143.01.21.01 1.146 0 1.984-.705 1.984-1.686 0-.375-.11-.662-.32-.927.177.022.232.033.364.033.375 0 .673-.12.982-.419zM5.384 7.085c-1.764.43-2.966 1.279-2.966 2.25 0 .606.463 1.157 1.224 1.587a2.155 2.155 0 01-.353-1.157c.01-1.004.794-1.941 2.095-2.68zM24 10.889c0-.64-.397-1.224-1.059-1.709.055.2.088.406.088.621 0 1.797-2.547 3.31-5.87 3.696.287.464.45.993.45 1.554 0 .033-.008.065-.01.098C21.18 14.653 24 12.9 24 10.889zm-7.48 5.962c-.508.044-1.026.066-1.554.066-4.756 0-8.613-1.908-8.613-4.26 0-.398.11-.775.31-1.125-1.764.43-2.879 1.246-2.879 2.162 0 1.753 3.416 3.178 7.635 3.178 2.216 0 4.212-.442 5.545-1.143a4.418 4.418 0 01-.443.122zM9.73 8.517c0-1.962 2.58-3.553 5.76-3.553.486 0 .96.044 1.411.121C15.56 3.79 13.51 2.85 11.224 2.85c-3.208 0-5.81 1.918-5.81 4.286 0 1.378.906 2.612 2.337 3.441a5.553 5.553 0 01-.022-.06z' />,
  },
  {
    type: 'tcr',
    name: 'Tencent TCR',
    description: 'Tencent Cloud Container Registry for hosting images.',
    bgColor: 'bg-[#006EFF]/10',
    defaultEndpoint: '',
    endpointMode: 'editable',
    endpointPlaceholder: 'http(s)://192.168.1.1',
    credentialLabel: 'SecretId',
    passwordLabel: 'SecretKey',
    icon: (
      <svg viewBox='0 0 24 24' className='size-5' xmlns='http://www.w3.org/2000/svg' fill='#006EFF'>
        <path d='M12.003 1.5C6.201 1.5 1.5 6.201 1.5 12.003c0 5.8 4.701 10.497 10.503 10.497 5.8 0 10.497-4.698 10.497-10.497C22.5 6.2 17.803 1.5 12.003 1.5zm4.693 14.478h-2.04v-5.75l-4.55 5.75H8.298V8.025h2.04v5.743l4.543-5.743h1.815v7.953z'/>
      </svg>
    ),
  },
  {
    type: 'swr',
    name: 'Huawei SWR',
    description: 'Huawei Cloud SoftWare Repository for container images.',
    bgColor: 'bg-[#CF0A2C]/10',
    defaultEndpoint: '',
    endpointMode: 'editable',
    endpointPlaceholder: 'http(s)://192.168.1.1',
    credentialLabel: 'Access Key ID',
    passwordLabel: 'Secret Access Key',
    icon: <SI color='#FF0000' path='M3.67 6.14S1.82 7.91 1.72 9.78v.35c.08 1.51 1.22 2.4 1.22 2.4 1.83 1.79 6.26 4.04 7.3 4.55 0 0 .06.03.1-.01l.02-.04v-.04C7.52 10.8 3.67 6.14 3.67 6.14zM9.65 18.6c-.02-.08-.1-.08-.1-.08l-7.38.26c.8 1.43 2.15 2.53 3.56 2.2.96-.25 3.16-1.78 3.88-2.3.06-.05.04-.09.04-.09zm.08-.78C6.49 15.63.21 12.28.21 12.28c-.15.46-.2.9-.21 1.3v.07c0 1.07.4 1.82.4 1.82.8 1.69 2.34 2.2 2.34 2.2.7.3 1.4.31 1.4.31.12.02 4.4 0 5.54 0 .05 0 .08-.05.08-.05v-.06c0-.03-.03-.05-.03-.05zM9.06 3.19a3.42 3.42 0 00-2.57 3.15v.41c.03.6.16 1.05.16 1.05.66 2.9 3.86 7.65 4.55 8.65.05.05.1.03.1.03a.1.1 0 00.06-.1c1.06-10.6-1.11-13.42-1.11-13.42-.32.02-1.19.23-1.19.23zm8.299 2.27s-.49-1.8-2.44-2.28c0 0-.57-.14-1.17-.22 0 0-2.18 2.81-1.12 13.43.01.07.06.08.06.08.07.03.1-.03.1-.03.72-1.03 3.9-5.76 4.55-8.64 0 0 .36-1.4.02-2.34zm-2.92 13.07s-.07 0-.09.05c0 0-.01.07.03.1.7.51 2.85 2 3.88 2.3 0 0 .16.05.43.06h.14c.69-.02 1.9-.37 3-2.26l-7.4-.25zm7.83-8.41c.14-2.06-1.94-3.97-1.94-3.98 0 0-3.85 4.66-6.67 10.8 0 0-.03.08.02.13l.04.01h.06c1.06-.53 5.46-2.77 7.28-4.54 0 0 1.15-.93 1.21-2.42zm1.52 2.14s-6.28 3.37-9.52 5.55c0 0-.05.04-.03.11 0 0 .03.06.07.06 1.16 0 5.56 0 5.67-.02 0 0 .57-.02 1.27-.29 0 0 1.56-.5 2.37-2.27 0 0 .73-1.45.17-3.14z' />,
  },
  {
    type: 'generic',
    name: 'Generic OCI / Docker v2',
    description: 'Any OCI-compliant or Docker Registry v2 endpoint not listed above.',
    bgColor: 'bg-muted/50',
    defaultEndpoint: '',
    endpointMode: 'editable',
    endpointPlaceholder: 'https://registry.example.com',
    credentialLabel: 'Username',
    passwordLabel: 'Password',
    icon: (
      <svg viewBox='0 0 24 24' className='size-5' fill='none' xmlns='http://www.w3.org/2000/svg'>
        <rect x='3' y='3' width='18' height='18' rx='3' stroke='currentColor' strokeWidth='1.5'/>
        <path d='M7 8h10M7 12h6M7 16h8' stroke='currentColor' strokeWidth='1.5' strokeLinecap='round'/>
      </svg>
    ),
  },
]

// ── Connect / Edit modal ──────────────────────────────────────────────────────

interface ConnectModalProps {
  provider: Provider
  existing?: RemoteRegistry
  open: boolean
  onOpenChange: (v: boolean) => void
  onSave: (data: Record<string, unknown>) => Promise<void>
}

function ConnectModal({ provider, existing, open, onOpenChange, onSave }: ConnectModalProps) {
  const [name,     setName]     = useState(existing?.name ?? '')
  const [desc,     setDesc]     = useState(existing?.description ?? '')
  const [endpoint, setEndpoint] = useState(
    existing?.endpoint ?? (provider.endpointMode === 'fixed' ? provider.defaultEndpoint : '')
  )
  const [username, setUsername] = useState(existing?.username ?? '')
  const [password, setPassword] = useState('')
  const [insecure, setInsecure] = useState(existing?.insecure ?? false)
  const [saving,   setSaving]   = useState(false)

  const reset = () => {
    setName(existing?.name ?? '')
    setDesc(existing?.description ?? '')
    setEndpoint(existing?.endpoint ?? (provider.endpointMode === 'fixed' ? provider.defaultEndpoint : ''))
    setUsername(existing?.username ?? '')
    setPassword('')
    setInsecure(existing?.insecure ?? false)
  }

  const handleOpenChange = (v: boolean) => {
    if (!v) reset()
    onOpenChange(v)
  }

  const handleSave = async () => {
    const ep = provider.endpointMode === 'fixed' ? provider.defaultEndpoint : endpoint
    if (!name.trim() || !ep.trim()) return
    setSaving(true)
    try {
      await onSave({
        name: name.trim(),
        description: desc.trim(),
        registry_type: provider.type,
        endpoint: ep.trim(),
        username: username.trim(),
        ...(password ? { password } : {}),
        insecure,
      })
      handleOpenChange(false)
    } finally {
      setSaving(false)
    }
  }

  const isEdit = !!existing
  const mode = provider.endpointMode

  // Compute whether Save should be disabled
  const effectiveEndpoint = mode === 'fixed' ? provider.defaultEndpoint : endpoint
  const canSave = name.trim().length > 0 && effectiveEndpoint.trim().length > 0 && !saving

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className='sm:max-w-md'>
        <DialogHeader>
          <div className='flex items-center gap-3 mb-1'>
            <Avatar size='lg' className='after:border-0'>
              <AvatarFallback className={cn('rounded-lg', provider.bgColor)}>
                {provider.icon}
              </AvatarFallback>
            </Avatar>
            <div>
              <DialogTitle>{isEdit ? `Edit ${provider.name}` : `Connect ${provider.name}`}</DialogTitle>
              <DialogDescription className='text-xs mt-0.5'>{provider.description}</DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className='space-y-3'>
          {/* Registry name */}
          <div className='space-y-1.5'>
            <Label htmlFor='reg-name'>Registry name</Label>
            <Input
              id='reg-name'
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={`my-${provider.type}`}
              autoFocus
            />
          </div>

          {/* Endpoint — rendered differently per mode */}
          {mode === 'fixed' && (
            <div className='space-y-1.5'>
              <Label>Registry URL</Label>
              <Input
                value={provider.defaultEndpoint}
                readOnly
                className='bg-muted text-muted-foreground'
              />
            </div>
          )}

          {mode === 'editable' && (
            <div className='space-y-1.5'>
              <Label htmlFor='reg-endpoint'>Registry URL</Label>
              <Input
                id='reg-endpoint'
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder={provider.endpointPlaceholder ?? 'https://registry.example.com'}
              />
            </div>
          )}

          {mode === 'select' && (
            <div className='space-y-1.5'>
              <Label>Registry URL</Label>
              <Select
                value={endpoint || provider.defaultEndpoint}
                onValueChange={setEndpoint}
              >
                <SelectTrigger>
                  <SelectValue placeholder='Select endpoint…' />
                </SelectTrigger>
                <SelectContent>
                  {provider.endpointOptions?.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {mode === 'select+edit' && (
            <div className='space-y-1.5'>
              <Label>Region</Label>
              <Select
                value={
                  // Match current endpoint to an option to show the region label,
                  // otherwise fall back to blank so the placeholder shows.
                  provider.endpointOptions?.find((o) => o.value === endpoint)?.value ?? ''
                }
                onValueChange={(val) => setEndpoint(val)}
              >
                <SelectTrigger>
                  <SelectValue placeholder='Select region…' />
                </SelectTrigger>
                <SelectContent>
                  {provider.endpointOptions?.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Label htmlFor='reg-endpoint-edit' className='sr-only'>Registry URL</Label>
              <Input
                id='reg-endpoint-edit'
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder={provider.endpointPlaceholder}
                className='font-mono text-xs'
              />
              <p className='text-xs text-muted-foreground'>
                Replace <code className='bg-muted px-1 rounded'>&lt;account-id&gt;</code> with your AWS account ID.
              </p>
            </div>
          )}

          {/* Credentials */}
          <div className='grid grid-cols-2 gap-3'>
            <div className='space-y-1.5'>
              <Label htmlFor='reg-user'>{provider.credentialLabel}</Label>
              <Input
                id='reg-user'
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete='off'
              />
            </div>
            <div className='space-y-1.5'>
              <Label htmlFor='reg-pass'>
                {provider.passwordLabel}
                {isEdit && <span className='text-muted-foreground font-normal'> (leave blank to keep)</span>}
              </Label>
              <Input
                id='reg-pass'
                type='password'
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete='new-password'
                placeholder={isEdit ? '••••••••' : ''}
              />
            </div>
          </div>

          {/* Description */}
          <div className='space-y-1.5'>
            <Label htmlFor='reg-desc'>
              Description <span className='text-muted-foreground font-normal'>(optional)</span>
            </Label>
            <Input
              id='reg-desc'
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              placeholder='e.g. Production ECR in us-east-1'
            />
          </div>

          {/* Skip TLS — only shown for non-fixed endpoints */}
          {mode !== 'fixed' && (
            <div className='flex items-center justify-between rounded-lg border px-3 py-2.5'>
              <div>
                <p className='text-sm font-medium'>Skip TLS verification</p>
                <p className='text-xs text-muted-foreground'>Use for self-signed certificates.</p>
              </div>
              <Switch checked={insecure} onCheckedChange={setInsecure} />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant='outline' onClick={() => handleOpenChange(false)}>Cancel</Button>
          <Button onClick={handleSave} disabled={!canSave}>
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Connect'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Provider card ─────────────────────────────────────────────────────────────

function ProviderCard({
  provider,
  instances,
  pinging,
  onCreate,
  onEdit,
  onDelete,
  onPing,
}: {
  provider: Provider
  instances: RemoteRegistry[]
  pinging: number | null
  onCreate: (data: Record<string, unknown>) => Promise<void>
  onEdit:   (id: number, data: Record<string, unknown>) => Promise<void>
  onDelete: (id: number) => Promise<void>
  onPing:   (id: number) => Promise<void>
}) {
  const [connectOpen,  setConnectOpen]  = useState(false)
  const [editTarget,   setEditTarget]   = useState<RemoteRegistry | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<RemoteRegistry | null>(null)
  const isConnected = instances.length > 0

  return (
    <>
      <Card className={cn('group transition-colors', isConnected && 'ring-1 ring-border')}>
        {/* Top row: icon + connect/add button */}
        <CardContent className='flex flex-wrap items-center justify-between gap-4'>
          <Avatar size='lg' className='after:border-0'>
            <AvatarFallback className={cn('rounded-lg', provider.bgColor)}>
              {provider.icon}
            </AvatarFallback>
          </Avatar>
          <Button
            variant='outline'
            size='sm'
            onClick={() => setConnectOpen(true)}
            className={cn(
              isConnected
                ? 'border-sky-600 text-sky-600! hover:bg-sky-600/10 focus-visible:border-sky-600 focus-visible:ring-sky-600/20 dark:border-sky-400 dark:text-sky-400! dark:hover:bg-sky-400/10 dark:focus-visible:border-sky-400 dark:focus-visible:ring-sky-400/40'
                : ''
            )}
          >
            {isConnected
              ? <><CheckIcon className='size-3.5' />Connected</>
              : <><LinkIcon className='size-3.5' />Connect</>}
          </Button>
        </CardContent>

        {/* Name + description */}
        <CardContent>
          <CardTitle className='mb-1.5 font-medium text-sm'>{provider.name}</CardTitle>
          <CardDescription className='text-xs leading-snug'>{provider.description}</CardDescription>
        </CardContent>

        {/* Configured instances */}
        {instances.length > 0 && (
          <CardContent className='pt-0 space-y-1'>
            <Separator className='mb-2' />
            {instances.map((reg) => (
              <div key={reg.id} className='flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs'>
                <div className='flex-1 min-w-0'>
                  <p className='font-medium truncate'>{reg.name}</p>
                  {reg.verified ? (
                    <span className='flex items-center gap-1 text-green-600 dark:text-green-400'>
                      <WifiIcon className='size-3' />Reachable
                    </span>
                  ) : (
                    <span className='flex items-center gap-1 text-destructive'>
                      <WifiOffIcon className='size-3' />Unreachable
                    </span>
                  )}
                </div>
                <Button
                  size='icon' variant='ghost' className='size-6 shrink-0'
                  title='Edit'
                  onClick={() => setEditTarget(reg)}
                >
                  <PencilIcon className='size-3' />
                </Button>
                <Button
                  size='icon' variant='ghost' className='size-6 shrink-0'
                  title='Test connection'
                  disabled={pinging === reg.id}
                  onClick={() => onPing(reg.id)}
                >
                  <RefreshCwIcon className={cn('size-3', pinging === reg.id && 'animate-spin')} />
                </Button>
                <Button
                  size='icon' variant='ghost' className='size-6 shrink-0 hover:text-destructive'
                  title='Delete'
                  onClick={() => setDeleteTarget(reg)}
                >
                  <Trash2Icon className='size-3' />
                </Button>
              </div>
            ))}
          </CardContent>
        )}

        {/* Add another instance */}
        {instances.length > 0 && (
          <CardContent className='pt-0'>
            <Button
              variant='ghost'
              size='sm'
              className='h-7 w-full gap-1.5 text-xs text-muted-foreground'
              onClick={() => setConnectOpen(true)}
            >
              <PlusCircleIcon className='size-3.5' />
              Add another
            </Button>
          </CardContent>
        )}
      </Card>

      {/* Connect modal */}
      <ConnectModal
        provider={provider}
        open={connectOpen}
        onOpenChange={setConnectOpen}
        onSave={onCreate}
      />

      {/* Edit modal */}
      {editTarget && (
        <ConnectModal
          provider={provider}
          existing={editTarget}
          open={!!editTarget}
          onOpenChange={(v) => { if (!v) setEditTarget(null) }}
          onSave={async (data) => {
            await onEdit(editTarget.id, data)
            setEditTarget(null)
          }}
        />
      )}

      {/* Delete confirm */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete registry?</AlertDialogTitle>
            <AlertDialogDescription>
              <strong>{deleteTarget?.name}</strong> and all associated replication rules will be permanently removed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className='bg-destructive text-destructive-foreground hover:bg-destructive/90'
              onClick={async () => {
                if (deleteTarget) await onDelete(deleteTarget.id)
                setDeleteTarget(null)
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ── Main block ────────────────────────────────────────────────────────────────

export function RegistriesList({
  registries,
  loading,
  pinging,
  onCreate,
  onEdit,
  onDelete,
  onPing,
}: RegistriesListProps) {
  const byType = (type: string) => registries.filter((r) => r.registry_type === type)

  if (loading) {
    return (
      <div className='grid gap-6 sm:grid-cols-2 xl:grid-cols-3'>
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className='h-44 rounded-xl border bg-muted/30 animate-pulse' />
        ))}
      </div>
    )
  }

  return (
    <div className='grid gap-6 sm:grid-cols-2 xl:grid-cols-3'>
      {PROVIDERS.map((provider) => (
        <ProviderCard
          key={provider.type}
          provider={provider}
          instances={byType(provider.type)}
          pinging={pinging}
          onCreate={onCreate}
          onEdit={onEdit}
          onDelete={onDelete}
          onPing={onPing}
        />
      ))}
    </div>
  )
}
