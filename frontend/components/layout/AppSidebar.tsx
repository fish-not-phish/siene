'use client'

import type { ReactElement } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useTheme } from 'next-themes'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from '@/components/ui/sidebar'
import WorkspaceSwitcher from '@/components/shadcn-studio/blocks/sidebar-workspace-switcher'
import SidebarUserDropdown from '@/components/shadcn-studio/blocks/sidebar-user-dropdown'
import { useAuthContext } from '@/store/AuthContext'
import { useProjects } from '@/providers/ProjectsContext'
import {
  BoxesIcon,
  GaugeIcon,
  LayoutDashboardIcon,
  UsersIcon,
  BotIcon,
  SettingsIcon,
  ScrollTextIcon,
  WrenchIcon,
  PlusIcon,
  TagIcon,
  Globe2Icon,
  ArrowLeftRightIcon,
  ShieldAlertIcon,
  SunIcon,
  MoonIcon,
  MonitorIcon,
} from 'lucide-react'

type NavItem = {
  icon: ReactElement
  label: string
  href: string
  badge?: string
}

const useProjectNav = (): NavItem[] => {
  const pathname = usePathname()
  const { lastProject } = useProjects()

  // Use the slug from the current URL if on a project route,
  // otherwise fall back to the last visited project so the nav
  // stays visible on /profile, /admin/*, /dashboard, etc.
  const slugFromPath = pathname.match(/^\/projects\/([^/]+)/)?.[1] ?? null
  const project = slugFromPath ?? lastProject

  if (!project) return []

  return [
    { icon: <GaugeIcon />,         label: 'Overview',       href: `/projects/${project}` },
    { icon: <BoxesIcon />,         label: 'Repositories',   href: `/projects/${project}/repositories` },
    { icon: <UsersIcon />,         label: 'Members',        href: `/projects/${project}/members` },
    { icon: <BotIcon />,           label: 'Robot Accounts', href: `/projects/${project}/robots` },
    { icon: <TagIcon />,           label: 'Labels',         href: `/projects/${project}/labels` },
    { icon: <ShieldAlertIcon />,   label: 'Security',       href: `/projects/${project}/security` },
    { icon: <ScrollTextIcon />,    label: 'Audit Logs',     href: `/projects/${project}/logs` },
    { icon: <SettingsIcon />,      label: 'Settings',       href: `/projects/${project}/settings` },
  ]
}

const adminNav: NavItem[] = [
  { icon: <LayoutDashboardIcon />, label: 'Dashboard',          href: '/admin/dashboard' },
  { icon: <UsersIcon />,          label: 'Users',              href: '/admin/users' },
  { icon: <ScrollTextIcon />,     label: 'Audit Logs',         href: '/admin/logs' },
  { icon: <ShieldAlertIcon />,    label: 'Security Hub',       href: '/admin/security' },
  { icon: <Globe2Icon />,         label: 'Remote Registries',  href: '/admin/registries' },
  { icon: <ArrowLeftRightIcon />, label: 'Replications',       href: '/admin/replications' },
  { icon: <WrenchIcon />,         label: 'Jobs & GC',          href: '/admin/jobs' },
  { icon: <SettingsIcon />,       label: 'Settings',           href: '/admin/settings' },
]



// Exact match for the project overview (/projects/[slug]), prefix match for everything else
function isNavItemActive(href: string, pathname: string): boolean {
  if (/^\/projects\/[^/]+$/.test(href)) return pathname === href
  return pathname.startsWith(href)
}

function NavGroup({ items, label }: { items: NavItem[]; label?: string }) {
  const pathname = usePathname()
  return (
    <SidebarGroup>
      {label && <SidebarGroupLabel>{label}</SidebarGroupLabel>}
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map(item => (
            <SidebarMenuItem key={item.label}>
              <SidebarMenuButton tooltip={item.label} asChild isActive={isNavItemActive(item.href, pathname)}>
                <Link href={item.href}>
                  {item.icon}
                  <span>{item.label}</span>
                </Link>
              </SidebarMenuButton>
              {item.badge && (
                <SidebarMenuBadge className='bg-primary/10 top-1/2! right-2 -translate-y-1/2! rounded-full'>
                  {item.badge}
                </SidebarMenuBadge>
              )}
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}

function ThemeToggle() {
  const { theme, setTheme } = useTheme()

  const next = theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light'
  const label = theme === 'light' ? 'Switch to dark' : theme === 'dark' ? 'Switch to system' : 'Switch to light'
  const Icon = theme === 'light' ? SunIcon : theme === 'dark' ? MoonIcon : MonitorIcon
  const modeLabel = theme === 'light' ? 'Light' : theme === 'dark' ? 'Dark' : 'System'

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant='ghost'
            className='w-full justify-start gap-2 text-muted-foreground hover:text-foreground [[data-state=collapsed]_&]:size-8 [[data-state=collapsed]_&]:justify-center [[data-state=collapsed]_&]:px-0'
            onClick={() => setTheme(next)}
            aria-label={label}
          >
            <Icon className='size-4 shrink-0' />
            <span className='[[data-state=collapsed]_&]:hidden'>{modeLabel}</span>
          </Button>
        </TooltipTrigger>
        <TooltipContent side='right'>{label}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

export default function AppSidebar() {
  const { user } = useAuthContext()
  const projectNav = useProjectNav()

  return (
    <Sidebar collapsible='icon'>
      <SidebarHeader>
        <WorkspaceSwitcher />
      </SidebarHeader>

      <SidebarContent>
        {projectNav.length > 0 && (
          <NavGroup items={projectNav} label='Project' />
        )}
        {user.isAdmin && (
          <NavGroup items={adminNav} label='System' />
        )}
      </SidebarContent>

      <SidebarFooter className='gap-2 p-3 transition-[padding] duration-200 [[data-state=collapsed]_&]:p-2'>
        <ThemeToggle />

        <Button
          className='bg-primary/10 text-primary hover:bg-primary/20 focus-visible:ring-primary/20 dark:focus-visible:ring-primary/40'
          asChild
        >
          <Link href='/projects/new'>
            <span className='truncate [[data-state=collapsed]_&]:hidden'>New project</span>
            <PlusIcon />
          </Link>
        </Button>

        <SidebarUserDropdown />
      </SidebarFooter>
    </Sidebar>
  )
}
