'use client'

import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from '@/components/ui/sidebar'
import { ChevronRightIcon, PlusIcon, BoxesIcon } from 'lucide-react'
import { useProjects } from '@/providers/ProjectsContext'
import type { Project } from '@/services/projects'

const ProjectSwitcher = () => {
  const { isMobile } = useSidebar()
  const router = useRouter()
  const pathname = usePathname()
  const { projects } = useProjects()

  const { lastProject, setLastProject } = useProjects()
  const [active, setActive] = useState<Project | null>(null)

  const slugFromPath = pathname.match(/^\/projects\/([^/]+)/)?.[1] ?? null
  // Active slug: current URL > last visited > first project
  const activeSlug = slugFromPath ?? lastProject

  // Sync active project from URL, lastProject, or first available
  useEffect(() => {
    if (projects.length === 0) return
    const resolved = projects.find((p) => p.name === activeSlug) ?? projects[0]
    setActive(resolved)
  }, [activeSlug, projects])

  const handleSelect = (project: Project) => {
    setActive(project)
    setLastProject(project.name)
    router.push(`/projects/${project.name}/repositories`)
  }

  if (!active && projects.length === 0) {
    return (
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton size='lg' onClick={() => router.push('/projects/new')}>
            <div className='flex size-8 items-center justify-center rounded-md bg-muted'>
              <BoxesIcon className='size-4' />
            </div>
            <span className='text-sm text-muted-foreground'>No projects</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    )
  }

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size='lg'
              className='data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground'
            >
              {/* Project avatar — first two letters of name */}
              <div className='flex size-8 shrink-0 items-center justify-center rounded-md bg-primary/10 font-semibold text-xs uppercase text-primary'>
                {active?.name.slice(0, 2) ?? '??'}
              </div>
              <div className='flex flex-col items-start leading-tight'>
                <span className='text-sm font-medium truncate max-w-32'>{active?.name ?? '…'}</span>
                <span className='text-xs font-light text-muted-foreground'>Project</span>
              </div>
              <ChevronRightIcon className='ml-auto size-4 transition-transform duration-200 max-lg:rotate-90 [[data-state=open]>&]:rotate-270 lg:[[data-state=open]>&]:rotate-180' />
            </SidebarMenuButton>
          </DropdownMenuTrigger>

          <DropdownMenuContent
            className='w-(--radix-dropdown-menu-trigger-width) min-w-56'
            side={isMobile ? 'bottom' : 'right'}
            sideOffset={isMobile ? 8 : 16}
          >
            {projects.map((project) => (
              <DropdownMenuCheckboxItem
                key={project.name}
                className='gap-3 px-3 py-2.5 [&>span]:hidden'
                checked={active?.name === project.name}
                onCheckedChange={() => handleSelect(project)}
              >
                <div className='flex size-8 shrink-0 items-center justify-center rounded-md bg-primary/10 font-semibold text-xs uppercase text-primary'>
                  {project.name.slice(0, 2)}
                </div>
                <div className='flex flex-col items-start'>
                  <span className='text-sm font-medium'>{project.name}</span>
                  <span className='text-muted-foreground text-xs'>
                    {project.public ? 'Public' : 'Private'}
                  </span>
                </div>
              </DropdownMenuCheckboxItem>
            ))}

            <DropdownMenuSeparator />

            <DropdownMenuItem
              className='gap-2 text-primary focus:text-primary'
              onSelect={() => router.push('/projects/new')}
            >
              <PlusIcon className='size-4' />
              <span>New project</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}

export default ProjectSwitcher
