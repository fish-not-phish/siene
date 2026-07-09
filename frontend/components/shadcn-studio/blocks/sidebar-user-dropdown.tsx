'use client'

import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from '@/components/ui/sidebar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ChevronRightIcon, UserIcon, LogOutIcon, KeyRoundIcon, ShieldCheckIcon } from 'lucide-react'
import Link from 'next/link'
import { useAuthContext } from '@/store/AuthContext'
import { baseUrlAccounts } from '@/constants/constants'

async function postLogout(csrfToken: string) {
  await fetch(`${baseUrlAccounts}accounts/logout/`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-CSRFToken': csrfToken },
  })
  window.location.href = `${baseUrlAccounts}accounts/login/`
}

const SidebarUserDropdown = () => {
  const { isMobile } = useSidebar()
  const { user } = useAuthContext()

  const initials = user.username
    ? user.username.slice(0, 2).toUpperCase()
    : '?'

  const displayName = user.username ?? 'Account'
  const displaySub = user.isAdmin ? 'Admin' : (user.email ?? '')

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size='lg'
              className='data-open:bg-sidebar-accent data-open:text-sidebar-accent-foreground'
            >
              <Avatar className='rounded-lg after:rounded-[inherit]'>
                <AvatarFallback className='rounded-[inherit] bg-primary/10 text-primary text-xs font-semibold'>
                  {initials}
                </AvatarFallback>
              </Avatar>
              <div className='grid flex-1 text-left text-sm leading-tight'>
                <span className='truncate font-medium'>{displayName}</span>
                <span className='text-muted-foreground truncate text-xs'>{displaySub}</span>
              </div>
              <ChevronRightIcon className='ml-auto size-4 transition-transform duration-200 max-lg:rotate-270 [[data-state=open]>&]:rotate-90 lg:[[data-state=open]>&]:-rotate-180' />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className='w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg'
            side={isMobile ? 'bottom' : 'right'}
            align='end'
            sideOffset={isMobile ? 8 : 16}
          >
            <DropdownMenuGroup>
              <DropdownMenuLabel className='p-0 font-normal'>
                <div className='flex items-center gap-2 px-1 py-1.5 text-left text-sm'>
                  <Avatar className='rounded-lg'>
                    <AvatarFallback className='rounded-lg bg-primary/10 text-primary text-xs font-semibold'>
                      {initials}
                    </AvatarFallback>
                  </Avatar>
                  <div className='grid flex-1 text-left text-sm leading-tight'>
                    <span className='text-popover-foreground truncate font-medium'>{displayName}</span>
                    <span className='text-muted-foreground truncate text-xs'>{user.email ?? ''}</span>
                  </div>
                </div>
              </DropdownMenuLabel>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem asChild>
                <Link href='/profile'>
                  <UserIcon />
                  Profile
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href='/profile/tokens'>
                  <KeyRoundIcon />
                  Access tokens
                </Link>
              </DropdownMenuItem>
              {user.isAdmin && (
                <DropdownMenuItem asChild>
                  <Link href='/admin/users'>
                    <ShieldCheckIcon />
                    Admin
                  </Link>
                </DropdownMenuItem>
              )}
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => postLogout(user.csrfToken ?? '')}>
              <LogOutIcon />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}

export default SidebarUserDropdown
