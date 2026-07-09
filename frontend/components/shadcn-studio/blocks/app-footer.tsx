import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { CodeIcon } from 'lucide-react'

export default function AppFooter() {
  return (
    <footer className='flex items-center justify-between gap-3 border-t px-4 py-3 max-sm:flex-col sm:gap-6 sm:px-6'>
      <p className='text-muted-foreground text-sm text-balance max-sm:text-center'>
        {`©${new Date().getFullYear()} `}
        <a
          href='https://github.com/fish-not-phish/siene'
          target='_blank'
          rel='noopener noreferrer'
          className='text-primary hover:underline'
        >
          Siene
        </a>
        {' — self-hosted container registry UI'}
      </p>

      <Button variant='ghost' size='sm' className='text-muted-foreground' asChild>
        <Link href='/developer'>
          <CodeIcon className='size-4' />
          <span>API</span>
        </Link>
      </Button>
    </footer>
  )
}
