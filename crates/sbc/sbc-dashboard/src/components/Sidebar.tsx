import { useNavigate } from 'react-router-dom';
import SideNavigation, {
  SideNavigationProps,
} from '@cloudscape-design/components/side-navigation';

// Matches the section structure of the prior Angular sidebar.component.ts.
const items: SideNavigationProps.Item[] = [
  { type: 'link', text: 'Dashboard', href: '/dashboard' },

  { type: 'divider' },
  { type: 'section', text: 'User & Device Management', items: [
    { type: 'link', text: 'Users', href: '/users' },
    { type: 'link', text: 'Phones', href: '/phones' },
    { type: 'link', text: 'Registrations', href: '/registrations' },
    { type: 'link', text: 'Directory Numbers', href: '/directory' },
  ]},

  { type: 'section', text: 'Call Routing', items: [
    { type: 'link', text: 'Partitions', href: '/partitions' },
    { type: 'link', text: 'Calling Search Spaces', href: '/css' },
    { type: 'link', text: 'Route Patterns', href: '/routepatterns' },
    { type: 'link', text: 'Route Lists', href: '/routelists' },
    { type: 'link', text: 'Route Groups', href: '/trunkgroups' },
  ]},

  { type: 'section', text: 'Monitoring', items: [
    { type: 'link', text: 'CDR Records', href: '/cdrs' },
    { type: 'link', text: 'Call Ladder', href: '/call-ladder' },
  ]},
];

export function Sidebar({ activePath }: { activePath: string }) {
  const navigate = useNavigate();
  // Cloudscape matches activeHref against item.href. Strip params (e.g.
  // /phones/abc-123 should still highlight /phones).
  const active = activePath.startsWith('/phones/') ? '/phones' : activePath;
  return (
    <SideNavigation
      header={{ text: 'USG SBC', href: '/dashboard' }}
      activeHref={active}
      items={items}
      onFollow={(e) => {
        if (!e.detail.external) {
          e.preventDefault();
          navigate(e.detail.href);
        }
      }}
    />
  );
}
