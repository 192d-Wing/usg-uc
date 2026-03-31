import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'dashboard',
    loadComponent: () =>
      import('./pages/dashboard/dashboard.component').then((m) => m.DashboardComponent),
  },
  {
    path: 'registrations',
    loadComponent: () =>
      import('./pages/registrations/registrations.component').then((m) => m.RegistrationsComponent),
  },
  {
    path: 'directory',
    loadComponent: () =>
      import('./pages/directory/directory.component').then((m) => m.DirectoryComponent),
  },
  {
    path: 'cdrs',
    loadComponent: () =>
      import('./pages/cdrs/cdrs.component').then((m) => m.CdrsComponent),
  },
  {
    path: 'call-ladder',
    loadComponent: () =>
      import('./pages/call-ladder/call-ladder.component').then((m) => m.CallLadderPageComponent),
  },
  {
    path: 'dialplans',
    loadComponent: () =>
      import('./pages/dialplans/dialplans.component').then(m => m.DialplansComponent),
  },
  {
    path: 'trunkgroups',
    loadComponent: () =>
      import('./pages/trunkgroups/trunkgroups.component').then(m => m.TrunkgroupsComponent),
  },
  {
    path: 'users',
    loadComponent: () =>
      import('./pages/users/users.component').then(m => m.UsersComponent),
  },
  {
    path: 'phones',
    loadComponent: () =>
      import('./pages/phones/phones.component').then(m => m.PhonesComponent),
  },
  {
    path: 'partitions',
    loadComponent: () =>
      import('./pages/partitions/partitions.component').then(m => m.PartitionsComponent),
  },
  {
    path: 'css',
    loadComponent: () =>
      import('./pages/css-editor/css-editor.component').then(m => m.CssEditorComponent),
  },
  {
    path: 'routepatterns',
    loadComponent: () =>
      import('./pages/route-patterns/route-patterns.component').then(m => m.RoutePatternsComponent),
  },
  {
    path: 'routelists',
    loadComponent: () =>
      import('./pages/route-lists/route-lists.component').then(m => m.RouteListsComponent),
  },
  { path: '**', redirectTo: 'dashboard' },
];
