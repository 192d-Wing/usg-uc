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
  { path: '**', redirectTo: 'dashboard' },
];
