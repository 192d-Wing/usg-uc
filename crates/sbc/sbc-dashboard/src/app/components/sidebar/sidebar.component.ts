import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, MatIconModule],
  template: `
    <nav class="usa-sidenav">
      <a class="usa-sidenav__item" routerLink="/dashboard" routerLinkActive="usa-current">
        <mat-icon>home</mat-icon>
        <span>Dashboard</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/registrations" routerLinkActive="usa-current">
        <mat-icon>person</mat-icon>
        <span>Registrations</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/directory" routerLinkActive="usa-current">
        <mat-icon>dialpad</mat-icon>
        <span>Directory Numbers</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/dialplans" routerLinkActive="usa-current">
        <mat-icon>rule</mat-icon>
        <span>Dial Plans</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/trunkgroups" routerLinkActive="usa-current">
        <mat-icon>dns</mat-icon>
        <span>Trunk Groups</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/users" routerLinkActive="usa-current">
        <mat-icon>people</mat-icon>
        <span>Users</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/phones" routerLinkActive="usa-current">
        <mat-icon>phone_android</mat-icon>
        <span>Phones</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/partitions" routerLinkActive="usa-current">
        <mat-icon>folder</mat-icon>
        <span>Partitions</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/css" routerLinkActive="usa-current">
        <mat-icon>security</mat-icon>
        <span>Calling Search Spaces</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/routepatterns" routerLinkActive="usa-current">
        <mat-icon>alt_route</mat-icon>
        <span>Route Patterns</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/routelists" routerLinkActive="usa-current">
        <mat-icon>format_list_numbered</mat-icon>
        <span>Route Lists</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/cdrs" routerLinkActive="usa-current">
        <mat-icon>history</mat-icon>
        <span>CDR Records</span>
      </a>
      <a class="usa-sidenav__item" routerLink="/call-ladder" routerLinkActive="usa-current">
        <mat-icon>timeline</mat-icon>
        <span>Call Ladder</span>
      </a>
    </nav>
  `,
  styles: [`
    :host {
      display: block;
      padding: 8px 0;
    }

    .usa-sidenav {
      list-style: none;
      padding: 0;
      margin: 0;
      border: none;
    }

    .usa-sidenav__item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 16px;
      color: var(--uswds-text-secondary);
      text-decoration: none;
      font-size: 14px;
      font-weight: 400;
      border-left: 3px solid transparent;
      transition: all 200ms ease;
      cursor: pointer;
    }

    .usa-sidenav__item:hover {
      color: var(--uswds-text);
      background: var(--uswds-hover);
    }

    .usa-sidenav__item mat-icon {
      font-size: 20px;
      width: 20px;
      height: 20px;
      opacity: 0.6;
      transition: opacity 200ms ease;
    }

    .usa-sidenav__item:hover mat-icon {
      opacity: 0.9;
    }

    .usa-sidenav__item.usa-current {
      color: var(--uswds-text);
      background: rgba(0, 94, 162, 0.15);
      border-left-color: var(--uswds-primary);
      font-weight: 700;
    }

    .usa-sidenav__item.usa-current mat-icon {
      color: var(--uswds-primary-light);
      opacity: 1;
    }
  `],
})
export class SidebarComponent {}
