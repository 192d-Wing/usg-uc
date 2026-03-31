import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { MatListModule } from '@angular/material/list';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, MatListModule, MatIconModule],
  template: `
    <div class="sidebar-header">
      <div class="logo-icon-wrap">
        <mat-icon class="logo-icon">router</mat-icon>
      </div>
      <div class="logo-text-group">
        <span class="logo-text gradient-text">USG SBC</span>
        <span class="logo-subtitle">Session Border Controller</span>
      </div>
    </div>
    <mat-nav-list>
      <a mat-list-item routerLink="/dashboard" routerLinkActive="active-link">
        <mat-icon matListItemIcon>home</mat-icon>
        <span matListItemTitle>Dashboard</span>
      </a>
      <a mat-list-item routerLink="/registrations" routerLinkActive="active-link">
        <mat-icon matListItemIcon>person</mat-icon>
        <span matListItemTitle>Registrations</span>
      </a>
      <a mat-list-item routerLink="/directory" routerLinkActive="active-link">
        <mat-icon matListItemIcon>dialpad</mat-icon>
        <span matListItemTitle>Directory Numbers</span>
      </a>
      <a mat-list-item routerLink="/dialplans" routerLinkActive="active-link">
        <mat-icon matListItemIcon>rule</mat-icon>
        <span matListItemTitle>Dial Plans</span>
      </a>
      <a mat-list-item routerLink="/trunkgroups" routerLinkActive="active-link">
        <mat-icon matListItemIcon>dns</mat-icon>
        <span matListItemTitle>Trunk Groups</span>
      </a>
      <a mat-list-item routerLink="/users" routerLinkActive="active-link">
        <mat-icon matListItemIcon>people</mat-icon>
        <span matListItemTitle>Users</span>
      </a>
      <a mat-list-item routerLink="/phones" routerLinkActive="active-link">
        <mat-icon matListItemIcon>phone_android</mat-icon>
        <span matListItemTitle>Phones</span>
      </a>
      <a mat-list-item routerLink="/partitions" routerLinkActive="active-link">
        <mat-icon matListItemIcon>folder</mat-icon>
        <span matListItemTitle>Partitions</span>
      </a>
      <a mat-list-item routerLink="/css" routerLinkActive="active-link">
        <mat-icon matListItemIcon>security</mat-icon>
        <span matListItemTitle>Calling Search Spaces</span>
      </a>
      <a mat-list-item routerLink="/routepatterns" routerLinkActive="active-link">
        <mat-icon matListItemIcon>alt_route</mat-icon>
        <span matListItemTitle>Route Patterns</span>
      </a>
      <a mat-list-item routerLink="/routelists" routerLinkActive="active-link">
        <mat-icon matListItemIcon>format_list_numbered</mat-icon>
        <span matListItemTitle>Route Lists</span>
      </a>
      <a mat-list-item routerLink="/cdrs" routerLinkActive="active-link">
        <mat-icon matListItemIcon>history</mat-icon>
        <span matListItemTitle>CDR Records</span>
      </a>
      <a mat-list-item routerLink="/call-ladder" routerLinkActive="active-link">
        <mat-icon matListItemIcon>timeline</mat-icon>
        <span matListItemTitle>Call Ladder</span>
      </a>
    </mat-nav-list>
    <div class="sidebar-footer">
      <span class="version-badge">v0.1.0</span>
    </div>
  `,
  styles: [`
    :host {
      display: flex;
      flex-direction: column;
      height: 100%;
      background: transparent;
    }

    .sidebar-header {
      display: flex;
      align-items: center;
      padding: 24px 16px 20px;
      gap: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .logo-icon-wrap {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 40px;
      height: 40px;
      border-radius: 12px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
      flex-shrink: 0;
    }

    .logo-icon {
      color: #fff;
      font-size: 22px;
      width: 22px;
      height: 22px;
    }

    .logo-text-group {
      display: flex;
      flex-direction: column;
    }

    .logo-text {
      font-size: 18px;
      font-weight: 700;
      letter-spacing: 0.02em;
    }

    .logo-subtitle {
      font-size: 10px;
      color: rgba(255, 255, 255, 0.35);
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    mat-nav-list {
      padding-top: 8px;
      flex: 1;
      overflow-y: auto;
    }

    a[mat-list-item] {
      color: rgba(255, 255, 255, 0.55);
      margin: 1px 8px;
      border-radius: 10px;
      border-left: 3px solid transparent;
      transition: all 250ms ease;
    }

    a[mat-list-item]:hover {
      color: rgba(255, 255, 255, 0.9);
      background: rgba(255, 255, 255, 0.04);
    }

    :host ::ng-deep a[mat-list-item] mat-icon {
      font-size: 22px;
      width: 22px;
      height: 22px;
      opacity: 0.6;
      transition: opacity 250ms ease;
    }

    :host ::ng-deep a[mat-list-item]:hover mat-icon {
      opacity: 0.9;
    }

    :host ::ng-deep .active-link {
      color: rgba(255, 255, 255, 0.95) !important;
      background: rgba(102, 126, 234, 0.12) !important;
      border-left-color: transparent !important;
      position: relative;
    }

    :host ::ng-deep .active-link::before {
      content: '';
      position: absolute;
      left: 0;
      top: 20%;
      bottom: 20%;
      width: 3px;
      border-radius: 0 3px 3px 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      box-shadow: 0 0 8px rgba(102, 126, 234, 0.5);
    }

    :host ::ng-deep .active-link mat-icon {
      color: #667eea;
      opacity: 1 !important;
    }

    .sidebar-footer {
      padding: 12px 16px;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      display: flex;
      justify-content: center;
    }

    .version-badge {
      font-size: 11px;
      color: rgba(255, 255, 255, 0.25);
      padding: 2px 10px;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.04);
      letter-spacing: 0.05em;
    }
  `],
})
export class SidebarComponent {}
