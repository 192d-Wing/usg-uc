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
      <mat-icon class="logo-icon">router</mat-icon>
      <span class="logo-text">SBC Manager</span>
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
      <a mat-list-item routerLink="/cdrs" routerLinkActive="active-link">
        <mat-icon matListItemIcon>history</mat-icon>
        <span matListItemTitle>CDR Records</span>
      </a>
      <a mat-list-item routerLink="/call-ladder" routerLinkActive="active-link">
        <mat-icon matListItemIcon>timeline</mat-icon>
        <span matListItemTitle>Call Ladder</span>
      </a>
    </mat-nav-list>
  `,
  styles: [`
    :host {
      display: flex;
      flex-direction: column;
      height: 100%;
      background: #1a1a2e;
    }

    .sidebar-header {
      display: flex;
      align-items: center;
      padding: 20px 16px;
      gap: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }

    .logo-icon {
      color: #7c4dff;
      font-size: 28px;
      width: 28px;
      height: 28px;
    }

    .logo-text {
      color: #fff;
      font-size: 18px;
      font-weight: 500;
    }

    mat-nav-list {
      padding-top: 8px;
    }

    a[mat-list-item] {
      color: rgba(255, 255, 255, 0.7);
      margin: 2px 8px;
      border-radius: 8px;
    }

    a[mat-list-item]:hover {
      color: #fff;
      background: rgba(255, 255, 255, 0.05);
    }

    :host ::ng-deep .active-link {
      color: #fff !important;
      background: rgba(124, 77, 255, 0.2) !important;
    }

    :host ::ng-deep .active-link mat-icon {
      color: #7c4dff;
    }
  `],
})
export class SidebarComponent {}
