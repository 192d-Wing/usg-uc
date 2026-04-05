import { Component, inject, OnInit, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatTableModule } from '@angular/material/table';
import { MatChipsModule } from '@angular/material/chips';
import { ApiService } from '../../services/api.service';
import { UserDialogComponent } from './user-dialog.component';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatTableModule, MatChipsModule,
  ],
  template: `
    <div class="users-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Users</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddDialog()">
          <mat-icon>add</mat-icon> Add User
        </button>
        <button mat-icon-button (click)="loadUsers()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      @if (users().length) {
        <mat-card class="table-card">
          <table mat-table [dataSource]="users()" class="users-table">
            <ng-container matColumnDef="username">
              <th mat-header-cell *matHeaderCellDef>Username</th>
              <td mat-cell *matCellDef="let row">{{ row.username }}</td>
            </ng-container>
            <ng-container matColumnDef="display_name">
              <th mat-header-cell *matHeaderCellDef>Display Name</th>
              <td mat-cell *matCellDef="let row">{{ row.display_name }}</td>
            </ng-container>
            <ng-container matColumnDef="email">
              <th mat-header-cell *matHeaderCellDef>Email</th>
              <td mat-cell *matCellDef="let row">{{ row.email }}</td>
            </ng-container>
            <ng-container matColumnDef="auth_type">
              <th mat-header-cell *matHeaderCellDef>Auth Type</th>
              <td mat-cell *matCellDef="let row">
                <span class="auth-chip" [class]="'auth-' + row.auth_type">
                  {{ formatAuthType(row.auth_type) }}
                </span>
              </td>
            </ng-container>
            <ng-container matColumnDef="css">
              <th mat-header-cell *matHeaderCellDef>CSS</th>
              <td mat-cell *matCellDef="let row">{{ row.calling_search_space }}</td>
            </ng-container>
            <ng-container matColumnDef="enabled">
              <th mat-header-cell *matHeaderCellDef>Enabled</th>
              <td mat-cell *matCellDef="let row">
                <mat-icon [class.enabled]="row.enabled !== false">
                  {{ row.enabled !== false ? 'check_circle' : 'cancel' }}
                </mat-icon>
              </td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let row">
                <button mat-icon-button color="primary" (click)="openEditDialog(row)"
                        matTooltip="Edit User">
                  <mat-icon>edit</mat-icon>
                </button>
                <button mat-icon-button color="warn" (click)="deleteUser(row.id)"
                        matTooltip="Delete User">
                  <mat-icon>delete</mat-icon>
                </button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns;"></tr>
          </table>
        </mat-card>
      } @else {
        <mat-card class="empty-card">
          <mat-card-content>
            <p class="empty-msg">No users configured.</p>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .users-page { padding: 24px; }

    .users-table { width: 100%; }

    .auth-chip {
      padding: 3px 10px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .auth-digest {
      background: rgba(74, 222, 128, 0.15);
      color: var(--color-success);
      border-color: rgba(74, 222, 128, 0.25);
    }

    .auth-mtls_pki {
      background: rgba(0, 94, 162, 0.15);
      color: var(--uswds-primary-light);
      border-color: rgba(0, 94, 162, 0.3);
    }

    .auth-both {
      background: rgba(168, 85, 247, 0.15);
      color: #c4b5fd;
      border-color: rgba(168, 85, 247, 0.25);
    }

    .enabled { color: var(--color-success); }
    mat-icon:not(.enabled) { color: rgba(255, 255, 255, 0.2); }
  `],
})
export class UsersComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly displayedColumns = [
    'username', 'display_name', 'email', 'auth_type', 'css', 'enabled', 'actions',
  ];

  readonly users = signal<any[]>([]);

  ngOnInit(): void {
    this.loadUsers();
  }

  loadUsers(): void {
    this.api.getUsers().subscribe({
      next: (users) => this.users.set(users),
      error: () => {},
    });
  }

  openAddDialog(): void {
    const ref = this.dialog.open(UserDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.createUser(result).subscribe({
          next: () => this.loadUsers(),
          error: () => {},
        });
      }
    });
  }

  openEditDialog(user: any): void {
    const ref = this.dialog.open(UserDialogComponent, { data: user });
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.updateUser(result.id, result).subscribe({
          next: () => this.loadUsers(),
          error: () => {},
        });
      }
    });
  }

  deleteUser(id: string): void {
    this.api.deleteUser(id).subscribe({
      next: () => this.loadUsers(),
      error: () => {},
    });
  }

  formatAuthType(type: string): string {
    if (type === 'digest') return 'Digest';
    if (type === 'mtls_pki') return 'mTLS';
    if (type === 'both') return 'Both';
    return type;
  }
}
