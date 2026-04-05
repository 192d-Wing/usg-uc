import { Component, inject, OnInit, signal } from '@angular/core';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { ApiService } from '../../services/api.service';
import { DirectoryDialogComponent } from './directory-dialog.component';

@Component({
  selector: 'app-directory',
  standalone: true,
  imports: [
    MatTableModule, MatCardModule, MatIconModule, MatButtonModule,
    MatSlideToggleModule, MatTooltipModule, MatDialogModule,
  ],
  template: `
    <div class="directory-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Directory Numbers</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddDialog()">
          <mat-icon>add</mat-icon> Add Number
        </button>
        <button mat-icon-button (click)="loadNumbers()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      <mat-card class="table-card">
        <mat-card-content>
          <table mat-table [dataSource]="numbers()" class="dir-table">
            <ng-container matColumnDef="did">
              <th mat-header-cell *matHeaderCellDef>DID</th>
              <td mat-cell *matCellDef="let row">{{ row.did }}</td>
            </ng-container>
            <ng-container matColumnDef="user">
              <th mat-header-cell *matHeaderCellDef>User</th>
              <td mat-cell *matCellDef="let row">{{ row.user }}</td>
            </ng-container>
            <ng-container matColumnDef="description">
              <th mat-header-cell *matHeaderCellDef>Description</th>
              <td mat-cell *matCellDef="let row">{{ row.description }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let row">
                <button mat-icon-button color="warn" (click)="deleteNumber(row)"
                        matTooltip="Delete">
                  <mat-icon>delete</mat-icon>
                </button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns;"></tr>
          </table>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .directory-page { padding: 24px; }

    .dir-table { width: 100%; }

    .type-badge {
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .type-trunk_group {
      background: rgba(0, 94, 162, 0.15);
      color: var(--uswds-primary-light);
      border-color: rgba(0, 94, 162, 0.3);
    }

    .type-registered_user {
      background: rgba(74, 222, 128, 0.15);
      color: var(--color-success);
      border-color: rgba(74, 222, 128, 0.25);
    }

    .type-static_uri {
      background: rgba(0, 188, 212, 0.15);
      color: #67e8f9;
      border-color: rgba(0, 188, 212, 0.25);
    }
  `],
})
export class DirectoryComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly displayedColumns = ['did', 'user', 'description', 'actions'];
  readonly numbers = signal<any[]>([]);

  ngOnInit(): void {
    this.loadNumbers();
  }

  loadNumbers(): void {
    this.api.getDirectoryNumbers().subscribe({
      next: (nums) => this.numbers.set(nums),
      error: () => {},
    });
  }

  openAddDialog(): void {
    const ref = this.dialog.open(DirectoryDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.addDirectoryNumber(result).subscribe({
          next: () => this.loadNumbers(),
          error: () => {},
        });
      }
    });
  }

  deleteNumber(dn: any): void {
    this.api.deleteDirectoryNumber(dn.did).subscribe({
      next: () => this.loadNumbers(),
      error: () => {},
    });
  }

}
