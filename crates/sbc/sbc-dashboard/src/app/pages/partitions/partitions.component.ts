import { Component, inject, OnInit, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatTableModule } from '@angular/material/table';
import { ApiService } from '../../services/api.service';
import { PartitionDialogComponent } from './partition-dialog.component';

@Component({
  selector: 'app-partitions',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatTableModule,
  ],
  template: `
    <div class="partitions-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Partitions</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddDialog()">
          <mat-icon>add</mat-icon> Add Partition
        </button>
        <button mat-icon-button (click)="loadPartitions()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      @if (partitions().length) {
        <mat-card class="table-card">
          <table mat-table [dataSource]="partitions()" class="partitions-table">
            <ng-container matColumnDef="id">
              <th mat-header-cell *matHeaderCellDef>ID</th>
              <td mat-cell *matCellDef="let row">{{ row.id }}</td>
            </ng-container>
            <ng-container matColumnDef="name">
              <th mat-header-cell *matHeaderCellDef>Name</th>
              <td mat-cell *matCellDef="let row">{{ row.name }}</td>
            </ng-container>
            <ng-container matColumnDef="description">
              <th mat-header-cell *matHeaderCellDef>Description</th>
              <td mat-cell *matCellDef="let row">{{ row.description }}</td>
            </ng-container>
            <ng-container matColumnDef="route_pattern_count">
              <th mat-header-cell *matHeaderCellDef>Route Patterns</th>
              <td mat-cell *matCellDef="let row">{{ row.route_pattern_count ?? 0 }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let row">
                <button mat-icon-button color="warn" (click)="deletePartition(row.id || row.name)"
                        matTooltip="Delete Partition">
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
            <p class="empty-msg">No partitions configured.</p>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .partitions-page { padding: 24px; }

    .partitions-table { width: 100%; }
  `],
})
export class PartitionsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly displayedColumns = ['id', 'name', 'description', 'route_pattern_count', 'actions'];

  readonly partitions = signal<any[]>([]);

  ngOnInit(): void {
    this.loadPartitions();
  }

  loadPartitions(): void {
    this.api.getPartitions().subscribe({
      next: (partitions) => this.partitions.set(partitions),
      error: () => {},
    });
  }

  openAddDialog(): void {
    const ref = this.dialog.open(PartitionDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.createPartition(result).subscribe({
          next: () => this.loadPartitions(),
          error: () => {},
        });
      }
    });
  }

  deletePartition(id: string): void {
    this.api.deletePartition(id).subscribe({
      next: () => this.loadPartitions(),
      error: () => {},
    });
  }
}
