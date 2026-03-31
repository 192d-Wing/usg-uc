import { Component, inject, OnInit, signal } from '@angular/core';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatChipsModule } from '@angular/material/chips';
import { ApiService } from '../../services/api.service';
import { DialplanEntryDialogComponent } from './dialplan-entry-dialog.component';

@Component({
  selector: 'app-dialplans',
  standalone: true,
  imports: [
    MatTableModule, MatCardModule, MatIconModule, MatButtonModule,
    MatTooltipModule, MatDialogModule, MatChipsModule,
  ],
  template: `
    <div class="dialplans-page">
      <div class="page-header">
        <h2 class="page-title">Dial Plans</h2>
        <span class="spacer"></span>
        <button mat-icon-button (click)="loadPlans()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      @for (plan of plans(); track plan.id) {
        <mat-card class="plan-card">
          <mat-card-header class="plan-header">
            <mat-card-title>
              {{ plan.name || plan.id }}
              @if (plan.active) {
                <span class="active-badge">ACTIVE</span>
              }
            </mat-card-title>
            <span class="spacer"></span>
            <button mat-raised-button color="primary" (click)="openAddEntryDialog(plan.id)">
              <mat-icon>add</mat-icon> Add Entry
            </button>
          </mat-card-header>
          <mat-card-content>
            @if (entries()[plan.id]?.length) {
              <table mat-table [dataSource]="entries()[plan.id]" class="entries-table">
                <ng-container matColumnDef="direction">
                  <th mat-header-cell *matHeaderCellDef>Direction</th>
                  <td mat-cell *matCellDef="let row">{{ row.direction }}</td>
                </ng-container>
                <ng-container matColumnDef="pattern_type">
                  <th mat-header-cell *matHeaderCellDef>Pattern Type</th>
                  <td mat-cell *matCellDef="let row">{{ row.pattern_type }}</td>
                </ng-container>
                <ng-container matColumnDef="pattern_value">
                  <th mat-header-cell *matHeaderCellDef>Pattern Value</th>
                  <td mat-cell *matCellDef="let row">{{ row.pattern_value }}</td>
                </ng-container>
                <ng-container matColumnDef="domain_pattern">
                  <th mat-header-cell *matHeaderCellDef>Domain</th>
                  <td mat-cell *matCellDef="let row">{{ row.domain_pattern || '-' }}</td>
                </ng-container>
                <ng-container matColumnDef="source_trunk">
                  <th mat-header-cell *matHeaderCellDef>Source Trunk</th>
                  <td mat-cell *matCellDef="let row">{{ row.source_trunk || '-' }}</td>
                </ng-container>
                <ng-container matColumnDef="trunk_group">
                  <th mat-header-cell *matHeaderCellDef>Trunk Group</th>
                  <td mat-cell *matCellDef="let row">{{ row.trunk_group }}</td>
                </ng-container>
                <ng-container matColumnDef="destination_type">
                  <th mat-header-cell *matHeaderCellDef>Dest Type</th>
                  <td mat-cell *matCellDef="let row">
                    <span class="type-badge" [class]="'type-' + row.destination_type">
                      {{ formatType(row.destination_type) }}
                    </span>
                  </td>
                </ng-container>
                <ng-container matColumnDef="transform_type">
                  <th mat-header-cell *matHeaderCellDef>Transform</th>
                  <td mat-cell *matCellDef="let row">{{ formatType(row.transform_type || 'none') }}</td>
                </ng-container>
                <ng-container matColumnDef="priority">
                  <th mat-header-cell *matHeaderCellDef>Priority</th>
                  <td mat-cell *matCellDef="let row">{{ row.priority }}</td>
                </ng-container>
                <ng-container matColumnDef="actions">
                  <th mat-header-cell *matHeaderCellDef>Actions</th>
                  <td mat-cell *matCellDef="let row">
                    <button mat-icon-button color="warn" (click)="deleteEntry(plan.id, row.id)"
                            matTooltip="Delete">
                      <mat-icon>delete</mat-icon>
                    </button>
                  </td>
                </ng-container>

                <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: displayedColumns;"></tr>
              </table>
            } @else {
              <p class="empty-msg">No entries in this dial plan.</p>
            }
          </mat-card-content>
        </mat-card>
      } @empty {
        <mat-card class="plan-card">
          <mat-card-content>
            <p class="empty-msg">No dial plans configured.</p>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .dialplans-page { padding: 24px; }

    .page-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 24px;
    }

    .page-title {
      color: #fff;
      margin: 0;
      font-size: 24px;
      font-weight: 500;
    }

    .spacer { flex: 1; }

    .plan-card {
      background: #16213e;
      color: #fff;
      border-radius: 12px;
      margin-bottom: 16px;
    }

    .plan-header {
      display: flex;
      align-items: center;
      padding: 16px;
      background: #0f3460;
      border-radius: 12px 12px 0 0;
    }

    .active-badge {
      display: inline-block;
      margin-left: 12px;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      background: rgba(76, 175, 80, 0.2);
      color: #81c784;
    }

    .entries-table { width: 100%; }

    .type-badge {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 12px;
      text-transform: uppercase;
    }

    .type-trunk_group { background: rgba(124, 77, 255, 0.2); color: #b388ff; }
    .type-registered_user { background: rgba(76, 175, 80, 0.2); color: #81c784; }
    .type-static_uri { background: rgba(0, 188, 212, 0.2); color: #4dd0e1; }

    .empty-msg {
      text-align: center;
      color: rgba(255, 255, 255, 0.5);
      padding: 24px;
    }
  `],
})
export class DialplansComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly displayedColumns = [
    'direction', 'pattern_type', 'pattern_value', 'domain_pattern',
    'source_trunk', 'trunk_group', 'destination_type', 'transform_type',
    'priority', 'actions',
  ];

  readonly plans = signal<any[]>([]);
  readonly entries = signal<Record<string, any[]>>({});

  ngOnInit(): void {
    this.loadPlans();
  }

  loadPlans(): void {
    this.api.getDialPlans().subscribe({
      next: (plans) => {
        this.plans.set(plans);
        for (const plan of plans) {
          this.loadEntries(plan.id);
        }
      },
      error: () => {},
    });
  }

  loadEntries(planId: string): void {
    this.api.getDialPlanEntries(planId).subscribe({
      next: (resp) => {
        const list = resp.entries ?? resp ?? [];
        this.entries.update(e => ({ ...e, [planId]: list }));
      },
      error: () => {},
    });
  }

  openAddEntryDialog(planId: string): void {
    const ref = this.dialog.open(DialplanEntryDialogComponent, { data: { planId } });
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.addDialPlanEntry(planId, result).subscribe({
          next: () => this.loadEntries(planId),
          error: () => {},
        });
      }
    });
  }

  deleteEntry(planId: string, entryId: string): void {
    this.api.deleteDialPlanEntry(planId, entryId).subscribe({
      next: () => this.loadEntries(planId),
      error: () => {},
    });
  }

  formatType(type: string): string {
    return type.replace(/_/g, ' ');
  }
}
