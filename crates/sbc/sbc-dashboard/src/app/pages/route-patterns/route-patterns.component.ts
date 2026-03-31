import { Component, inject, OnInit, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatTableModule } from '@angular/material/table';
import { ApiService } from '../../services/api.service';
import { RoutePatternDialogComponent } from './route-pattern-dialog.component';

@Component({
  selector: 'app-route-patterns',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatTableModule,
  ],
  template: `
    <div class="rp-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Route Patterns</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddDialog()">
          <mat-icon>add</mat-icon> Add Route Pattern
        </button>
        <button mat-icon-button (click)="loadPatterns()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      @if (patterns().length) {
        <mat-card class="table-card">
          <table mat-table [dataSource]="patterns()" class="rp-table">
            <ng-container matColumnDef="pattern">
              <th mat-header-cell *matHeaderCellDef>Pattern</th>
              <td mat-cell *matCellDef="let row">
                <code class="pattern-code">{{ row.pattern }}</code>
              </td>
            </ng-container>
            <ng-container matColumnDef="partition">
              <th mat-header-cell *matHeaderCellDef>Partition</th>
              <td mat-cell *matCellDef="let row">{{ row.partition }}</td>
            </ng-container>
            <ng-container matColumnDef="route_target">
              <th mat-header-cell *matHeaderCellDef>Route List / Group</th>
              <td mat-cell *matCellDef="let row">{{ row.route_list_id || row.route_group_id || '-' }}</td>
            </ng-container>
            <ng-container matColumnDef="transform">
              <th mat-header-cell *matHeaderCellDef>Transform</th>
              <td mat-cell *matCellDef="let row">{{ row.called_party_transform || '-' }}</td>
            </ng-container>
            <ng-container matColumnDef="priority">
              <th mat-header-cell *matHeaderCellDef>Priority</th>
              <td mat-cell *matCellDef="let row">{{ row.priority ?? 0 }}</td>
            </ng-container>
            <ng-container matColumnDef="blocked">
              <th mat-header-cell *matHeaderCellDef>Blocked</th>
              <td mat-cell *matCellDef="let row">
                <mat-icon [class.blocked]="row.blocked">
                  {{ row.blocked ? 'block' : 'check_circle_outline' }}
                </mat-icon>
              </td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let row">
                <button mat-icon-button color="warn" (click)="deletePattern(row.id)"
                        matTooltip="Delete Route Pattern">
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
            <p class="empty-msg">No route patterns configured.</p>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .rp-page { padding: 24px; }

    .rp-table { width: 100%; }

    .pattern-code {
      padding: 3px 10px;
      border-radius: 4px;
      font-family: 'Source Code Pro', 'Roboto Mono', monospace;
      font-size: 13px;
      background: rgba(0, 94, 162, 0.12);
      color: var(--uswds-primary-light);
      border: 1px solid rgba(0, 94, 162, 0.2);
    }

    .blocked { color: var(--color-error); }
    mat-icon:not(.blocked) { color: rgba(255, 255, 255, 0.2); }
  `],
})
export class RoutePatternsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly displayedColumns = [
    'pattern', 'partition', 'route_target', 'transform', 'priority', 'blocked', 'actions',
  ];

  readonly patterns = signal<any[]>([]);

  ngOnInit(): void {
    this.loadPatterns();
  }

  loadPatterns(): void {
    this.api.getRoutePatterns().subscribe({
      next: (patterns) => this.patterns.set(patterns),
      error: () => {},
    });
  }

  openAddDialog(): void {
    const ref = this.dialog.open(RoutePatternDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.createRoutePattern(result).subscribe({
          next: () => this.loadPatterns(),
          error: () => {},
        });
      }
    });
  }

  deletePattern(id: string): void {
    this.api.deleteRoutePattern(id).subscribe({
      next: () => this.loadPatterns(),
      error: () => {},
    });
  }
}
