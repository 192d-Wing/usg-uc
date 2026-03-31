import { Component, inject, OnInit, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatTableModule } from '@angular/material/table';
import { ApiService } from '../../services/api.service';
import { RouteListDialogComponent } from './route-list-dialog.component';

@Component({
  selector: 'app-route-lists',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatExpansionModule, MatTableModule,
  ],
  template: `
    <div class="rl-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Route Lists</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddDialog()">
          <mat-icon>add</mat-icon> Add Route List
        </button>
        <button mat-icon-button (click)="loadRouteLists()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      <mat-accordion>
        @for (rl of routeLists(); track rl.id) {
          <mat-expansion-panel class="rl-panel">
            <mat-expansion-panel-header>
              <mat-panel-title>
                <mat-icon class="rl-icon">format_list_numbered</mat-icon>
                {{ rl.name || rl.id }}
              </mat-panel-title>
              <mat-panel-description>
                Members: {{ rl.route_groups?.length || 0 }}
              </mat-panel-description>
            </mat-expansion-panel-header>

            <div class="panel-actions">
              <button mat-raised-button color="primary" (click)="openEditDialog(rl)">
                <mat-icon>edit</mat-icon> Edit Route List
              </button>
              <button mat-raised-button color="warn" (click)="deleteRouteList(rl.id)">
                <mat-icon>delete</mat-icon> Delete Route List
              </button>
            </div>

            @if (rl.route_groups?.length) {
              <table mat-table [dataSource]="rl.route_groups" class="rg-table">
                <ng-container matColumnDef="order">
                  <th mat-header-cell *matHeaderCellDef>Order</th>
                  <td mat-cell *matCellDef="let row; let i = index">{{ i + 1 }}</td>
                </ng-container>
                <ng-container matColumnDef="route_group_id">
                  <th mat-header-cell *matHeaderCellDef>Route Group ID</th>
                  <td mat-cell *matCellDef="let row">{{ row.route_group_id || row.id }}</td>
                </ng-container>
                <ng-container matColumnDef="name">
                  <th mat-header-cell *matHeaderCellDef>Name</th>
                  <td mat-cell *matCellDef="let row">{{ row.name || '-' }}</td>
                </ng-container>
                <ng-container matColumnDef="priority">
                  <th mat-header-cell *matHeaderCellDef>Priority</th>
                  <td mat-cell *matCellDef="let row">{{ row.priority ?? 0 }}</td>
                </ng-container>

                <tr mat-header-row *matHeaderRowDef="rgColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: rgColumns;"></tr>
              </table>
            } @else {
              <p class="empty-msg">No route groups in this list.</p>
            }
          </mat-expansion-panel>
        } @empty {
          <mat-card class="empty-card">
            <mat-card-content>
              <p class="empty-msg">No route lists configured.</p>
            </mat-card-content>
          </mat-card>
        }
      </mat-accordion>
    </div>
  `,
  styles: [`
    .rl-page { padding: 24px; }

    .rl-panel {
      margin-bottom: 12px;
    }

    .rl-icon {
      margin-right: 8px;
      color: var(--uswds-primary-light);
    }

    .panel-actions {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }

    .rg-table { width: 100%; }
  `],
})
export class RouteListsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly rgColumns = ['order', 'route_group_id', 'name', 'priority'];

  readonly routeLists = signal<any[]>([]);

  ngOnInit(): void {
    this.loadRouteLists();
  }

  loadRouteLists(): void {
    this.api.getRouteLists().subscribe({
      next: (lists) => this.routeLists.set(lists),
      error: () => {},
    });
  }

  openAddDialog(): void {
    const ref = this.dialog.open(RouteListDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.createRouteList(result).subscribe({
          next: () => this.loadRouteLists(),
          error: () => {},
        });
      }
    });
  }

  openEditDialog(rl: any): void {
    const ref = this.dialog.open(RouteListDialogComponent, { data: rl });
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.updateRouteList(rl.id, result).subscribe({
          next: () => this.loadRouteLists(),
          error: () => {},
        });
      }
    });
  }

  deleteRouteList(id: string): void {
    this.api.deleteRouteList(id).subscribe({
      next: () => this.loadRouteLists(),
      error: () => {},
    });
  }
}
