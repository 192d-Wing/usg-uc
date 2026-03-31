import { Component, inject, OnInit, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatTableModule } from '@angular/material/table';
import { ApiService } from '../../services/api.service';
import { TrunkgroupDialogComponent } from './trunkgroup-dialog.component';
import { TrunkDialogComponent } from './trunk-dialog.component';

@Component({
  selector: 'app-trunkgroups',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatExpansionModule, MatTableModule,
  ],
  template: `
    <div class="trunkgroups-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Trunk Groups</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddGroupDialog()">
          <mat-icon>add</mat-icon> Add Trunk Group
        </button>
        <button mat-icon-button (click)="loadGroups()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      <mat-accordion>
        @for (group of groups(); track group.id) {
          <mat-expansion-panel class="group-panel">
            <mat-expansion-panel-header>
              <mat-panel-title>
                <mat-icon class="group-icon">dns</mat-icon>
                {{ group.name || group.id }}
              </mat-panel-title>
              <mat-panel-description>
                Strategy: {{ formatType(group.strategy || 'priority') }}
                &bull; Trunks: {{ group.trunks?.length || 0 }}
              </mat-panel-description>
            </mat-expansion-panel-header>

            <div class="panel-actions">
              <button mat-raised-button color="primary" (click)="openAddTrunkDialog(group.id)">
                <mat-icon>add</mat-icon> Add Trunk
              </button>
              <button mat-raised-button color="warn" (click)="deleteGroup(group.id)">
                <mat-icon>delete</mat-icon> Delete Group
              </button>
            </div>

            @if (group.trunks?.length) {
              <table mat-table [dataSource]="group.trunks" class="trunks-table">
                <ng-container matColumnDef="id">
                  <th mat-header-cell *matHeaderCellDef>ID</th>
                  <td mat-cell *matCellDef="let row">{{ row.id }}</td>
                </ng-container>
                <ng-container matColumnDef="host">
                  <th mat-header-cell *matHeaderCellDef>Host</th>
                  <td mat-cell *matCellDef="let row">{{ row.host }}</td>
                </ng-container>
                <ng-container matColumnDef="port">
                  <th mat-header-cell *matHeaderCellDef>Port</th>
                  <td mat-cell *matCellDef="let row">{{ row.port }}</td>
                </ng-container>
                <ng-container matColumnDef="protocol">
                  <th mat-header-cell *matHeaderCellDef>Protocol</th>
                  <td mat-cell *matCellDef="let row">
                    <span class="protocol-badge">{{ (row.protocol || 'udp').toUpperCase() }}</span>
                  </td>
                </ng-container>
                <ng-container matColumnDef="priority">
                  <th mat-header-cell *matHeaderCellDef>Priority</th>
                  <td mat-cell *matCellDef="let row">{{ row.priority }}</td>
                </ng-container>
                <ng-container matColumnDef="weight">
                  <th mat-header-cell *matHeaderCellDef>Weight</th>
                  <td mat-cell *matCellDef="let row">{{ row.weight }}</td>
                </ng-container>
                <ng-container matColumnDef="max_calls">
                  <th mat-header-cell *matHeaderCellDef>Max Calls</th>
                  <td mat-cell *matCellDef="let row">{{ row.max_calls }}</td>
                </ng-container>
                <ng-container matColumnDef="state">
                  <th mat-header-cell *matHeaderCellDef>State</th>
                  <td mat-cell *matCellDef="let row">
                    <span class="state-badge" [class]="'state-' + (row.state || 'active')">
                      {{ (row.state || 'active').toUpperCase() }}
                    </span>
                  </td>
                </ng-container>
                <ng-container matColumnDef="actions">
                  <th mat-header-cell *matHeaderCellDef>Actions</th>
                  <td mat-cell *matCellDef="let row">
                    <button mat-icon-button color="warn" (click)="deleteTrunk(group.id, row.id)"
                            matTooltip="Delete Trunk">
                      <mat-icon>delete</mat-icon>
                    </button>
                  </td>
                </ng-container>

                <tr mat-header-row *matHeaderRowDef="trunkColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: trunkColumns;"></tr>
              </table>
            } @else {
              <p class="empty-msg">No trunks in this group.</p>
            }
          </mat-expansion-panel>
        } @empty {
          <mat-card class="empty-card">
            <mat-card-content>
              <p class="empty-msg">No trunk groups configured.</p>
            </mat-card-content>
          </mat-card>
        }
      </mat-accordion>
    </div>
  `,
  styles: [`
    .trunkgroups-page { padding: 24px; }

    .group-panel {
      margin-bottom: 12px;
    }

    .group-icon {
      margin-right: 8px;
      color: var(--uswds-primary-light);
    }

    .panel-actions {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }

    .trunks-table { width: 100%; }

    .protocol-badge {
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      background: rgba(0, 94, 162, 0.15);
      color: var(--uswds-primary-light);
      border: 1px solid rgba(0, 94, 162, 0.3);
    }

    .state-badge {
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .state-active {
      background: rgba(74, 222, 128, 0.12);
      color: var(--color-success);
      border-color: rgba(74, 222, 128, 0.2);
    }

    .state-failed {
      background: rgba(248, 113, 113, 0.12);
      color: var(--color-error);
      border-color: rgba(248, 113, 113, 0.2);
    }

    .state-cooldown {
      background: rgba(251, 191, 36, 0.12);
      color: var(--color-warning);
      border-color: rgba(251, 191, 36, 0.2);
    }
  `],
})
export class TrunkgroupsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly trunkColumns = [
    'id', 'host', 'port', 'protocol', 'priority', 'weight', 'max_calls', 'state', 'actions',
  ];

  readonly groups = signal<any[]>([]);

  ngOnInit(): void {
    this.loadGroups();
  }

  loadGroups(): void {
    this.api.getTrunkGroups().subscribe({
      next: (groups) => {
        // For each group, fetch full details including trunks
        for (const g of groups) {
          this.api.getTrunkGroup(g.id).subscribe({
            next: (full) => {
              this.groups.update(list => {
                const updated = list.filter(x => x.id !== full.id);
                return [...updated, full].sort((a, b) => (a.id > b.id ? 1 : -1));
              });
            },
            error: () => {},
          });
        }
        if (groups.length === 0) {
          this.groups.set([]);
        }
      },
      error: () => {},
    });
  }

  openAddGroupDialog(): void {
    const ref = this.dialog.open(TrunkgroupDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.addTrunkGroup(result).subscribe({
          next: () => this.loadGroups(),
          error: () => {},
        });
      }
    });
  }

  openAddTrunkDialog(groupId: string): void {
    const ref = this.dialog.open(TrunkDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.addTrunk(groupId, result).subscribe({
          next: () => this.loadGroups(),
          error: () => {},
        });
      }
    });
  }

  deleteGroup(groupId: string): void {
    this.api.deleteTrunkGroup(groupId).subscribe({
      next: () => this.loadGroups(),
      error: () => {},
    });
  }

  deleteTrunk(groupId: string, trunkId: string): void {
    this.api.deleteTrunk(groupId, trunkId).subscribe({
      next: () => this.loadGroups(),
      error: () => {},
    });
  }

  formatType(type: string): string {
    return type.replace(/_/g, ' ');
  }
}
