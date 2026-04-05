import { Component, inject, OnInit, OnDestroy, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatTableModule } from '@angular/material/table';
import { MatChipsModule } from '@angular/material/chips';
import { ApiService } from '../../services/api.service';
import { TrunkgroupDialogComponent } from './trunkgroup-dialog.component';
import { TrunkDialogComponent } from './trunk-dialog.component';

@Component({
  selector: 'app-trunkgroups',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatExpansionModule, MatTableModule, MatChipsModule,
  ],
  template: `
    <div class="trunkgroups-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Trunk Groups</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddGroupDialog()">
          <mat-icon>add</mat-icon> Add Trunk Group
        </button>
        <button mat-icon-button (click)="loadAll()" matTooltip="Refresh">
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
              <button mat-raised-button color="primary" (click)="openEditGroupDialog(group)">
                <mat-icon>edit</mat-icon> Edit Group
              </button>
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
                <ng-container matColumnDef="registration">
                  <th mat-header-cell *matHeaderCellDef>Registration</th>
                  <td mat-cell *matCellDef="let row">
                    @if (getRegStatus(row.id); as reg) {
                      <span class="reg-badge" [class]="'reg-' + reg.state.toLowerCase()">
                        <mat-icon class="reg-icon">{{ getRegIcon(reg.state) }}</mat-icon>
                        {{ reg.state }}
                      </span>
                      @if (reg.last_error) {
                        <span class="reg-error" [matTooltip]="reg.last_error">
                          <mat-icon class="error-icon">warning</mat-icon>
                        </span>
                      }
                    } @else if (row.sip_username) {
                      <button mat-stroked-button class="register-btn" (click)="registerTrunk(row.id)">
                        <mat-icon>app_registration</mat-icon> Register
                      </button>
                    } @else {
                      <span class="reg-na">N/A</span>
                    }
                  </td>
                </ng-container>
                <ng-container matColumnDef="health">
                  <th mat-header-cell *matHeaderCellDef>Service Status</th>
                  <td mat-cell *matCellDef="let row">
                    @if (getHealthStatus(row.id); as h) {
                      @if (h.reachable) {
                        <span class="health-badge health-up">
                          <mat-icon class="health-icon">check_circle</mat-icon>
                          In Service: {{ getServiceDuration(h) }}
                        </span>
                        <span class="latency">{{ h.last_response_ms }}ms</span>
                        <span class="uptime">{{ h.uptime_pct.toFixed(1) }}%</span>
                      } @else {
                        <span class="health-badge health-down">
                          <mat-icon class="health-icon">cancel</mat-icon>
                          Not In Service
                        </span>
                        @if (h.last_success) {
                          <span class="last-seen">Last up: {{ getTimeAgo(h.last_success) }}</span>
                        }
                      }
                    } @else if (row.options_ping_enabled) {
                      <span class="health-pending">Pending</span>
                    } @else {
                      <span class="reg-na">N/A</span>
                    }
                  </td>
                </ng-container>
                <ng-container matColumnDef="actions">
                  <th mat-header-cell *matHeaderCellDef>Actions</th>
                  <td mat-cell *matCellDef="let row">
                    <button mat-icon-button (click)="openEditTrunkDialog(group.id, row)"
                            matTooltip="Edit Trunk" color="primary">
                      <mat-icon>edit</mat-icon>
                    </button>
                    @if (getRegStatus(row.id); as reg) {
                      <button mat-icon-button (click)="registerTrunk(row.id)"
                              matTooltip="Re-Register" color="primary">
                        <mat-icon>refresh</mat-icon>
                      </button>
                    }
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

    .reg-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .reg-icon, .health-icon, .error-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
    }

    .reg-registered {
      background: rgba(74, 222, 128, 0.12);
      color: var(--color-success, #4ade80);
      border-color: rgba(74, 222, 128, 0.2);
    }

    .reg-failed {
      background: rgba(248, 113, 113, 0.12);
      color: var(--color-error, #f87171);
      border-color: rgba(248, 113, 113, 0.2);
    }

    .reg-initializing {
      background: rgba(251, 191, 36, 0.12);
      color: var(--color-warning, #fbbf24);
      border-color: rgba(251, 191, 36, 0.2);
    }

    .reg-error {
      margin-left: 4px;
      cursor: help;
    }

    .error-icon {
      color: var(--color-warning, #fbbf24);
    }

    .reg-na {
      font-size: 12px;
      color: rgba(255, 255, 255, 0.3);
    }

    .register-btn {
      font-size: 12px;
    }

    .health-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .health-up {
      background: rgba(74, 222, 128, 0.12);
      color: var(--color-success, #4ade80);
      border-color: rgba(74, 222, 128, 0.2);
    }

    .health-down {
      background: rgba(248, 113, 113, 0.12);
      color: var(--color-error, #f87171);
      border-color: rgba(248, 113, 113, 0.2);
    }

    .health-pending {
      font-size: 12px;
      color: rgba(255, 255, 255, 0.4);
    }

    .latency {
      margin-left: 6px;
      font-size: 11px;
      color: rgba(255, 255, 255, 0.5);
    }

    .uptime {
      margin-left: 4px;
      font-size: 11px;
      color: rgba(255, 255, 255, 0.4);
    }

    .last-seen {
      margin-left: 6px;
      font-size: 11px;
      color: rgba(255, 255, 255, 0.4);
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
export class TrunkgroupsComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);
  private refreshTimer: ReturnType<typeof setInterval> | null = null;

  readonly trunkColumns = [
    'id', 'host', 'port', 'protocol', 'priority', 'weight', 'max_calls',
    'registration', 'health', 'actions',
  ];

  readonly groups = signal<any[]>([]);
  readonly regStatuses = signal<Map<string, any>>(new Map());
  readonly healthStatuses = signal<Map<string, any>>(new Map());
  readonly now = signal<number>(Math.floor(Date.now() / 1000));
  private tickTimer: ReturnType<typeof setInterval> | null = null;

  ngOnInit(): void {
    this.loadAll();
    // Auto-refresh registration & health status every 15s
    this.refreshTimer = setInterval(() => this.loadStatusData(), 15000);
    // Tick every second to update the live service duration timer
    this.tickTimer = setInterval(() => this.now.set(Math.floor(Date.now() / 1000)), 1000);
  }

  ngOnDestroy(): void {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    if (this.tickTimer) clearInterval(this.tickTimer);
  }

  loadAll(): void {
    this.loadGroups();
    this.loadStatusData();
  }

  loadGroups(): void {
    this.api.getTrunkGroups().subscribe({
      next: (groups) => {
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

  loadStatusData(): void {
    this.api.getTrunkRegistrationStatus().subscribe({
      next: (regs) => {
        const map = new Map<string, any>();
        for (const r of regs) {
          map.set(r.trunk_id, r);
        }
        this.regStatuses.set(map);
      },
      error: () => {},
    });

    this.api.getTrunkHealth().subscribe({
      next: (trunks) => {
        const map = new Map<string, any>();
        for (const t of trunks) {
          map.set(t.trunk_id, t);
        }
        this.healthStatuses.set(map);
      },
      error: () => {},
    });
  }

  getRegStatus(trunkId: string): any | null {
    return this.regStatuses().get(trunkId) ?? null;
  }

  getHealthStatus(trunkId: string): any | null {
    return this.healthStatuses().get(trunkId) ?? null;
  }

  getRegIcon(state: string): string {
    switch (state.toLowerCase()) {
      case 'registered': return 'check_circle';
      case 'failed': return 'error';
      case 'initializing': return 'hourglass_empty';
      default: return 'help_outline';
    }
  }

  registerTrunk(trunkId: string): void {
    this.api.triggerTrunkRegister(trunkId).subscribe({
      next: () => {
        // Refresh status after a short delay to allow registration to complete
        setTimeout(() => this.loadStatusData(), 2000);
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

  openEditGroupDialog(group: any): void {
    const ref = this.dialog.open(TrunkgroupDialogComponent, { data: group });
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.updateTrunkGroup(group.id, result).subscribe({
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

  openEditTrunkDialog(groupId: string, trunk: any): void {
    const ref = this.dialog.open(TrunkDialogComponent, { data: trunk });
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.updateTrunk(groupId, trunk.id, result).subscribe({
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

  /** Computes service uptime duration as HH:MM:SS from the last failure timestamp. */
  getServiceDuration(health: any): string {
    // Use last_failure to determine when the trunk came back up.
    // If no failure recorded, use the first success or fall back to consecutive_success * interval.
    const now = this.now();
    let upSince: number;

    if (health.last_failure && health.last_success && health.last_success > health.last_failure) {
      // Came back up after a failure — uptime starts at last_failure + ping interval
      upSince = health.last_failure;
    } else if (health.last_success) {
      // Never failed — estimate from consecutive successes * ~30s intervals
      const estimatedStart = health.last_success - (health.consecutive_success * 30);
      upSince = estimatedStart;
    } else {
      return '0:00';
    }

    const secs = Math.max(0, now - upSince);
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) {
      return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    }
    return `${m}:${s.toString().padStart(2, '0')}`;
  }

  /** Formats a unix timestamp as "X min ago" or "X hr ago". */
  getTimeAgo(timestamp: number): string {
    const secs = Math.max(0, this.now() - timestamp);
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m ago`;
  }

  formatType(type: string): string {
    return type.replace(/_/g, ' ');
  }
}
