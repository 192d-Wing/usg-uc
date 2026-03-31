import { Component, inject, OnInit, OnDestroy, signal } from '@angular/core';
import { TitleCasePipe, SlicePipe } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { StatsCardComponent } from '../../components/stats-card/stats-card.component';
import { ApiService } from '../../services/api.service';
import { WebSocketService } from '../../services/websocket.service';
import { SystemStats, HealthStatus, CdrRecord } from '../../models/sbc.models';
import { Subscription, interval } from 'rxjs';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    TitleCasePipe, SlicePipe,
    MatTableModule, MatCardModule, MatIconModule, MatButtonModule,
    MatChipsModule, StatsCardComponent,
  ],
  template: `
    <div class="dashboard-page">
      <div class="grid-row">
        <div class="grid-col-12">
          <h1 class="usa-heading page-title">Dashboard</h1>
        </div>
      </div>

      <div class="stats-grid">
        <app-stats-card title="Active Calls" [value]="stats().calls_active"
                        icon="phone_in_talk" color="#7c4dff"/>
        <app-stats-card title="Total Calls" [value]="stats().calls_total"
                        icon="phone" color="#00bcd4"/>
        <app-stats-card title="Registrations" [value]="stats().registrations_active"
                        icon="person" color="#4caf50"/>
        <app-stats-card title="Messages/sec" [value]="messagesPerSec()"
                        icon="message" color="#ff9800"/>
      </div>

      <div class="panels-grid">
        <mat-card class="health-panel">
          <mat-card-header>
            <mat-card-title>System Health</mat-card-title>
          </mat-card-header>
          <mat-card-content>
            <div class="health-overview">
              <div class="health-status-row">
                <span class="health-dot" [class]="'dot-' + health().status"></span>
                <span class="health-text">{{ health().status | titlecase }}</span>
              </div>
              <div class="health-meta">
                <span>Version: {{ health().version || 'N/A' }}</span>
                <span>Uptime: {{ formatUptime(health().uptime_secs) }}</span>
              </div>
            </div>
            @for (check of health().checks; track check.name) {
              <div class="health-check-row">
                <mat-icon [class]="check.status === 'ok' ? 'check-ok' : 'check-fail'">
                  {{ check.status === 'ok' ? 'check_circle' : 'error' }}
                </mat-icon>
                <span>{{ check.name }}</span>
                <span class="check-status">{{ check.status }}</span>
              </div>
            }
          </mat-card-content>
        </mat-card>

        <mat-card class="calls-panel">
          <mat-card-header>
            <mat-card-title>Active Calls</mat-card-title>
            <button mat-icon-button (click)="loadActiveCalls()">
              <mat-icon>refresh</mat-icon>
            </button>
          </mat-card-header>
          <mat-card-content>
            @if (activeCalls().length === 0) {
              <div class="no-calls">No active calls</div>
            } @else {
              <table mat-table [dataSource]="activeCalls()" class="calls-table">
                <ng-container matColumnDef="call_id">
                  <th mat-header-cell *matHeaderCellDef>Call ID</th>
                  <td mat-cell *matCellDef="let row">{{ row.call_id | slice:0:12 }}...</td>
                </ng-container>
                <ng-container matColumnDef="caller">
                  <th mat-header-cell *matHeaderCellDef>Caller</th>
                  <td mat-cell *matCellDef="let row">{{ row.caller }}</td>
                </ng-container>
                <ng-container matColumnDef="callee">
                  <th mat-header-cell *matHeaderCellDef>Callee</th>
                  <td mat-cell *matCellDef="let row">{{ row.callee }}</td>
                </ng-container>
                <ng-container matColumnDef="duration">
                  <th mat-header-cell *matHeaderCellDef>Duration</th>
                  <td mat-cell *matCellDef="let row">{{ formatDuration(row.duration_secs) }}</td>
                </ng-container>
                <ng-container matColumnDef="status">
                  <th mat-header-cell *matHeaderCellDef>Status</th>
                  <td mat-cell *matCellDef="let row">
                    <mat-chip [class]="'status-' + row.status">{{ row.status }}</mat-chip>
                  </td>
                </ng-container>
                <tr mat-header-row *matHeaderRowDef="callColumns"></tr>
                <tr mat-row *matRowDef="let row; columns: callColumns;"></tr>
              </table>
            }
          </mat-card-content>
        </mat-card>
      </div>
    </div>
  `,
  styles: [`
    .dashboard-page { padding: 24px; }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 16px;
    }

    .panels-grid {
      display: grid;
      grid-template-columns: 1fr 2fr;
      gap: 16px;
    }

    mat-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .health-overview { margin-bottom: 16px; }

    .health-status-row {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
    }

    .health-dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }

    .dot-healthy {
      background: var(--color-success);
      box-shadow: 0 0 8px var(--color-success);
    }

    .dot-degraded {
      background: var(--color-warning);
      box-shadow: 0 0 8px var(--color-warning);
    }

    .dot-unhealthy {
      background: var(--color-error);
      box-shadow: 0 0 8px var(--color-error);
    }

    .health-text { font-size: 18px; font-weight: 700; }

    .health-meta {
      display: flex;
      gap: 24px;
      color: var(--uswds-text-secondary);
      font-size: 13px;
    }

    .health-check-row {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 0;
      border-top: 1px solid var(--uswds-border);
      font-size: 14px;
      transition: background 200ms ease;
    }

    .health-check-row:hover {
      background: var(--uswds-hover);
    }

    .check-ok { color: var(--color-success); }
    .check-fail { color: var(--color-error); }
    .check-status { margin-left: auto; color: var(--uswds-text-secondary); font-size: 12px; }

    .calls-table { width: 100%; }

    .no-calls {
      text-align: center;
      padding: 32px;
      color: var(--uswds-text-secondary);
    }

    @media (max-width: 1100px) {
      .stats-grid { grid-template-columns: repeat(2, 1fr); }
    }

    @media (max-width: 900px) {
      .panels-grid { grid-template-columns: 1fr; }
    }

    @media (max-width: 600px) {
      .stats-grid { grid-template-columns: 1fr; }
    }
  `],
})
export class DashboardComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  private readonly ws = inject(WebSocketService);
  private subs: Subscription[] = [];

  readonly stats = signal<SystemStats>({
    calls_total: 0, calls_active: 0,
    registrations_total: 0, registrations_active: 0,
    messages_received: 0, messages_sent: 0, rate_limited: 0,
  });

  readonly health = signal<HealthStatus>({
    status: 'healthy', uptime_secs: 0, version: '', checks: [],
  });

  readonly activeCalls = signal<CdrRecord[]>([]);
  readonly messagesPerSec = signal(0);
  readonly callColumns = ['call_id', 'caller', 'callee', 'duration', 'status'];

  private lastMsgCount = 0;

  ngOnInit(): void {
    this.loadStats();
    this.loadHealth();
    this.loadActiveCalls();

    this.subs.push(
      interval(5000).subscribe(() => {
        this.loadStats();
        this.loadActiveCalls();
      }),
      interval(15000).subscribe(() => this.loadHealth()),
      this.ws.on('stats_update').subscribe((e) => {
        const s = e.data as SystemStats;
        const totalMsgs = s.messages_received + s.messages_sent;
        if (this.lastMsgCount > 0) {
          this.messagesPerSec.set(Math.round((totalMsgs - this.lastMsgCount) / 5));
        }
        this.lastMsgCount = totalMsgs;
        this.stats.set(s);
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.forEach((s) => s.unsubscribe());
  }

  loadStats(): void {
    this.api.getStats().subscribe({
      next: (s) => {
        const totalMsgs = s.messages_received + s.messages_sent;
        if (this.lastMsgCount > 0) {
          this.messagesPerSec.set(Math.round((totalMsgs - this.lastMsgCount) / 5));
        }
        this.lastMsgCount = totalMsgs;
        this.stats.set(s);
      },
      error: () => {},
    });
  }

  loadHealth(): void {
    this.api.getHealth().subscribe({
      next: (h) => this.health.set(h),
      error: () => {},
    });
  }

  loadActiveCalls(): void {
    this.api.getActiveCalls().subscribe({
      next: (c) => this.activeCalls.set(c),
      error: () => {},
    });
  }

  formatUptime(secs: number): string {
    if (!secs) return 'N/A';
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  formatDuration(secs?: number): string {
    if (secs == null) return '--';
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  }
}
