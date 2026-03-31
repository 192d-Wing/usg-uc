import { Component, inject, OnInit, OnDestroy, signal } from '@angular/core';
import { TitleCasePipe } from '@angular/common';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatIconModule } from '@angular/material/icon';
import { MatBadgeModule } from '@angular/material/badge';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService } from '../../services/api.service';
import { WebSocketService } from '../../services/websocket.service';
import { Subscription, interval } from 'rxjs';
import { SystemStats } from '../../models/sbc.models';

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [
    TitleCasePipe,
    MatToolbarModule,
    MatIconModule,
    MatBadgeModule,
    MatButtonModule,
    MatTooltipModule,
  ],
  template: `
    <mat-toolbar class="header-toolbar">
      <span class="instance-name">SBC Instance</span>
      <span class="spacer"></span>

      <div class="health-indicator" [matTooltip]="'Status: ' + healthStatus()">
        <span class="health-dot" [class]="'health-' + healthStatus()"></span>
        <span class="health-label">{{ healthStatus() | titlecase }}</span>
      </div>

      <button mat-icon-button [matBadge]="activeCalls().toString()" matBadgeColor="accent"
              matBadgeSize="small" [matBadgeHidden]="activeCalls() === 0"
              matTooltip="Active Calls">
        <mat-icon>phone_in_talk</mat-icon>
      </button>

      <button mat-icon-button matTooltip="Settings">
        <mat-icon>settings</mat-icon>
      </button>
    </mat-toolbar>
  `,
  styles: [`
    .header-toolbar {
      background: rgba(255, 255, 255, 0.03);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      color: var(--text-primary);
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
      padding: 0 24px;
      height: 56px;
    }

    .instance-name {
      font-size: 16px;
      font-weight: 600;
      color: var(--text-secondary);
      letter-spacing: 0.02em;
    }

    .spacer {
      flex: 1;
    }

    .health-indicator {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-right: 16px;
      padding: 6px 14px;
      border-radius: 20px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.06);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      transition: background 200ms ease;
    }

    .health-indicator:hover {
      background: rgba(255, 255, 255, 0.06);
    }

    .health-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }

    .health-healthy {
      background-color: #4ade80;
      box-shadow: 0 0 6px #4ade80;
      animation: pulse-glow 2s ease-in-out infinite;
      color: #4ade80;
    }

    .health-degraded {
      background-color: #fbbf24;
      box-shadow: 0 0 6px #fbbf24;
      color: #fbbf24;
    }

    .health-unhealthy {
      background-color: #f87171;
      box-shadow: 0 0 6px #f87171;
      color: #f87171;
    }

    @keyframes pulse-glow {
      0%, 100% { box-shadow: 0 0 4px currentColor; }
      50% { box-shadow: 0 0 12px currentColor, 0 0 20px currentColor; }
    }

    .health-label {
      font-size: 13px;
      color: rgba(255, 255, 255, 0.7);
    }
  `],
})
export class HeaderComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  private readonly ws = inject(WebSocketService);
  private subscriptions: Subscription[] = [];

  readonly healthStatus = signal<'healthy' | 'degraded' | 'unhealthy'>('healthy');
  readonly activeCalls = signal(0);

  ngOnInit(): void {
    this.loadHealth();
    this.loadStats();

    this.subscriptions.push(
      interval(15000).subscribe(() => this.loadHealth()),
      this.ws.on('stats_update').subscribe((event) => {
        const stats = event.data as SystemStats;
        this.activeCalls.set(stats.calls_active);
      }),
    );
  }

  ngOnDestroy(): void {
    this.subscriptions.forEach((s) => s.unsubscribe());
  }

  private loadHealth(): void {
    this.api.getHealth().subscribe({
      next: (h) => this.healthStatus.set(h.status),
      error: () => this.healthStatus.set('unhealthy'),
    });
  }

  private loadStats(): void {
    this.api.getStats().subscribe({
      next: (s) => this.activeCalls.set(s.calls_active),
      error: () => {},
    });
  }
}
