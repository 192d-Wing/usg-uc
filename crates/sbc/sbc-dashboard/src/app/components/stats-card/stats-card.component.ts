import { Component, input } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-stats-card',
  standalone: true,
  imports: [MatCardModule, MatIconModule],
  template: `
    <div class="stats-card glass-card">
      <div class="card-content">
        <div class="card-icon-wrap">
          <mat-icon>{{ icon() }}</mat-icon>
        </div>
        <div class="card-info">
          <span class="card-label">{{ title() }}</span>
          <span class="card-value">{{ value() }}</span>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .stats-card {
      padding: 20px;
      cursor: default;
    }

    .stats-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
    }

    .card-content {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .card-icon-wrap {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 48px;
      height: 48px;
      border-radius: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
      flex-shrink: 0;
    }

    .card-icon-wrap mat-icon {
      color: #fff;
      font-size: 24px;
    }

    .card-info {
      display: flex;
      flex-direction: column;
    }

    .card-label {
      font-size: 13px;
      color: rgba(255, 255, 255, 0.5);
      margin-bottom: 4px;
      letter-spacing: 0.02em;
    }

    .card-value {
      font-size: 28px;
      font-weight: 700;
      color: rgba(255, 255, 255, 0.95);
      line-height: 1;
      transition: text-shadow 250ms ease;
    }

    .stats-card:hover .card-value {
      text-shadow: 0 0 20px rgba(102, 126, 234, 0.3);
    }
  `],
})
export class StatsCardComponent {
  readonly title = input.required<string>();
  readonly value = input.required<string | number>();
  readonly icon = input.required<string>();
  readonly color = input<string>('#7c4dff');
}
