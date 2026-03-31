import { Component, input } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-stats-card',
  standalone: true,
  imports: [MatCardModule, MatIconModule],
  template: `
    <div class="usa-card usa-card--dark">
      <div class="usa-card__body">
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
    </div>
  `,
  styles: [`
    .usa-card.usa-card--dark {
      background: var(--uswds-card-bg);
      border: 1px solid var(--uswds-card-border);
      border-radius: 8px;
      padding: 0;
      margin: 0;
      cursor: default;
      transition: box-shadow 200ms ease;
    }

    .usa-card.usa-card--dark:hover {
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
    }

    .usa-card__body {
      padding: 20px;
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
      border-radius: 8px;
      background: var(--uswds-primary);
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
      font-size: 12px;
      color: var(--uswds-text-secondary);
      margin-bottom: 4px;
      letter-spacing: 0.03em;
      text-transform: uppercase;
      font-weight: 700;
    }

    .card-value {
      font-size: 28px;
      font-weight: 700;
      color: var(--uswds-text);
      line-height: 1;
    }
  `],
})
export class StatsCardComponent {
  readonly title = input.required<string>();
  readonly value = input.required<string | number>();
  readonly icon = input.required<string>();
  readonly color = input<string>('#7c4dff');
}
