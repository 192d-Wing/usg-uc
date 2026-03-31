import { Component, input } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-stats-card',
  standalone: true,
  imports: [MatCardModule, MatIconModule],
  template: `
    <mat-card class="stats-card" [style.border-left-color]="color()">
      <mat-card-content class="card-content">
        <div class="card-icon" [style.background]="color() + '20'" [style.color]="color()">
          <mat-icon>{{ icon() }}</mat-icon>
        </div>
        <div class="card-info">
          <span class="card-label">{{ title() }}</span>
          <span class="card-value">{{ value() }}</span>
        </div>
      </mat-card-content>
    </mat-card>
  `,
  styles: [`
    .stats-card {
      background: #16213e;
      border-left: 4px solid;
      border-radius: 12px;
    }

    .card-content {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 8px 0;
    }

    .card-icon {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 48px;
      height: 48px;
      border-radius: 12px;
    }

    .card-info {
      display: flex;
      flex-direction: column;
    }

    .card-label {
      font-size: 13px;
      color: rgba(255, 255, 255, 0.6);
      margin-bottom: 4px;
    }

    .card-value {
      font-size: 28px;
      font-weight: 600;
      color: #fff;
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
