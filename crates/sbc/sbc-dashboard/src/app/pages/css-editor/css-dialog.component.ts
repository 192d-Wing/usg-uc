import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-css-dialog',
  standalone: true,
  imports: [
    FormsModule, MatDialogModule, MatFormFieldModule,
    MatInputModule, MatSelectModule, MatButtonModule,
    MatIconModule, MatTooltipModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ isEdit ? 'Edit' : 'Add' }} Calling Search Space</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Name</mat-label>
        <input matInput [(ngModel)]="css.name" required [readonly]="isEdit" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Partitions</mat-label>
        <mat-select [(ngModel)]="css.partitions" multiple>
          @for (p of availablePartitions(); track p.id) {
            <mat-option [value]="p.id">{{ p.name || p.id }}</mat-option>
          }
        </mat-select>
      </mat-form-field>

      @if (css.partitions.length) {
        <div class="partition-order">
          <p class="order-label">Evaluation Order:</p>
          @for (p of css.partitions; track p; let i = $index) {
            <div class="partition-row">
              <span class="order-num">{{ i + 1 }}</span>
              <span class="partition-name">{{ p }}</span>
              <button mat-icon-button (click)="moveUp(i)" [disabled]="i === 0" matTooltip="Move up">
                <mat-icon>arrow_upward</mat-icon>
              </button>
              <button mat-icon-button (click)="moveDown(i)" [disabled]="i === css.partitions.length - 1" matTooltip="Move down">
                <mat-icon>arrow_downward</mat-icon>
              </button>
            </div>
          }
        </div>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" [disabled]="!css.name"
              (click)="dialogRef.close(css)">
        {{ isEdit ? 'Save' : 'Add' }}
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; padding-top: 8px !important; }
    .partition-order { margin-top: 8px; }
    .order-label { font-weight: 500; margin: 0 0 8px; font-size: 14px; color: rgba(255,255,255,0.7); }
    .partition-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; }
    .order-num { min-width: 24px; text-align: center; font-weight: 600; color: var(--uswds-primary-light); }
    .partition-name { flex: 1; }
  `],
})
export class CssDialogComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly data: any = inject(MAT_DIALOG_DATA, { optional: true });

  isEdit = false;
  css: any = { name: '', partitions: [] };
  readonly availablePartitions = signal<any[]>([]);

  constructor(public dialogRef: MatDialogRef<CssDialogComponent>) {}

  ngOnInit(): void {
    this.api.getPartitions().subscribe({
      next: (partitions) => this.availablePartitions.set(partitions),
    });

    if (this.data) {
      this.isEdit = true;
      this.css = {
        name: this.data.name || this.data.id,
        partitions: [...(this.data.partitions || [])],
      };
    }
  }

  moveUp(index: number): void {
    const arr = [...this.css.partitions];
    [arr[index - 1], arr[index]] = [arr[index], arr[index - 1]];
    this.css.partitions = arr;
  }

  moveDown(index: number): void {
    const arr = [...this.css.partitions];
    [arr[index], arr[index + 1]] = [arr[index + 1], arr[index]];
    this.css.partitions = arr;
  }
}
