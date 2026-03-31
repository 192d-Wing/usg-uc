import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-css-dialog',
  standalone: true,
  imports: [
    FormsModule, MatDialogModule, MatFormFieldModule,
    MatInputModule, MatSelectModule, MatButtonModule,
  ],
  template: `
    <h2 mat-dialog-title>Add Calling Search Space</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Name</mat-label>
        <input matInput [(ngModel)]="css.name" required />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Partitions</mat-label>
        <mat-select [(ngModel)]="css.partitions" multiple>
          @for (p of availablePartitions(); track p.id) {
            <mat-option [value]="p.name">{{ p.name }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" [disabled]="!css.name"
              (click)="dialogRef.close(css)">
        Add
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; padding-top: 8px !important; }
  `],
})
export class CssDialogComponent implements OnInit {
  private readonly api = inject(ApiService);

  css: any = { name: '', partitions: [] };
  readonly availablePartitions = signal<any[]>([]);

  constructor(public dialogRef: MatDialogRef<CssDialogComponent>) {}

  ngOnInit(): void {
    this.api.getPartitions().subscribe({
      next: (partitions) => this.availablePartitions.set(partitions),
      error: () => {},
    });
  }
}
