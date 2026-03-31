import { Component, inject } from '@angular/core';
import { MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-trunkgroup-dialog',
  standalone: true,
  imports: [
    MatDialogModule, MatFormFieldModule, MatInputModule,
    MatSelectModule, MatButtonModule, FormsModule,
  ],
  template: `
    <h2 mat-dialog-title>Add Trunk Group</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Group ID</mat-label>
        <input matInput [(ngModel)]="form.id">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Name</mat-label>
        <input matInput [(ngModel)]="form.name">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Strategy</mat-label>
        <mat-select [(ngModel)]="form.strategy">
          <mat-option value="priority">Priority</mat-option>
          <mat-option value="round_robin">Round Robin</mat-option>
          <mat-option value="weighted_random">Weighted Random</mat-option>
          <mat-option value="least_connections">Least Connections</mat-option>
          <mat-option value="best_success_rate">Best Success Rate</mat-option>
        </mat-select>
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" (click)="save()">Save</button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; }
  `],
})
export class TrunkgroupDialogComponent {
  private readonly dialogRef = inject(MatDialogRef<TrunkgroupDialogComponent>);

  form = {
    id: '',
    name: '',
    strategy: 'priority',
  };

  save(): void {
    this.dialogRef.close(this.form);
  }
}
