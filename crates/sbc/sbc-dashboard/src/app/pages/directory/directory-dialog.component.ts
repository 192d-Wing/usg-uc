import { Component, inject } from '@angular/core';
import { MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-directory-dialog',
  standalone: true,
  imports: [
    MatDialogModule, MatFormFieldModule, MatInputModule,
    MatButtonModule, FormsModule,
  ],
  template: `
    <h2 mat-dialog-title>Add Directory Number</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>DID</mat-label>
        <input matInput [(ngModel)]="form.did" required>
        <mat-hint>E.164 format (e.g., +12139160002)</mat-hint>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>User</mat-label>
        <input matInput [(ngModel)]="form.user" required>
        <mat-hint>Registered SIP username to route calls to</mat-hint>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Description</mat-label>
        <input matInput [(ngModel)]="form.description">
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" [disabled]="!form.did || !form.user"
              (click)="dialogRef.close(form)">
        Add
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; }
  `],
})
export class DirectoryDialogComponent {
  private readonly ref = inject(MatDialogRef<DirectoryDialogComponent>);

  form = {
    did: '',
    user: '',
    description: '',
  };

  get dialogRef() { return this.ref; }
}
