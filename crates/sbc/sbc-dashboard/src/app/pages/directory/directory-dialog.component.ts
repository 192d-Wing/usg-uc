import { Component, inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { FormsModule } from '@angular/forms';
import { DirectoryNumber } from '../../models/sbc.models';

export interface DirectoryDialogData {
  mode: 'add' | 'edit';
  number?: DirectoryNumber;
}

@Component({
  selector: 'app-directory-dialog',
  standalone: true,
  imports: [
    MatDialogModule, MatFormFieldModule, MatInputModule,
    MatSelectModule, MatButtonModule, MatSlideToggleModule, FormsModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ data.mode === 'add' ? 'Add Directory Number' : 'Edit Directory Number' }}</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>DID</mat-label>
        <input matInput [(ngModel)]="form.did" [disabled]="data.mode === 'edit'">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Description</mat-label>
        <input matInput [(ngModel)]="form.description">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Destination Type</mat-label>
        <mat-select [(ngModel)]="form.destination_type">
          <mat-option value="trunk_group">Trunk Group</mat-option>
          <mat-option value="registered_user">Registered User</mat-option>
          <mat-option value="static_uri">Static URI</mat-option>
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Destination</mat-label>
        <input matInput [(ngModel)]="form.destination">
      </mat-form-field>

      @if (form.destination_type === 'trunk_group') {
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Trunk Group</mat-label>
          <input matInput [(ngModel)]="form.trunk_group">
        </mat-form-field>
      }

      <mat-slide-toggle [(ngModel)]="form.enabled">Enabled</mat-slide-toggle>
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
export class DirectoryDialogComponent {
  readonly data = inject<DirectoryDialogData>(MAT_DIALOG_DATA);
  private readonly dialogRef = inject(MatDialogRef<DirectoryDialogComponent>);

  form: DirectoryNumber = this.data.number
    ? { ...this.data.number }
    : {
        did: '',
        description: '',
        destination_type: 'trunk_group',
        destination: '',
        trunk_group: '',
        enabled: true,
      };

  save(): void {
    this.dialogRef.close(this.form);
  }
}
