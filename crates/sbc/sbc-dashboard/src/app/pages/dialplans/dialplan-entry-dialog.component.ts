import { Component, inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-dialplan-entry-dialog',
  standalone: true,
  imports: [
    MatDialogModule, MatFormFieldModule, MatInputModule,
    MatSelectModule, MatButtonModule, FormsModule,
  ],
  template: `
    <h2 mat-dialog-title>Add Dial Plan Entry</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Direction</mat-label>
        <mat-select [(ngModel)]="form.direction">
          <mat-option value="inbound">Inbound</mat-option>
          <mat-option value="outbound">Outbound</mat-option>
          <mat-option value="both">Both</mat-option>
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Pattern Type</mat-label>
        <mat-select [(ngModel)]="form.pattern_type">
          <mat-option value="exact">Exact</mat-option>
          <mat-option value="prefix">Prefix</mat-option>
          <mat-option value="wildcard">Wildcard</mat-option>
          <mat-option value="any">Any</mat-option>
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Pattern Value</mat-label>
        <input matInput [(ngModel)]="form.pattern_value">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Domain Pattern</mat-label>
        <input matInput [(ngModel)]="form.domain_pattern">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Source Trunk</mat-label>
        <input matInput [(ngModel)]="form.source_trunk">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Trunk Group</mat-label>
        <input matInput [(ngModel)]="form.trunk_group">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Destination Type</mat-label>
        <mat-select [(ngModel)]="form.destination_type">
          <mat-option value="trunk_group">Trunk Group</mat-option>
          <mat-option value="registered_user">Registered User</mat-option>
          <mat-option value="static_uri">Static URI</mat-option>
        </mat-select>
      </mat-form-field>

      @if (form.destination_type === 'static_uri') {
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Static Destination</mat-label>
          <input matInput [(ngModel)]="form.static_destination">
        </mat-form-field>
      }

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Transform Type</mat-label>
        <mat-select [(ngModel)]="form.transform_type">
          <mat-option value="none">None</mat-option>
          <mat-option value="strip_prefix">Strip Prefix</mat-option>
          <mat-option value="add_prefix">Add Prefix</mat-option>
          <mat-option value="replace_prefix">Replace Prefix</mat-option>
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Transform Value</mat-label>
        <input matInput [(ngModel)]="form.transform_value">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Priority</mat-label>
        <input matInput type="number" [(ngModel)]="form.priority">
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
export class DialplanEntryDialogComponent {
  readonly data = inject(MAT_DIALOG_DATA);
  private readonly dialogRef = inject(MatDialogRef<DialplanEntryDialogComponent>);

  form: any = {
    direction: 'inbound',
    pattern_type: 'exact',
    pattern_value: '',
    domain_pattern: '',
    source_trunk: '',
    trunk_group: '',
    destination_type: 'trunk_group',
    static_destination: '',
    transform_type: 'none',
    transform_value: '',
    priority: 100,
  };

  save(): void {
    this.dialogRef.close(this.form);
  }
}
