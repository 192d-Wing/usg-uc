import { Component, inject, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'app-route-list-dialog',
  standalone: true,
  imports: [
    FormsModule, MatDialogModule, MatFormFieldModule,
    MatInputModule, MatButtonModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ isEdit ? 'Edit' : 'Add' }} Route List</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Name</mat-label>
        <input matInput [(ngModel)]="routeList.name" required [readonly]="isEdit"
               (input)="autoId()" />
      </mat-form-field>

      @if (!isEdit) {
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>ID</mat-label>
          <input matInput [(ngModel)]="routeList.id" required readonly />
          <mat-hint>Auto-generated from name</mat-hint>
        </mat-form-field>
      }

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Description</mat-label>
        <input matInput [(ngModel)]="routeList.description" />
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" [disabled]="!routeList.name"
              (click)="dialogRef.close(routeList)">
        {{ isEdit ? 'Save' : 'Add' }}
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; }
  `],
})
export class RouteListDialogComponent implements OnInit {
  private readonly data: any = inject(MAT_DIALOG_DATA, { optional: true });

  isEdit = false;
  routeList: any = { id: '', name: '', description: '' };

  constructor(public dialogRef: MatDialogRef<RouteListDialogComponent>) {}

  ngOnInit(): void {
    if (this.data) {
      this.isEdit = true;
      this.routeList = {
        id: this.data.id || '',
        name: this.data.name || this.data.id,
        description: this.data.description || '',
      };
    }
  }

  autoId(): void {
    if (!this.isEdit) {
      this.routeList.id = 'rl-' + this.routeList.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
    }
  }
}
