import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-route-pattern-dialog',
  standalone: true,
  imports: [
    FormsModule, MatDialogModule, MatFormFieldModule,
    MatInputModule, MatSelectModule, MatButtonModule, MatCheckboxModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ isEdit ? 'Edit' : 'Add' }} Route Pattern</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Pattern</mat-label>
        <input matInput [(ngModel)]="rp.pattern" required placeholder="e.g. +1XXXXXXXXXX" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Partition</mat-label>
        <mat-select [(ngModel)]="rp.partition_id">
          @for (p of availablePartitions(); track p.id) {
            <mat-option [value]="p.id">{{ p.name || p.id }}</mat-option>
          }
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Route List</mat-label>
        <mat-select [(ngModel)]="rp.route_list_id">
          <mat-option value="">-- None --</mat-option>
          @for (rl of availableRouteLists(); track rl.id) {
            <mat-option [value]="rl.id">{{ rl.name || rl.id }}</mat-option>
          }
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Route Group (if no Route List)</mat-label>
        <mat-select [(ngModel)]="rp.route_group_id">
          <mat-option value="">-- None --</mat-option>
          @for (rg of availableRouteGroups(); track rg.id) {
            <mat-option [value]="rg.id">{{ rg.name || rg.id }}</mat-option>
          }
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Priority</mat-label>
        <input matInput [(ngModel)]="rp.priority" type="number" />
      </mat-form-field>

      <mat-checkbox [(ngModel)]="rp.blocked">Blocked</mat-checkbox>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" [disabled]="!rp.pattern"
              (click)="dialogRef.close(rp)">
        {{ isEdit ? 'Save' : 'Add' }}
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 450px; }
    mat-checkbox { margin-bottom: 8px; }
  `],
})
export class RoutePatternDialogComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly data: any = inject(MAT_DIALOG_DATA, { optional: true });

  isEdit = false;

  rp: any = {
    pattern: '',
    partition_id: '',
    route_list_id: '',
    route_group_id: '',
    priority: 0,
    blocked: false,
  };

  readonly availablePartitions = signal<any[]>([]);
  readonly availableRouteLists = signal<any[]>([]);
  readonly availableRouteGroups = signal<any[]>([]);

  constructor(public dialogRef: MatDialogRef<RoutePatternDialogComponent>) {}

  ngOnInit(): void {
    // Load dropdowns
    this.api.getPartitions().subscribe({
      next: (partitions) => this.availablePartitions.set(partitions),
    });
    this.api.getRouteLists().subscribe({
      next: (lists) => this.availableRouteLists.set(lists),
    });
    this.api.getTrunkGroups().subscribe({
      next: (groups) => this.availableRouteGroups.set(groups),
    });

    // Populate form if editing
    if (this.data) {
      this.isEdit = true;
      this.rp = { ...this.data };
    }
  }
}
