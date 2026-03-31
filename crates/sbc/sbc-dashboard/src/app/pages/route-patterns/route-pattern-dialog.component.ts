import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
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
    <h2 mat-dialog-title>Add Route Pattern</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Pattern</mat-label>
        <input matInput [(ngModel)]="rp.pattern" required placeholder="e.g. 9.!" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Partition</mat-label>
        <mat-select [(ngModel)]="rp.partition">
          @for (p of availablePartitions(); track p.id) {
            <mat-option [value]="p.name">{{ p.name }}</mat-option>
          }
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Route List ID</mat-label>
        <input matInput [(ngModel)]="rp.route_list_id" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Called Party Transform</mat-label>
        <input matInput [(ngModel)]="rp.called_party_transform" />
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
        Add
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; }
    mat-checkbox { margin-bottom: 8px; }
  `],
})
export class RoutePatternDialogComponent implements OnInit {
  private readonly api = inject(ApiService);

  rp: any = {
    pattern: '',
    partition: '',
    route_list_id: '',
    called_party_transform: '',
    priority: 0,
    blocked: false,
  };

  readonly availablePartitions = signal<any[]>([]);

  constructor(public dialogRef: MatDialogRef<RoutePatternDialogComponent>) {}

  ngOnInit(): void {
    this.api.getPartitions().subscribe({
      next: (partitions) => this.availablePartitions.set(partitions),
      error: () => {},
    });
  }
}
