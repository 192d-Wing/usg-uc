import { Component, inject, OnInit, signal } from '@angular/core';
import { Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatChipsModule, MatChipListboxChange } from '@angular/material/chips';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatTooltipModule } from '@angular/material/tooltip';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';
import { CdrRecord, CdrFilter } from '../../models/sbc.models';

@Component({
  selector: 'app-cdrs',
  standalone: true,
  imports: [
    DatePipe, MatTableModule, MatCardModule, MatIconModule, MatButtonModule,
    MatInputModule, MatFormFieldModule, MatPaginatorModule, MatChipsModule,
    MatDatepickerModule, MatTooltipModule, FormsModule,
  ],
  template: `
    <div class="cdrs-page">
      <div class="page-header">
        <h2 class="page-title">CDR Records</h2>
        <button mat-icon-button (click)="loadCdrs()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      <mat-card class="filter-card">
        <mat-card-content class="filter-content">
          <mat-form-field appearance="outline">
            <mat-label>Start Date</mat-label>
            <input matInput [matDatepicker]="startPicker" [(ngModel)]="startDate">
            <mat-datepicker-toggle matIconSuffix [for]="startPicker"></mat-datepicker-toggle>
            <mat-datepicker #startPicker></mat-datepicker>
          </mat-form-field>

          <mat-form-field appearance="outline">
            <mat-label>End Date</mat-label>
            <input matInput [matDatepicker]="endPicker" [(ngModel)]="endDate">
            <mat-datepicker-toggle matIconSuffix [for]="endPicker"></mat-datepicker-toggle>
            <mat-datepicker #endPicker></mat-datepicker>
          </mat-form-field>

          <mat-form-field appearance="outline">
            <mat-label>Search</mat-label>
            <input matInput [(ngModel)]="searchQuery" placeholder="Caller or callee">
            <mat-icon matPrefix>search</mat-icon>
          </mat-form-field>

          <mat-chip-listbox (change)="onStatusFilter($event)" [multiple]="false">
            <mat-chip-option value="">All</mat-chip-option>
            <mat-chip-option value="connected" class="chip-connected">Connected</mat-chip-option>
            <mat-chip-option value="failed" class="chip-failed">Failed</mat-chip-option>
            <mat-chip-option value="cancelled" class="chip-cancelled">Cancelled</mat-chip-option>
          </mat-chip-listbox>

          <button mat-raised-button color="primary" (click)="loadCdrs()">
            <mat-icon>filter_list</mat-icon> Apply
          </button>
        </mat-card-content>
      </mat-card>

      <mat-card class="table-card">
        <mat-card-content>
          <table mat-table [dataSource]="cdrs()" class="cdr-table">
            <ng-container matColumnDef="start_time">
              <th mat-header-cell *matHeaderCellDef>Time</th>
              <td mat-cell *matCellDef="let row">{{ row.start_time | date:'short' }}</td>
            </ng-container>
            <ng-container matColumnDef="duration_secs">
              <th mat-header-cell *matHeaderCellDef>Duration</th>
              <td mat-cell *matCellDef="let row">{{ formatDuration(row.duration_secs) }}</td>
            </ng-container>
            <ng-container matColumnDef="caller">
              <th mat-header-cell *matHeaderCellDef>Caller</th>
              <td mat-cell *matCellDef="let row">{{ row.caller }}</td>
            </ng-container>
            <ng-container matColumnDef="callee">
              <th mat-header-cell *matHeaderCellDef>Callee</th>
              <td mat-cell *matCellDef="let row">{{ row.callee }}</td>
            </ng-container>
            <ng-container matColumnDef="status">
              <th mat-header-cell *matHeaderCellDef>Status</th>
              <td mat-cell *matCellDef="let row">
                <span class="status-badge" [class]="'status-' + row.status">{{ row.status }}</span>
              </td>
            </ng-container>
            <ng-container matColumnDef="a_leg_trunk">
              <th mat-header-cell *matHeaderCellDef>Trunk</th>
              <td mat-cell *matCellDef="let row">{{ row.a_leg_trunk || '--' }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef></th>
              <td mat-cell *matCellDef="let row">
                <button mat-icon-button matTooltip="View Call Ladder"
                        (click)="viewCallLadder(row)">
                  <mat-icon>timeline</mat-icon>
                </button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns;"></tr>
          </table>

          <mat-paginator [length]="totalRecords()"
                         [pageSize]="pageSize"
                         [pageIndex]="pageIndex"
                         [pageSizeOptions]="[10, 25, 50, 100]"
                         (page)="onPage($event)"
                         showFirstLastButtons>
          </mat-paginator>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .cdrs-page { padding: 24px; }

    .page-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 24px;
    }

    .page-title {
      color: #fff;
      margin: 0;
      font-size: 24px;
      font-weight: 500;
    }

    .filter-card {
      background: #16213e;
      color: #fff;
      border-radius: 12px;
      margin-bottom: 16px;
    }

    .filter-content {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .table-card {
      background: #16213e;
      color: #fff;
      border-radius: 12px;
    }

    .cdr-table { width: 100%; }

    .status-badge {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 500;
    }

    .status-connected { background: rgba(76, 175, 80, 0.2); color: #81c784; }
    .status-failed { background: rgba(244, 67, 54, 0.2); color: #ef9a9a; }
    .status-cancelled { background: rgba(255, 152, 0, 0.2); color: #ffcc80; }

    .chip-connected { --mdc-chip-label-text-color: #4caf50; }
    .chip-failed { --mdc-chip-label-text-color: #f44336; }
    .chip-cancelled { --mdc-chip-label-text-color: #ff9800; }
  `],
})
export class CdrsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);

  readonly displayedColumns = ['start_time', 'duration_secs', 'caller', 'callee', 'status', 'a_leg_trunk', 'actions'];
  readonly cdrs = signal<CdrRecord[]>([]);
  readonly totalRecords = signal(0);

  searchQuery = '';
  statusFilter = '';
  startDate: Date | null = null;
  endDate: Date | null = null;
  pageSize = 25;
  pageIndex = 0;

  ngOnInit(): void {
    this.loadCdrs();
  }

  loadCdrs(): void {
    const filter: CdrFilter = {
      page: this.pageIndex + 1,
      page_size: this.pageSize,
    };
    if (this.searchQuery) {
      filter.caller = this.searchQuery;
      filter.callee = this.searchQuery;
    }
    if (this.statusFilter) {
      filter.status = this.statusFilter;
    }
    if (this.startDate) {
      filter.start_date = this.startDate.toISOString();
    }
    if (this.endDate) {
      filter.end_date = this.endDate.toISOString();
    }

    this.api.getCdrs(filter).subscribe({
      next: (res) => {
        this.cdrs.set(res.items);
        this.totalRecords.set(res.total);
      },
      error: () => {},
    });
  }

  onPage(event: PageEvent): void {
    this.pageSize = event.pageSize;
    this.pageIndex = event.pageIndex;
    this.loadCdrs();
  }

  onStatusFilter(event: MatChipListboxChange): void {
    this.statusFilter = event.value || '';
    this.pageIndex = 0;
    this.loadCdrs();
  }

  viewCallLadder(cdr: CdrRecord): void {
    this.router.navigate(['/call-ladder'], { queryParams: { callId: cdr.call_id } });
  }

  formatDuration(secs?: number): string {
    if (secs == null) return '--';
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  }
}
