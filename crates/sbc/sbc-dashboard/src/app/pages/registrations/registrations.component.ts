import { Component, inject, OnInit, signal } from '@angular/core';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatTooltipModule } from '@angular/material/tooltip';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';
import { Registration } from '../../models/sbc.models';

interface FlatRegistration {
  aor: string;
  contactUri: string;
  expires?: number;
  transport?: string;
  sourceAddress?: string;
  userAgent?: string;
}

@Component({
  selector: 'app-registrations',
  standalone: true,
  imports: [
    MatTableModule, MatCardModule, MatIconModule, MatButtonModule,
    MatInputModule, MatFormFieldModule, MatPaginatorModule,
    MatTooltipModule, FormsModule,
  ],
  template: `
    <div class="registrations-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Registrations</h1>
        <button mat-icon-button (click)="loadRegistrations()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      <mat-card class="table-card">
        <mat-card-content>
          <mat-form-field appearance="outline" class="search-field">
            <mat-label>Search by AOR</mat-label>
            <input matInput [(ngModel)]="searchQuery" (input)="applyFilter()"
                   placeholder="sip:user@domain">
            <mat-icon matPrefix>search</mat-icon>
          </mat-form-field>

          <table mat-table [dataSource]="filteredRows()" class="reg-table">
            <ng-container matColumnDef="aor">
              <th mat-header-cell *matHeaderCellDef>AOR</th>
              <td mat-cell *matCellDef="let row">{{ row.aor }}</td>
            </ng-container>
            <ng-container matColumnDef="contactUri">
              <th mat-header-cell *matHeaderCellDef>Contact URI</th>
              <td mat-cell *matCellDef="let row">{{ row.contactUri }}</td>
            </ng-container>
            <ng-container matColumnDef="expires">
              <th mat-header-cell *matHeaderCellDef>Expires</th>
              <td mat-cell *matCellDef="let row">{{ row.expires ?? '--' }}s</td>
            </ng-container>
            <ng-container matColumnDef="transport">
              <th mat-header-cell *matHeaderCellDef>Transport</th>
              <td mat-cell *matCellDef="let row">{{ row.transport ?? '--' }}</td>
            </ng-container>
            <ng-container matColumnDef="sourceAddress">
              <th mat-header-cell *matHeaderCellDef>Source</th>
              <td mat-cell *matCellDef="let row">{{ row.sourceAddress ?? '--' }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let row">
                <button mat-icon-button color="warn"
                        (click)="deleteRegistration(row)"
                        matTooltip="Delete registration">
                  <mat-icon>delete</mat-icon>
                </button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns;"></tr>
          </table>

          <mat-paginator [length]="filteredRows().length"
                         [pageSize]="pageSize"
                         [pageSizeOptions]="[10, 25, 50]"
                         (page)="onPage($event)"
                         showFirstLastButtons>
          </mat-paginator>
        </mat-card-content>
      </mat-card>
    </div>
  `,
  styles: [`
    .registrations-page { padding: 24px; }

    .search-field {
      width: 100%;
      max-width: 400px;
      margin-bottom: 8px;
    }

    .reg-table { width: 100%; }
  `],
})
export class RegistrationsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly displayedColumns = ['aor', 'contactUri', 'expires', 'transport', 'sourceAddress', 'actions'];
  searchQuery = '';
  pageSize = 25;

  private allRows = signal<FlatRegistration[]>([]);
  readonly filteredRows = signal<FlatRegistration[]>([]);

  ngOnInit(): void {
    this.loadRegistrations();
  }

  loadRegistrations(): void {
    this.api.getRegistrations().subscribe({
      next: (regs) => {
        const rows = this.flattenRegistrations(regs);
        this.allRows.set(rows);
        this.applyFilter();
      },
      error: () => {},
    });
  }

  applyFilter(): void {
    const q = this.searchQuery.toLowerCase();
    const rows = this.allRows();
    if (!q) {
      this.filteredRows.set(rows);
    } else {
      this.filteredRows.set(rows.filter((r) => r.aor.toLowerCase().includes(q)));
    }
  }

  deleteRegistration(row: FlatRegistration): void {
    this.api.deleteRegistration(row.aor, row.contactUri).subscribe({
      next: () => this.loadRegistrations(),
      error: () => {},
    });
  }

  onPage(_event: PageEvent): void {
    // paginator handles display
  }

  private flattenRegistrations(regs: Registration[]): FlatRegistration[] {
    const rows: FlatRegistration[] = [];
    for (const reg of regs) {
      for (const c of reg.contacts) {
        rows.push({
          aor: reg.aor,
          contactUri: c.uri,
          expires: c.expires,
          transport: c.transport,
          sourceAddress: c.source_address,
          userAgent: reg.user_agent,
        });
      }
    }
    return rows;
  }
}
