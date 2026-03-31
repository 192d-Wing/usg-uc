import { Component, inject, OnInit, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatTableModule } from '@angular/material/table';
import { MatChipsModule } from '@angular/material/chips';
import { TitleCasePipe } from '@angular/common';
import { ApiService } from '../../services/api.service';
import { PhoneDialogComponent } from './phone-dialog.component';

@Component({
  selector: 'app-phones',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatTableModule, MatChipsModule, TitleCasePipe,
  ],
  template: `
    <div class="phones-page">
      <div class="page-header">
        <h2 class="page-title">Phones</h2>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddDialog()">
          <mat-icon>add</mat-icon> Add Phone
        </button>
        <button mat-icon-button (click)="loadPhones()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      @if (phones().length) {
        <mat-card class="table-card">
          <table mat-table [dataSource]="phones()" class="phones-table">
            <ng-container matColumnDef="name">
              <th mat-header-cell *matHeaderCellDef>Name</th>
              <td mat-cell *matCellDef="let row">{{ row.name }}</td>
            </ng-container>
            <ng-container matColumnDef="mac_address">
              <th mat-header-cell *matHeaderCellDef>MAC Address</th>
              <td mat-cell *matCellDef="let row">{{ row.mac_address }}</td>
            </ng-container>
            <ng-container matColumnDef="model">
              <th mat-header-cell *matHeaderCellDef>Model</th>
              <td mat-cell *matCellDef="let row">{{ formatModel(row.model) }}</td>
            </ng-container>
            <ng-container matColumnDef="status">
              <th mat-header-cell *matHeaderCellDef>Status</th>
              <td mat-cell *matCellDef="let row">
                <span class="status-chip" [class]="'status-' + (row.status || 'offline')">
                  {{ (row.status || 'offline') | titlecase }}
                </span>
              </td>
            </ng-container>
            <ng-container matColumnDef="owner">
              <th mat-header-cell *matHeaderCellDef>Owner</th>
              <td mat-cell *matCellDef="let row">{{ row.owner_user_id }}</td>
            </ng-container>
            <ng-container matColumnDef="lines">
              <th mat-header-cell *matHeaderCellDef>Lines</th>
              <td mat-cell *matCellDef="let row">{{ row.lines?.length || 0 }}</td>
            </ng-container>
            <ng-container matColumnDef="firmware">
              <th mat-header-cell *matHeaderCellDef>Firmware</th>
              <td mat-cell *matCellDef="let row">{{ row.firmware_version }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let row">
                <button mat-icon-button color="warn" (click)="deletePhone(row.id)"
                        matTooltip="Delete Phone">
                  <mat-icon>delete</mat-icon>
                </button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns;"></tr>
          </table>
        </mat-card>
      } @else {
        <mat-card class="empty-card">
          <mat-card-content>
            <p class="empty-msg">No phones configured.</p>
          </mat-card-content>
        </mat-card>
      }
    </div>
  `,
  styles: [`
    .phones-page { padding: 24px; }

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

    .spacer { flex: 1; }

    .table-card, .empty-card {
      background: #16213e;
      color: #fff;
      border-radius: 12px;
    }

    .phones-table { width: 100%; }

    .status-chip {
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
    }

    .status-registered { background: rgba(76, 175, 80, 0.2); color: #81c784; }
    .status-provisioning { background: rgba(255, 235, 59, 0.2); color: #fff176; }
    .status-offline { background: rgba(158, 158, 158, 0.2); color: #bdbdbd; }
    .status-error { background: rgba(244, 67, 54, 0.2); color: #e57373; }

    .empty-msg {
      text-align: center;
      color: rgba(255, 255, 255, 0.5);
      padding: 24px;
    }
  `],
})
export class PhonesComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly displayedColumns = [
    'name', 'mac_address', 'model', 'status', 'owner', 'lines', 'firmware', 'actions',
  ];

  readonly phones = signal<any[]>([]);

  private readonly modelNames: Record<string, string> = {
    poly_edge_e100: 'Poly Edge E100', poly_edge_e220: 'Poly Edge E220',
    poly_edge_e300: 'Poly Edge E300', poly_edge_e350: 'Poly Edge E350',
    poly_edge_e400: 'Poly Edge E400', poly_edge_e450: 'Poly Edge E450',
    poly_edge_e500: 'Poly Edge E500', poly_edge_e550: 'Poly Edge E550',
    poly_edge_b10: 'Poly Edge B10', poly_edge_b20: 'Poly Edge B20',
    poly_edge_b30: 'Poly Edge B30',
    polycom_vvx150: 'Polycom VVX 150', polycom_vvx250: 'Polycom VVX 250',
    polycom_vvx350: 'Polycom VVX 350', polycom_vvx450: 'Polycom VVX 450',
    polycom_vvx501: 'Polycom VVX 501', polycom_vvx601: 'Polycom VVX 601',
    cisco_6821: 'Cisco 6821', cisco_6841: 'Cisco 6841',
    cisco_6851: 'Cisco 6851', cisco_6861: 'Cisco 6861',
    cisco_7821: 'Cisco 7821', cisco_7841: 'Cisco 7841',
    cisco_7861: 'Cisco 7861', cisco_8811: 'Cisco 8811',
    cisco_8841: 'Cisco 8841', cisco_8851: 'Cisco 8851',
    cisco_8861: 'Cisco 8861',
    cisco_9841: 'Cisco 9841', cisco_9851: 'Cisco 9851',
    cisco_9861: 'Cisco 9861', cisco_9871: 'Cisco 9871',
  };

  ngOnInit(): void {
    this.loadPhones();
  }

  loadPhones(): void {
    this.api.getPhones().subscribe({
      next: (phones) => this.phones.set(phones),
      error: () => {},
    });
  }

  openAddDialog(): void {
    const ref = this.dialog.open(PhoneDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.createPhone(result).subscribe({
          next: () => this.loadPhones(),
          error: () => {},
        });
      }
    });
  }

  deletePhone(id: string): void {
    this.api.deletePhone(id).subscribe({
      next: () => this.loadPhones(),
      error: () => {},
    });
  }

  formatModel(model: string): string {
    return this.modelNames[model] || model || 'Unknown';
  }
}
