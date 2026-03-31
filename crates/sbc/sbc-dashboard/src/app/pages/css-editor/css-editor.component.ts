import { Component, inject, OnInit, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatChipsModule } from '@angular/material/chips';
import { ApiService } from '../../services/api.service';
import { CssDialogComponent } from './css-dialog.component';

@Component({
  selector: 'app-css-editor',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatDialogModule, MatChipsModule,
  ],
  template: `
    <div class="css-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Calling Search Spaces</h1>
        <span class="spacer"></span>
        <button mat-raised-button color="primary" (click)="openAddDialog()">
          <mat-icon>add</mat-icon> Add CSS
        </button>
        <button mat-icon-button (click)="loadCss()" matTooltip="Refresh">
          <mat-icon>refresh</mat-icon>
        </button>
      </div>

      <div class="css-grid">
        @for (css of cssList(); track css.id) {
          <mat-card class="css-card">
            <mat-card-header>
              <mat-card-title>{{ css.name }}</mat-card-title>
            </mat-card-header>
            <mat-card-content>
              <div class="partition-chips">
                @for (p of css.partitions || []; track p; let i = $index) {
                  <span class="partition-chip">
                    <span class="chip-order">{{ i + 1 }}</span>
                    {{ p }}
                  </span>
                }
                @if (!css.partitions?.length) {
                  <span class="empty-hint">No partitions assigned</span>
                }
              </div>
            </mat-card-content>
            <mat-card-actions align="end">
              <button mat-icon-button (click)="editCss(css)"
                      matTooltip="Edit CSS">
                <mat-icon>edit</mat-icon>
              </button>
              <button mat-icon-button color="warn" (click)="deleteCss(css.id)"
                      matTooltip="Delete CSS">
                <mat-icon>delete</mat-icon>
              </button>
            </mat-card-actions>
          </mat-card>
        } @empty {
          <mat-card class="empty-card">
            <mat-card-content>
              <p class="empty-msg">No calling search spaces configured.</p>
            </mat-card-content>
          </mat-card>
        }
      </div>
    </div>
  `,
  styles: [`
    .css-page { padding: 24px; }

    .css-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 16px;
    }

    .css-card {
      transition: transform 250ms ease, box-shadow 250ms ease;
    }

    .css-card:hover {
      transform: translateY(-2px);
    }

    .partition-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 8px;
    }

    .partition-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 4px;
      font-size: 13px;
      background: rgba(0, 94, 162, 0.12);
      color: var(--uswds-primary-light);
      border: 1px solid rgba(0, 94, 162, 0.2);
    }

    .chip-order {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: var(--uswds-primary);
      color: #fff;
      font-size: 11px;
      font-weight: 700;
    }

    .empty-hint {
      color: var(--text-secondary);
      font-size: 13px;
    }
  `],
})
export class CssEditorComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);

  readonly cssList = signal<any[]>([]);

  ngOnInit(): void {
    this.loadCss();
  }

  loadCss(): void {
    this.api.getCss().subscribe({
      next: (list) => this.cssList.set(list),
      error: () => {},
    });
  }

  openAddDialog(): void {
    const ref = this.dialog.open(CssDialogComponent);
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.createCss(result).subscribe({
          next: () => this.loadCss(),
          error: () => {},
        });
      }
    });
  }

  editCss(css: any): void {
    const ref = this.dialog.open(CssDialogComponent, { data: css });
    ref.afterClosed().subscribe((result: any) => {
      if (result) {
        this.api.updateCss(css.id, result).subscribe({
          next: () => this.loadCss(),
          error: () => {},
        });
      }
    });
  }

  deleteCss(id: string): void {
    this.api.deleteCss(id).subscribe({
      next: () => this.loadCss(),
      error: () => {},
    });
  }
}
