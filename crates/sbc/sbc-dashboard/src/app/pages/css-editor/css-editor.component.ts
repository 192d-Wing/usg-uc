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
        <h2 class="page-title">Calling Search Spaces</h2>
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

    .css-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 16px;
    }

    .css-card {
      background: #16213e;
      color: #fff;
      border-radius: 12px;
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
      border-radius: 16px;
      font-size: 13px;
      background: rgba(124, 77, 255, 0.15);
      color: #b388ff;
    }

    .chip-order {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: rgba(124, 77, 255, 0.3);
      font-size: 11px;
      font-weight: 600;
    }

    .empty-hint {
      color: rgba(255, 255, 255, 0.3);
      font-size: 13px;
    }

    .empty-card {
      background: #16213e;
      color: #fff;
      border-radius: 12px;
    }

    .empty-msg {
      text-align: center;
      color: rgba(255, 255, 255, 0.5);
      padding: 24px;
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

  deleteCss(id: string): void {
    this.api.deleteCss(id).subscribe({
      next: () => this.loadCss(),
      error: () => {},
    });
  }
}
