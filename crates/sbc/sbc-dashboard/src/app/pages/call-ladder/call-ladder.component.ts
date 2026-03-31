import { Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatChipsModule } from '@angular/material/chips';
import { FormsModule } from '@angular/forms';
import { CallLadderDiagramComponent } from '../../components/call-ladder-diagram/call-ladder-diagram.component';
import { ApiService } from '../../services/api.service';
import { CallLadder, SipMessage } from '../../models/sbc.models';

@Component({
  selector: 'app-call-ladder-page',
  standalone: true,
  imports: [
    MatCardModule, MatIconModule, MatButtonModule, MatInputModule,
    MatFormFieldModule, MatChipsModule, FormsModule,
    CallLadderDiagramComponent,
  ],
  styleUrl: './call-ladder.component.scss',
  template: `
    <div class="call-ladder-page">
      <div class="page-header">
        <h1 class="usa-heading page-title">Call Ladder</h1>
      </div>

      <div class="search-row">
        <mat-form-field appearance="outline" class="search-field">
          <mat-label>Call ID</mat-label>
          <input matInput [(ngModel)]="callIdQuery" placeholder="Enter Call-ID"
                 (keydown.enter)="searchCallLadder()">
          <mat-icon matPrefix>search</mat-icon>
        </mat-form-field>
        <button mat-raised-button color="primary" (click)="searchCallLadder()">
          <mat-icon>timeline</mat-icon> Load
        </button>
      </div>

      @if (recentCallIds().length > 0) {
        <div class="recent-calls">
          <span class="recent-label">Recent:</span>
          @for (id of recentCallIds(); track id) {
            <button mat-stroked-button (click)="loadCallLadder(id)">
              {{ id.length > 16 ? id.substring(0, 16) + '...' : id }}
            </button>
          }
        </div>
      }

      @if (ladder()) {
        <mat-card class="ladder-card">
          <mat-card-content>
            <app-call-ladder-diagram
              [ladder]="ladder()"
              (messageSelected)="onMessageSelected($event)"
            />
          </mat-card-content>
        </mat-card>
      }

      @if (selectedMessage()) {
        <div class="detail-panel">
          <mat-card class="detail-card">
            <mat-card-header>
              <mat-card-title>Message Detail</mat-card-title>
            </mat-card-header>
            <mat-card-content>
              <div class="detail-header">
                <span class="detail-method">{{ selectedMessage()!.method_or_status }}</span>
                <span class="detail-direction">{{ selectedMessage()!.direction }}</span>
                <span class="detail-time">{{ selectedMessage()!.timestamp }}</span>
              </div>
              <div class="detail-route">
                {{ selectedMessage()!.source }} &rarr; {{ selectedMessage()!.destination }}
              </div>
              @if (selectedMessage()!.raw_message) {
                <pre class="detail-raw">{{ selectedMessage()!.raw_message }}</pre>
              }
            </mat-card-content>
          </mat-card>
        </div>
      }
    </div>
  `,
})
export class CallLadderPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);

  callIdQuery = '';
  readonly ladder = signal<CallLadder | null>(null);
  readonly selectedMessage = signal<SipMessage | null>(null);
  readonly recentCallIds = signal<string[]>([]);

  ngOnInit(): void {
    // Check for query param
    this.route.queryParams.subscribe((params) => {
      const callId = params['callId'];
      if (callId) {
        this.callIdQuery = callId;
        this.loadCallLadder(callId);
      }
    });

    // Load recent call IDs
    this.api.getRecentCallIds().subscribe({
      next: (ids) => this.recentCallIds.set(ids.slice(0, 5)),
      error: () => {},
    });
  }

  searchCallLadder(): void {
    if (this.callIdQuery.trim()) {
      this.loadCallLadder(this.callIdQuery.trim());
    }
  }

  loadCallLadder(callId: string): void {
    this.callIdQuery = callId;
    this.selectedMessage.set(null);
    this.api.getCallLadder(callId).subscribe({
      next: (ladder) => this.ladder.set(ladder),
      error: () => this.ladder.set(null),
    });
  }

  onMessageSelected(msg: SipMessage): void {
    this.selectedMessage.set(
      this.selectedMessage() === msg ? null : msg,
    );
  }
}
