import { Component, inject, OnInit } from '@angular/core';
import { MatDialogRef, MatDialogModule, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { FormsModule } from '@angular/forms';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';

@Component({
  selector: 'app-trunk-dialog',
  standalone: true,
  imports: [
    MatDialogModule, MatFormFieldModule, MatInputModule,
    MatSelectModule, MatButtonModule, FormsModule,
    MatSlideToggleModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ isEdit ? 'Edit Trunk' : 'Add Trunk' }}</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Trunk ID</mat-label>
        <input matInput [(ngModel)]="form.id" [disabled]="isEdit">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Host</mat-label>
        <input matInput [(ngModel)]="form.host">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Port</mat-label>
        <input matInput type="number" [(ngModel)]="form.port">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Protocol</mat-label>
        <mat-select [(ngModel)]="form.protocol">
          <mat-option value="udp">UDP</mat-option>
          <mat-option value="tcp">TCP</mat-option>
          <mat-option value="tls">TLS</mat-option>
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Priority</mat-label>
        <input matInput type="number" [(ngModel)]="form.priority">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Weight</mat-label>
        <input matInput type="number" [(ngModel)]="form.weight">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Max Calls</mat-label>
        <input matInput type="number" [(ngModel)]="form.max_calls">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Cooldown (seconds)</mat-label>
        <input matInput type="number" [(ngModel)]="form.cooldown_seconds">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Max Failures</mat-label>
        <input matInput type="number" [(ngModel)]="form.max_failures">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP Username</mat-label>
        <input matInput [(ngModel)]="form.sip_username">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP Password</mat-label>
        <input matInput type="password" [(ngModel)]="form.sip_password">
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP Domain</mat-label>
        <input matInput [(ngModel)]="form.sip_domain">
        <mat-hint>Domain for SIP registration (e.g., sip.carrier.com)</mat-hint>
      </mat-form-field>

      <div class="toggle-row">
        <mat-slide-toggle [(ngModel)]="form.options_ping_enabled">
          SIP OPTIONS Ping
        </mat-slide-toggle>
        <span class="toggle-hint">Send periodic OPTIONS to monitor trunk availability</span>
      </div>

      @if (form.options_ping_enabled) {
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Ping Interval (seconds)</mat-label>
          <input matInput type="number" [(ngModel)]="form.options_ping_interval" min="5" max="300" />
          <mat-hint>How often to send OPTIONS (5-300s)</mat-hint>
        </mat-form-field>
      }

      <div class="toggle-row">
        <mat-slide-toggle [(ngModel)]="form.register_enabled">
          SIP Registration
        </mat-slide-toggle>
        <span class="toggle-hint">Register the SBC as a subscriber to this trunk</span>
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" (click)="save()">Save</button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; max-height: 65vh; overflow-y: auto; padding-top: 8px !important; }
    .toggle-row { display: flex; flex-direction: column; gap: 4px; padding: 8px 0; }
    .toggle-hint { font-size: 12px; color: var(--uswds-text-secondary, rgba(255,255,255,0.5)); }
  `],
})
export class TrunkDialogComponent implements OnInit {
  private readonly dialogRef = inject(MatDialogRef<TrunkDialogComponent>);
  private readonly data: any = inject(MAT_DIALOG_DATA, { optional: true });

  isEdit = false;

  form = {
    id: '',
    host: '',
    port: 5060,
    protocol: 'udp',
    priority: 1,
    weight: 100,
    max_calls: 100,
    cooldown_seconds: 30,
    max_failures: 5,
    sip_username: '',
    sip_password: '',
    sip_domain: '',
    options_ping_enabled: false,
    options_ping_interval: 30,
    register_enabled: false,
  };

  ngOnInit(): void {
    if (this.data) {
      this.isEdit = true;
      this.form = {
        id: this.data.id ?? '',
        host: this.data.host ?? '',
        port: this.data.port ?? 5060,
        protocol: this.data.protocol ?? 'udp',
        priority: this.data.priority ?? 1,
        weight: this.data.weight ?? 100,
        max_calls: this.data.max_calls ?? 100,
        cooldown_seconds: this.data.cooldown_seconds ?? 30,
        max_failures: this.data.max_failures ?? 5,
        sip_username: this.data.sip_username ?? '',
        sip_password: this.data.sip_password ?? '',
        sip_domain: this.data.sip_domain ?? '',
        options_ping_enabled: this.data.options_ping_enabled ?? false,
        options_ping_interval: this.data.options_ping_interval ?? 30,
        register_enabled: this.data.register_enabled ?? false,
      };
    }
  }

  save(): void {
    this.dialogRef.close(this.form);
  }
}
