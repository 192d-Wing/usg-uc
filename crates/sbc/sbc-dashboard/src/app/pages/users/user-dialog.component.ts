import { Component, inject, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'app-user-dialog',
  standalone: true,
  imports: [
    FormsModule, MatDialogModule, MatFormFieldModule,
    MatInputModule, MatSelectModule, MatButtonModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ isEdit ? 'Edit User' : 'Add User' }}</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Username</mat-label>
        <input matInput [(ngModel)]="user.username" required [disabled]="isEdit" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>{{ isEdit ? 'New Password (leave blank to keep)' : 'Password' }}</mat-label>
        <input matInput [(ngModel)]="user.password" type="password" />
        <mat-hint>Used for SIP digest authentication</mat-hint>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP Domain / Realm</mat-label>
        <input matInput [(ngModel)]="user.sip_domain" />
        <mat-hint>Digest realm (e.g., sip.example.com)</mat-hint>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Display Name</mat-label>
        <input matInput [(ngModel)]="user.display_name" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Email</mat-label>
        <input matInput [(ngModel)]="user.email" type="email" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP URI</mat-label>
        <input matInput [(ngModel)]="user.sip_uri" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Auth Type</mat-label>
        <mat-select [(ngModel)]="user.auth_type">
          <mat-option value="digest">Digest</mat-option>
          <mat-option value="mtls_pki">mTLS / PKI</mat-option>
          <mat-option value="both">Both</mat-option>
        </mat-select>
      </mat-form-field>

      @if (user.auth_type === 'mtls_pki' || user.auth_type === 'both') {
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Certificate DN</mat-label>
          <input matInput [(ngModel)]="user.certificate_dn" />
        </mat-form-field>
      }

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Calling Search Space</mat-label>
        <input matInput [(ngModel)]="user.calling_search_space" />
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" [disabled]="!user.username"
              (click)="dialogRef.close(user)">
        {{ isEdit ? 'Save' : 'Add' }}
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; max-height: 65vh; overflow-y: auto; padding-top: 8px !important; }
  `],
})
export class UserDialogComponent implements OnInit {
  private readonly data: any = inject(MAT_DIALOG_DATA, { optional: true });

  isEdit = false;

  user: any = {
    username: '',
    password: '',
    sip_domain: 'sbc-local',
    display_name: '',
    email: '',
    sip_uri: '',
    auth_type: 'digest',
    certificate_dn: '',
    calling_search_space: '',
  };

  constructor(public dialogRef: MatDialogRef<UserDialogComponent>) {}

  ngOnInit(): void {
    if (this.data) {
      this.isEdit = true;
      this.user = {
        ...this.user,
        username: this.data.username ?? '',
        display_name: this.data.display_name ?? '',
        email: this.data.email ?? '',
        sip_uri: this.data.sip_uri ?? '',
        auth_type: this.data.auth_type ?? 'digest',
        certificate_dn: this.data.certificate_dn ?? '',
        calling_search_space: this.data.calling_search_space ?? '',
        password: '', // Don't pre-fill password
        sip_domain: this.data.sip_domain ?? 'sbc-local',
        id: this.data.id,
      };
    }
  }
}
