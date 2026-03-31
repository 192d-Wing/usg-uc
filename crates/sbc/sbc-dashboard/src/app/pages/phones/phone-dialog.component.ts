import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';

interface ModelOption {
  value: string;
  label: string;
}

interface ModelGroup {
  name: string;
  models: ModelOption[];
}

@Component({
  selector: 'app-phone-dialog',
  standalone: true,
  imports: [
    FormsModule, MatDialogModule, MatFormFieldModule,
    MatInputModule, MatSelectModule, MatButtonModule,
  ],
  template: `
    <h2 mat-dialog-title>Add Phone</h2>
    <mat-dialog-content>
      <mat-form-field appearance="outline" class="full-width">
        <mat-label>MAC Address</mat-label>
        <input matInput [(ngModel)]="phone.mac_address" required placeholder="AA:BB:CC:DD:EE:FF" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Name</mat-label>
        <input matInput [(ngModel)]="phone.name" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Model</mat-label>
        <mat-select [(ngModel)]="phone.model">
          @for (group of modelGroups; track group.name) {
            <mat-optgroup [label]="group.name">
              @for (m of group.models; track m.value) {
                <mat-option [value]="m.value">{{ m.label }}</mat-option>
              }
            </mat-optgroup>
          }
        </mat-select>
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Owner (User ID)</mat-label>
        <input matInput [(ngModel)]="phone.owner_user_id" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Calling Search Space</mat-label>
        <input matInput [(ngModel)]="phone.calling_search_space" />
      </mat-form-field>

      <h3 class="section-title">Line 1</h3>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Directory Number</mat-label>
        <input matInput [(ngModel)]="line.directory_number" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>Display Name</mat-label>
        <input matInput [(ngModel)]="line.display_name" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP Username</mat-label>
        <input matInput [(ngModel)]="line.sip_username" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP Password</mat-label>
        <input matInput [(ngModel)]="line.sip_password" type="password" />
      </mat-form-field>

      <mat-form-field appearance="outline" class="full-width">
        <mat-label>SIP Server</mat-label>
        <input matInput [(ngModel)]="line.sip_server" />
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button color="primary" [disabled]="!phone.mac_address"
              (click)="submit()">
        Add
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    .full-width { width: 100%; }
    mat-dialog-content { display: flex; flex-direction: column; gap: 4px; min-width: 400px; }
    .section-title { color: rgba(255, 255, 255, 0.7); margin: 8px 0 4px; font-size: 14px; }
  `],
})
export class PhoneDialogComponent {
  phone: any = {
    mac_address: '',
    name: '',
    model: '',
    owner_user_id: '',
    calling_search_space: '',
  };

  line: any = {
    directory_number: '',
    display_name: '',
    sip_username: '',
    sip_password: '',
    sip_server: '',
  };

  readonly modelGroups: ModelGroup[] = [
    {
      name: 'Poly Edge',
      models: [
        { value: 'poly_edge_e100', label: 'E100' },
        { value: 'poly_edge_e220', label: 'E220' },
        { value: 'poly_edge_e300', label: 'E300' },
        { value: 'poly_edge_e350', label: 'E350' },
        { value: 'poly_edge_e400', label: 'E400' },
        { value: 'poly_edge_e450', label: 'E450' },
        { value: 'poly_edge_e500', label: 'E500' },
        { value: 'poly_edge_e550', label: 'E550' },
        { value: 'poly_edge_b10', label: 'B10' },
        { value: 'poly_edge_b20', label: 'B20' },
        { value: 'poly_edge_b30', label: 'B30' },
      ],
    },
    {
      name: 'Polycom VVX',
      models: [
        { value: 'polycom_vvx150', label: 'VVX 150' },
        { value: 'polycom_vvx250', label: 'VVX 250' },
        { value: 'polycom_vvx350', label: 'VVX 350' },
        { value: 'polycom_vvx450', label: 'VVX 450' },
        { value: 'polycom_vvx501', label: 'VVX 501' },
        { value: 'polycom_vvx601', label: 'VVX 601' },
      ],
    },
    {
      name: 'Cisco MPP',
      models: [
        { value: 'cisco_6821', label: '6821' },
        { value: 'cisco_6841', label: '6841' },
        { value: 'cisco_6851', label: '6851' },
        { value: 'cisco_6861', label: '6861' },
        { value: 'cisco_7821', label: '7821' },
        { value: 'cisco_7841', label: '7841' },
        { value: 'cisco_7861', label: '7861' },
        { value: 'cisco_8811', label: '8811' },
        { value: 'cisco_8841', label: '8841' },
        { value: 'cisco_8851', label: '8851' },
        { value: 'cisco_8861', label: '8861' },
      ],
    },
    {
      name: 'Cisco 9800',
      models: [
        { value: 'cisco_9841', label: '9841' },
        { value: 'cisco_9851', label: '9851' },
        { value: 'cisco_9861', label: '9861' },
        { value: 'cisco_9871', label: '9871' },
      ],
    },
  ];

  constructor(public dialogRef: MatDialogRef<PhoneDialogComponent>) {}

  submit(): void {
    const result = { ...this.phone };
    if (this.line.directory_number) {
      result.lines = [{ ...this.line, position: 1 }];
    }
    this.dialogRef.close(result);
  }
}
