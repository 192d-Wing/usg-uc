import { Component, inject, OnInit, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { TitleCasePipe } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatTabsModule } from '@angular/material/tabs';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSliderModule } from '@angular/material/slider';
import { MatTableModule } from '@angular/material/table';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-phone-detail',
  standalone: true,
  imports: [
    RouterModule, FormsModule, TitleCasePipe,
    MatCardModule, MatIconModule, MatButtonModule, MatTooltipModule,
    MatTabsModule, MatFormFieldModule, MatInputModule, MatSelectModule,
    MatSlideToggleModule, MatSliderModule, MatTableModule, MatChipsModule,
    MatSnackBarModule,
  ],
  styleUrl: './phone-detail.component.scss',
  template: `
    <div class="phone-detail-page">
      <!-- Header -->
      <div class="page-header">
        <button mat-icon-button (click)="goBack()" matTooltip="Back to Phones">
          <mat-icon>arrow_back</mat-icon>
        </button>
        <h2 class="page-title">{{ phone().name || 'Phone Details' }}</h2>
        <span class="spacer"></span>
        <div class="header-actions">
          <button mat-raised-button color="primary" (click)="savePhone()" matTooltip="Save Changes">
            <mat-icon>save</mat-icon> Save
          </button>
          <button mat-stroked-button (click)="rebootPhone()" matTooltip="Reboot Phone">
            <mat-icon>restart_alt</mat-icon> Reboot
          </button>
        </div>
      </div>

      <!-- Tabs -->
      <mat-tab-group class="detail-tabs" animationDuration="200ms">

        <!-- Tab 1: General -->
        <mat-tab label="General">
          <div class="glass-card" style="margin-top: 16px;">
            <h3 class="card-title">General Information</h3>
            <div class="form-grid">
              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Name</mat-label>
                <input matInput [(ngModel)]="phone().name" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>MAC Address</mat-label>
                <input matInput [value]="phone().mac_address" readonly />
              </mat-form-field>

              <div class="info-row">
                <span class="info-label">Model</span>
                <span class="model-badge">{{ formatModel(phone().model) }}</span>
              </div>

              <div class="info-row">
                <span class="info-label">Status</span>
                <span class="status-chip" [class]="'status-' + (phone().status || 'offline')">
                  <span class="status-dot"></span>
                  {{ (phone().status || 'offline') | titlecase }}
                </span>
              </div>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Owner</mat-label>
                <input matInput [(ngModel)]="phone().owner_user_id" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Calling Search Space</mat-label>
                <input matInput [(ngModel)]="phone().calling_search_space" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Device Pool</mat-label>
                <input matInput [(ngModel)]="phone().device_pool" />
              </mat-form-field>

              <div class="info-row">
                <span class="info-label">Firmware</span>
                <span class="info-value">{{ phone().firmware_version || '--' }}</span>
              </div>

              <div class="info-row">
                <span class="info-label">IP Address</span>
                <span class="info-value">{{ phone().ip_address || '--' }}</span>
              </div>

              <div class="info-row">
                <span class="info-label">Last Seen</span>
                <span class="info-value">{{ phone().last_seen || '--' }}</span>
              </div>
            </div>
          </div>
        </mat-tab>

        <!-- Tab 2: Lines -->
        <mat-tab label="Lines">
          <div style="margin-top: 16px;">
            @for (line of phone().lines || []; track $index) {
              <div class="line-card">
                <div class="line-header">
                  <span class="line-badge">{{ $index + 1 }}</span>
                  <span class="line-title">Line {{ $index + 1 }}</span>
                  <span class="line-actions">
                    <button mat-icon-button color="warn" (click)="removeLine($index)"
                            matTooltip="Remove Line">
                      <mat-icon>delete</mat-icon>
                    </button>
                  </span>
                </div>
                <div class="form-grid">
                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Directory Number</mat-label>
                    <input matInput [(ngModel)]="line.directory_number" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Display Name</mat-label>
                    <input matInput [(ngModel)]="line.display_name" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>SIP Username</mat-label>
                    <input matInput [(ngModel)]="line.sip_username" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>SIP Password</mat-label>
                    <input matInput [(ngModel)]="line.sip_password" type="password" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>SIP Server</mat-label>
                    <input matInput [(ngModel)]="line.sip_server" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Port</mat-label>
                    <input matInput [(ngModel)]="line.sip_port" type="number" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Transport</mat-label>
                    <mat-select [(ngModel)]="line.transport">
                      <mat-option value="udp">UDP</mat-option>
                      <mat-option value="tcp">TCP</mat-option>
                      <mat-option value="tls">TLS</mat-option>
                    </mat-select>
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Voicemail URI</mat-label>
                    <input matInput [(ngModel)]="line.voicemail_uri" />
                  </mat-form-field>
                </div>

                <!-- Call Forwarding -->
                <h4 class="section-subtitle">Call Forwarding</h4>
                <div class="form-grid">
                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Forward All</mat-label>
                    <input matInput [(ngModel)]="line.forward_all" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Forward Busy</mat-label>
                    <input matInput [(ngModel)]="line.forward_busy" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Forward No Answer</mat-label>
                    <input matInput [(ngModel)]="line.forward_no_answer" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>No Answer Timeout (sec)</mat-label>
                    <input matInput [(ngModel)]="line.forward_no_answer_timeout" type="number" />
                  </mat-form-field>
                </div>

                <div class="toggle-row">
                  <div>
                    <div class="toggle-label">Shared Line</div>
                    <div class="toggle-sublabel">Allow multiple devices on this line</div>
                  </div>
                  <mat-slide-toggle [(ngModel)]="line.shared_line"></mat-slide-toggle>
                </div>
              </div>
            }

            <button mat-stroked-button (click)="addLine()"
                    [disabled]="(phone().lines?.length || 0) >= getMaxLines()">
              <mat-icon>add</mat-icon> Add Line
            </button>
          </div>
        </mat-tab>

        <!-- Tab 3: Speed Dials & BLF -->
        <mat-tab label="Speed Dials & BLF">
          <div class="split-layout" style="margin-top: 16px;">
            <!-- Speed Dials -->
            <div class="glass-card">
              <h3 class="card-title">Speed Dials</h3>
              @if (phone().speed_dials?.length) {
                <table mat-table [dataSource]="phone().speed_dials" class="tab-table">
                  <ng-container matColumnDef="position">
                    <th mat-header-cell *matHeaderCellDef>Pos</th>
                    <td mat-cell *matCellDef="let row; let i = index">
                      <input matInput [(ngModel)]="row.position" type="number" style="width: 50px; background: transparent; border: none; color: var(--text-primary);" />
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="label">
                    <th mat-header-cell *matHeaderCellDef>Label</th>
                    <td mat-cell *matCellDef="let row">
                      <input matInput [(ngModel)]="row.label" style="background: transparent; border: none; color: var(--text-primary);" />
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="number">
                    <th mat-header-cell *matHeaderCellDef>Number</th>
                    <td mat-cell *matCellDef="let row">
                      <input matInput [(ngModel)]="row.number" style="background: transparent; border: none; color: var(--text-primary);" />
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="blf">
                    <th mat-header-cell *matHeaderCellDef>BLF</th>
                    <td mat-cell *matCellDef="let row">
                      <mat-slide-toggle [(ngModel)]="row.blf"></mat-slide-toggle>
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="actions">
                    <th mat-header-cell *matHeaderCellDef></th>
                    <td mat-cell *matCellDef="let row; let i = index">
                      <button mat-icon-button color="warn" (click)="removeSpeedDial(i)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </ng-container>
                  <tr mat-header-row *matHeaderRowDef="speedDialColumns"></tr>
                  <tr mat-row *matRowDef="let row; columns: speedDialColumns;"></tr>
                </table>
              } @else {
                <p class="empty-msg">No speed dials configured.</p>
              }
              <div class="table-actions">
                <button mat-stroked-button (click)="addSpeedDial()">
                  <mat-icon>add</mat-icon> Add
                </button>
              </div>
            </div>

            <!-- BLF Entries -->
            <div class="glass-card">
              <h3 class="card-title">BLF Entries</h3>
              @if (phone().blf_entries?.length) {
                <table mat-table [dataSource]="phone().blf_entries" class="tab-table">
                  <ng-container matColumnDef="position">
                    <th mat-header-cell *matHeaderCellDef>Pos</th>
                    <td mat-cell *matCellDef="let row">
                      <input matInput [(ngModel)]="row.position" type="number" style="width: 50px; background: transparent; border: none; color: var(--text-primary);" />
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="uri">
                    <th mat-header-cell *matHeaderCellDef>URI</th>
                    <td mat-cell *matCellDef="let row">
                      <input matInput [(ngModel)]="row.uri" style="background: transparent; border: none; color: var(--text-primary);" />
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="label">
                    <th mat-header-cell *matHeaderCellDef>Label</th>
                    <td mat-cell *matCellDef="let row">
                      <input matInput [(ngModel)]="row.label" style="background: transparent; border: none; color: var(--text-primary);" />
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="pickup">
                    <th mat-header-cell *matHeaderCellDef>Pickup</th>
                    <td mat-cell *matCellDef="let row">
                      <mat-slide-toggle [(ngModel)]="row.pickup_enabled"></mat-slide-toggle>
                    </td>
                  </ng-container>
                  <ng-container matColumnDef="actions">
                    <th mat-header-cell *matHeaderCellDef></th>
                    <td mat-cell *matCellDef="let row; let i = index">
                      <button mat-icon-button color="warn" (click)="removeBlfEntry(i)">
                        <mat-icon>delete</mat-icon>
                      </button>
                    </td>
                  </ng-container>
                  <tr mat-header-row *matHeaderRowDef="blfColumns"></tr>
                  <tr mat-row *matRowDef="let row; columns: blfColumns;"></tr>
                </table>
              } @else {
                <p class="empty-msg">No BLF entries configured.</p>
              }
              <div class="table-actions">
                <button mat-stroked-button (click)="addBlfEntry()">
                  <mat-icon>add</mat-icon> Add
                </button>
              </div>
            </div>
          </div>
        </mat-tab>

        <!-- Tab 4: Features -->
        <mat-tab label="Features">
          <div class="glass-card" style="margin-top: 16px;">
            <h3 class="card-title">Features</h3>
            <div class="form-grid">
              <!-- Auto Answer -->
              <div>
                <div class="toggle-row">
                  <div class="toggle-label">Auto Answer</div>
                  <mat-slide-toggle [(ngModel)]="phone().features.auto_answer"></mat-slide-toggle>
                </div>
                @if (phone().features.auto_answer) {
                  <div class="sub-field">
                    <mat-form-field appearance="outline" class="form-field">
                      <mat-label>Auto Answer Delay (ms)</mat-label>
                      <input matInput [(ngModel)]="phone().features.auto_answer_delay" type="number" />
                    </mat-form-field>
                  </div>
                }
              </div>

              <!-- DND -->
              <div>
                <div class="toggle-row">
                  <div class="toggle-label">Do Not Disturb</div>
                  <mat-slide-toggle [(ngModel)]="phone().features.dnd"></mat-slide-toggle>
                </div>
                @if (phone().features.dnd) {
                  <div class="sub-field">
                    <mat-form-field appearance="outline" class="form-field">
                      <mat-label>DND Ringtone</mat-label>
                      <input matInput [(ngModel)]="phone().features.dnd_ringtone" />
                    </mat-form-field>
                  </div>
                }
              </div>

              <!-- Call Park -->
              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Call Park Extension</mat-label>
                <input matInput [(ngModel)]="phone().features.call_park_extension" />
              </mat-form-field>

              <!-- Pickup Group -->
              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Pickup Group</mat-label>
                <input matInput [(ngModel)]="phone().features.pickup_group" />
              </mat-form-field>

              <!-- Intercom -->
              <div class="toggle-row">
                <div class="toggle-label">Intercom</div>
                <mat-slide-toggle [(ngModel)]="phone().features.intercom"></mat-slide-toggle>
              </div>

              <div class="toggle-row">
                <div class="toggle-label">Auto Answer Intercom</div>
                <mat-slide-toggle [(ngModel)]="phone().features.auto_answer_intercom"></mat-slide-toggle>
              </div>

              <!-- Hotline -->
              <div>
                <div class="toggle-row">
                  <div class="toggle-label">Hotline</div>
                  <mat-slide-toggle [(ngModel)]="phone().features.hotline"></mat-slide-toggle>
                </div>
                @if (phone().features.hotline) {
                  <div class="sub-field">
                    <mat-form-field appearance="outline" class="form-field">
                      <mat-label>Hotline Number</mat-label>
                      <input matInput [(ngModel)]="phone().features.hotline_number" />
                    </mat-form-field>
                  </div>
                }
              </div>

              <!-- Call Recording -->
              <div class="toggle-row">
                <div class="toggle-label">Call Recording</div>
                <mat-slide-toggle [(ngModel)]="phone().features.call_recording"></mat-slide-toggle>
              </div>
            </div>

            <!-- Paging Section -->
            <div class="paging-section">
              <h3 class="card-title">Paging</h3>
              <div class="form-grid">
                <div class="toggle-row">
                  <div class="toggle-label">Paging Enabled</div>
                  <mat-slide-toggle [(ngModel)]="phone().features.paging_enabled"></mat-slide-toggle>
                </div>

                @if (phone().features.paging_enabled) {
                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Multicast Address</mat-label>
                    <input matInput [(ngModel)]="phone().features.paging_multicast_address" />
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Priority</mat-label>
                    <mat-select [(ngModel)]="phone().features.paging_priority">
                      @for (p of [0,1,2,3,4,5]; track p) {
                        <mat-option [value]="p">{{ p }}</mat-option>
                      }
                    </mat-select>
                  </mat-form-field>

                  <mat-form-field appearance="outline" class="form-field">
                    <mat-label>Paging Group</mat-label>
                    <input matInput [(ngModel)]="phone().features.paging_group" />
                  </mat-form-field>
                }
              </div>
            </div>
          </div>
        </mat-tab>

        <!-- Tab 5: Network -->
        <mat-tab label="Network">
          <div class="glass-card" style="margin-top: 16px;">
            <h3 class="card-title">Network Configuration</h3>
            <div class="form-grid">
              <mat-form-field appearance="outline" class="form-field">
                <mat-label>VLAN ID</mat-label>
                <input matInput [(ngModel)]="phone().network.vlan_id" type="number" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>VLAN Priority</mat-label>
                <mat-select [(ngModel)]="phone().network.vlan_priority">
                  @for (p of [0,1,2,3,4,5,6,7]; track p) {
                    <mat-option [value]="p">{{ p }}</mat-option>
                  }
                </mat-select>
              </mat-form-field>

              <div class="toggle-row">
                <div class="toggle-label">CDP Enabled</div>
                <mat-slide-toggle [(ngModel)]="phone().network.cdp_enabled"></mat-slide-toggle>
              </div>

              <div class="toggle-row">
                <div class="toggle-label">LLDP Enabled</div>
                <mat-slide-toggle [(ngModel)]="phone().network.lldp_enabled"></mat-slide-toggle>
              </div>

              <div>
                <div class="toggle-row">
                  <div class="toggle-label">802.1x Enabled</div>
                  <mat-slide-toggle [(ngModel)]="phone().network.dot1x_enabled"></mat-slide-toggle>
                </div>
                @if (phone().network.dot1x_enabled) {
                  <div class="sub-field">
                    <mat-form-field appearance="outline" class="form-field">
                      <mat-label>802.1x Identity</mat-label>
                      <input matInput [(ngModel)]="phone().network.dot1x_identity" />
                    </mat-form-field>
                  </div>
                }
              </div>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>QoS DSCP</mat-label>
                <input matInput [(ngModel)]="phone().network.qos_dscp" type="number" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>HTTP Proxy</mat-label>
                <input matInput [(ngModel)]="phone().network.http_proxy" />
              </mat-form-field>
            </div>
          </div>
        </mat-tab>

        <!-- Tab 6: Display & Audio -->
        <mat-tab label="Display & Audio">
          <div class="cards-row" style="margin-top: 16px;">
            <!-- Display -->
            <div class="glass-card">
              <h3 class="card-title">Display</h3>

              <div class="slider-row">
                <span class="slider-label">Brightness</span>
                <mat-slider min="0" max="100" step="1" discrete>
                  <input matSliderThumb [(ngModel)]="phone().display.brightness" />
                </mat-slider>
                <span class="slider-value">{{ phone().display.brightness }}</span>
              </div>

              <div class="slider-row">
                <span class="slider-label">Contrast</span>
                <mat-slider min="0" max="100" step="1" discrete>
                  <input matSliderThumb [(ngModel)]="phone().display.contrast" />
                </mat-slider>
                <span class="slider-value">{{ phone().display.contrast }}</span>
              </div>

              <div class="form-grid">
                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Wallpaper URL</mat-label>
                  <input matInput [(ngModel)]="phone().display.wallpaper_url" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Screensaver Timeout (sec)</mat-label>
                  <input matInput [(ngModel)]="phone().display.screensaver_timeout" type="number" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Backlight Timeout (sec)</mat-label>
                  <input matInput [(ngModel)]="phone().display.backlight_timeout" type="number" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Ringtone</mat-label>
                  <input matInput [(ngModel)]="phone().display.ringtone" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Language</mat-label>
                  <mat-select [(ngModel)]="phone().display.language">
                    <mat-option value="en-US">English (US)</mat-option>
                    <mat-option value="de-DE">Deutsch</mat-option>
                    <mat-option value="fr-FR">Francais</mat-option>
                    <mat-option value="es-ES">Espanol</mat-option>
                    <mat-option value="ja-JP">Japanese</mat-option>
                  </mat-select>
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Time Zone</mat-label>
                  <input matInput [(ngModel)]="phone().display.time_zone" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>NTP Server</mat-label>
                  <input matInput [(ngModel)]="phone().display.ntp_server" />
                </mat-form-field>

                <div class="toggle-row">
                  <div class="toggle-label">24-Hour Time Format</div>
                  <mat-slide-toggle [(ngModel)]="phone().display.time_format_24h"></mat-slide-toggle>
                </div>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Date Format</mat-label>
                  <mat-select [(ngModel)]="phone().display.date_format">
                    <mat-option value="M/D/Y">M/D/Y</mat-option>
                    <mat-option value="D/M/Y">D/M/Y</mat-option>
                    <mat-option value="Y-M-D">Y-M-D</mat-option>
                  </mat-select>
                </mat-form-field>
              </div>
            </div>

            <!-- Audio -->
            <div class="glass-card">
              <h3 class="card-title">Audio</h3>

              <mat-form-field appearance="outline" class="form-field" style="width: 100%; margin-bottom: 12px;">
                <mat-label>Headset Mode</mat-label>
                <mat-select [(ngModel)]="phone().audio.headset_mode">
                  <mat-option value="none">None</mat-option>
                  <mat-option value="usb">USB</mat-option>
                  <mat-option value="bluetooth">Bluetooth</mat-option>
                  <mat-option value="analog">Analog</mat-option>
                  <mat-option value="ehs">EHS</mat-option>
                </mat-select>
              </mat-form-field>

              <div class="toggle-row">
                <div class="toggle-label">Wideband</div>
                <mat-slide-toggle [(ngModel)]="phone().audio.wideband"></mat-slide-toggle>
              </div>

              <div class="toggle-row">
                <div class="toggle-label">Electronic Hookswitch</div>
                <mat-slide-toggle [(ngModel)]="phone().audio.electronic_hookswitch"></mat-slide-toggle>
              </div>

              <div class="toggle-row">
                <div class="toggle-label">Noise Reduction</div>
                <mat-slide-toggle [(ngModel)]="phone().audio.noise_reduction"></mat-slide-toggle>
              </div>

              <div class="toggle-row">
                <div class="toggle-label">Acoustic Fence</div>
                <mat-slide-toggle [(ngModel)]="phone().audio.acoustic_fence"></mat-slide-toggle>
              </div>

              <div class="slider-row">
                <span class="slider-label">Ringer Volume</span>
                <mat-slider min="0" max="15" step="1" discrete>
                  <input matSliderThumb [(ngModel)]="phone().audio.ringer_volume" />
                </mat-slider>
                <span class="slider-value">{{ phone().audio.ringer_volume }}</span>
              </div>

              <div class="slider-row">
                <span class="slider-label">Speaker Volume</span>
                <mat-slider min="0" max="15" step="1" discrete>
                  <input matSliderThumb [(ngModel)]="phone().audio.speaker_volume" />
                </mat-slider>
                <span class="slider-value">{{ phone().audio.speaker_volume }}</span>
              </div>

              <div class="slider-row">
                <span class="slider-label">Handset Volume</span>
                <mat-slider min="0" max="15" step="1" discrete>
                  <input matSliderThumb [(ngModel)]="phone().audio.handset_volume" />
                </mat-slider>
                <span class="slider-value">{{ phone().audio.handset_volume }}</span>
              </div>
            </div>
          </div>
        </mat-tab>

        <!-- Tab 7: Directory -->
        <mat-tab label="Directory">
          <div class="glass-card" style="margin-top: 16px;">
            <h3 class="card-title">Directory Settings</h3>
            <div class="form-grid">
              <div class="toggle-row full-width">
                <div class="toggle-label">LDAP Enabled</div>
                <mat-slide-toggle [(ngModel)]="phone().directory.ldap_enabled"></mat-slide-toggle>
              </div>

              @if (phone().directory.ldap_enabled) {
                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>LDAP Server</mat-label>
                  <input matInput [(ngModel)]="phone().directory.ldap_server" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Base DN</mat-label>
                  <input matInput [(ngModel)]="phone().directory.ldap_base_dn" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Username</mat-label>
                  <input matInput [(ngModel)]="phone().directory.ldap_username" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field">
                  <mat-label>Password</mat-label>
                  <input matInput [(ngModel)]="phone().directory.ldap_password" type="password" />
                </mat-form-field>

                <mat-form-field appearance="outline" class="form-field full-width">
                  <mat-label>Search Filter</mat-label>
                  <input matInput [(ngModel)]="phone().directory.ldap_search_filter" />
                </mat-form-field>
              }

              <mat-form-field appearance="outline" class="form-field full-width">
                <mat-label>Corporate Directory URL</mat-label>
                <input matInput [(ngModel)]="phone().directory.corporate_directory_url" />
              </mat-form-field>
            </div>
          </div>
        </mat-tab>

        <!-- Tab 8: Emergency -->
        <mat-tab label="Emergency">
          <div class="glass-card" style="margin-top: 16px;">
            <h3 class="card-title">Emergency Settings</h3>
            <div class="form-grid">
              <mat-form-field appearance="outline" class="form-field">
                <mat-label>E911 Number</mat-label>
                <input matInput [(ngModel)]="phone().emergency.e911_number" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>ELIN</mat-label>
                <input matInput [(ngModel)]="phone().emergency.elin" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Location Description</mat-label>
                <input matInput [(ngModel)]="phone().emergency.location_description" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Building</mat-label>
                <input matInput [(ngModel)]="phone().emergency.building" />
              </mat-form-field>

              <mat-form-field appearance="outline" class="form-field">
                <mat-label>Floor</mat-label>
                <input matInput [(ngModel)]="phone().emergency.floor" />
              </mat-form-field>
            </div>
          </div>
        </mat-tab>

      </mat-tab-group>
    </div>
  `,
})
export class PhoneDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly api = inject(ApiService);
  private readonly snackBar = inject(MatSnackBar);

  readonly speedDialColumns = ['position', 'label', 'number', 'blf', 'actions'];
  readonly blfColumns = ['position', 'uri', 'label', 'pickup', 'actions'];

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

  private readonly modelMaxLines: Record<string, number> = {
    poly_edge_e100: 2, poly_edge_e220: 4,
    poly_edge_e300: 8, poly_edge_e350: 8,
    poly_edge_e400: 16, poly_edge_e450: 16,
    poly_edge_e500: 24, poly_edge_e550: 24,
    poly_edge_b10: 2, poly_edge_b20: 4, poly_edge_b30: 8,
    polycom_vvx150: 2, polycom_vvx250: 4,
    polycom_vvx350: 6, polycom_vvx450: 12,
    polycom_vvx501: 12, polycom_vvx601: 16,
    cisco_6821: 2, cisco_6841: 4, cisco_6851: 4, cisco_6861: 4,
    cisco_7821: 2, cisco_7841: 4, cisco_7861: 16,
    cisco_8811: 5, cisco_8841: 5, cisco_8851: 5, cisco_8861: 5,
    cisco_9841: 4, cisco_9851: 6, cisco_9861: 10, cisco_9871: 16,
  };

  readonly phone = signal<any>(this.defaultPhone());

  private phoneId = '';

  ngOnInit(): void {
    this.phoneId = this.route.snapshot.paramMap.get('id') || '';
    if (this.phoneId) {
      this.api.getPhone(this.phoneId).subscribe({
        next: (data) => {
          const merged = { ...this.defaultPhone(), ...data };
          merged.features = { ...this.defaultPhone().features, ...data.features };
          merged.network = { ...this.defaultPhone().network, ...data.network };
          merged.display = { ...this.defaultPhone().display, ...data.display };
          merged.audio = { ...this.defaultPhone().audio, ...data.audio };
          merged.directory = { ...this.defaultPhone().directory, ...data.directory };
          merged.emergency = { ...this.defaultPhone().emergency, ...data.emergency };
          merged.lines = data.lines || [];
          merged.speed_dials = data.speed_dials || [];
          merged.blf_entries = data.blf_entries || [];
          this.phone.set(merged);
        },
        error: () => this.snackBar.open('Failed to load phone', 'Close', { duration: 3000 }),
      });
    }
  }

  private defaultPhone(): any {
    return {
      name: '', mac_address: '', model: '', status: 'offline',
      owner_user_id: '', calling_search_space: '', device_pool: '',
      firmware_version: '', ip_address: '', last_seen: '',
      lines: [], speed_dials: [], blf_entries: [],
      features: {
        auto_answer: false, auto_answer_delay: 0,
        dnd: false, dnd_ringtone: '',
        call_park_extension: '', pickup_group: '',
        intercom: false, auto_answer_intercom: false,
        hotline: false, hotline_number: '',
        call_recording: false,
        paging_enabled: false, paging_multicast_address: '',
        paging_priority: 0, paging_group: '',
      },
      network: {
        vlan_id: 0, vlan_priority: 0,
        cdp_enabled: false, lldp_enabled: false,
        dot1x_enabled: false, dot1x_identity: '',
        qos_dscp: 46, http_proxy: '',
      },
      display: {
        brightness: 50, contrast: 50,
        wallpaper_url: '', screensaver_timeout: 300, backlight_timeout: 60,
        ringtone: '', language: 'en-US',
        time_zone: '', ntp_server: '',
        time_format_24h: false, date_format: 'M/D/Y',
      },
      audio: {
        headset_mode: 'none', wideband: false, electronic_hookswitch: false,
        noise_reduction: false, acoustic_fence: false,
        ringer_volume: 8, speaker_volume: 8, handset_volume: 8,
      },
      directory: {
        ldap_enabled: false, ldap_server: '', ldap_base_dn: '',
        ldap_username: '', ldap_password: '', ldap_search_filter: '',
        corporate_directory_url: '',
      },
      emergency: {
        e911_number: '', elin: '',
        location_description: '', building: '', floor: '',
      },
    };
  }

  goBack(): void {
    this.router.navigate(['/phones']);
  }

  savePhone(): void {
    this.api.updatePhone(this.phoneId, this.phone()).subscribe({
      next: () => this.snackBar.open('Phone saved successfully', 'Close', { duration: 3000 }),
      error: () => this.snackBar.open('Failed to save phone', 'Close', { duration: 3000 }),
    });
  }

  rebootPhone(): void {
    this.api.rebootPhone(this.phoneId).subscribe({
      next: () => this.snackBar.open('Reboot command sent', 'Close', { duration: 3000 }),
      error: () => this.snackBar.open('Failed to reboot phone', 'Close', { duration: 3000 }),
    });
  }

  formatModel(model: string): string {
    return this.modelNames[model] || model || 'Unknown';
  }

  getMaxLines(): number {
    return this.modelMaxLines[this.phone().model] || 4;
  }

  addLine(): void {
    const p = this.phone();
    const lines = [...(p.lines || [])];
    lines.push({
      position: lines.length + 1,
      directory_number: '', display_name: '',
      sip_username: '', sip_password: '', sip_server: '', sip_port: 5060,
      transport: 'udp', voicemail_uri: '',
      forward_all: '', forward_busy: '', forward_no_answer: '', forward_no_answer_timeout: 20,
      shared_line: false,
    });
    this.phone.set({ ...p, lines });
  }

  removeLine(index: number): void {
    const p = this.phone();
    const lines = [...(p.lines || [])];
    lines.splice(index, 1);
    this.phone.set({ ...p, lines });
  }

  addSpeedDial(): void {
    const p = this.phone();
    const sd = [...(p.speed_dials || [])];
    sd.push({ position: sd.length + 1, label: '', number: '', blf: false });
    this.phone.set({ ...p, speed_dials: sd });
  }

  removeSpeedDial(index: number): void {
    const p = this.phone();
    const sd = [...(p.speed_dials || [])];
    sd.splice(index, 1);
    this.phone.set({ ...p, speed_dials: sd });
  }

  addBlfEntry(): void {
    const p = this.phone();
    const entries = [...(p.blf_entries || [])];
    entries.push({ position: entries.length + 1, uri: '', label: '', pickup_enabled: false });
    this.phone.set({ ...p, blf_entries: entries });
  }

  removeBlfEntry(index: number): void {
    const p = this.phone();
    const entries = [...(p.blf_entries || [])];
    entries.splice(index, 1);
    this.phone.set({ ...p, blf_entries: entries });
  }
}
