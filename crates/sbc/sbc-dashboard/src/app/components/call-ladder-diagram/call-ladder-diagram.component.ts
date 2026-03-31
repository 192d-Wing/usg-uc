import { Component, input, output, signal, computed } from '@angular/core';
import { CallLadder, SipMessage } from '../../models/sbc.models';

interface ArrowLayout {
  message: SipMessage;
  y: number;
  fromX: number;
  toX: number;
  color: string;
  colorName: string;
  index: number;
}

@Component({
  selector: 'app-call-ladder-diagram',
  standalone: true,
  imports: [],
  template: `
    <div class="ladder-container">
      @if (ladder(); as ld) {
        <svg [attr.width]="svgWidth()" [attr.height]="svgHeight()" class="ladder-svg">
          <defs>
            <marker id="ah-blue" markerWidth="8" markerHeight="6"
                    refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
              <polygon points="0 0, 8 3, 0 6" fill="#64b5f6"/>
            </marker>
            <marker id="ah-gray" markerWidth="8" markerHeight="6"
                    refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
              <polygon points="0 0, 8 3, 0 6" fill="#9e9e9e"/>
            </marker>
            <marker id="ah-green" markerWidth="8" markerHeight="6"
                    refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
              <polygon points="0 0, 8 3, 0 6" fill="#4caf50"/>
            </marker>
            <marker id="ah-red" markerWidth="8" markerHeight="6"
                    refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
              <polygon points="0 0, 8 3, 0 6" fill="#f44336"/>
            </marker>
          </defs>

          @for (p of ld.participants; track p; let i = $index) {
            <text [attr.x]="participantX(i)" y="24" text-anchor="middle"
                  class="participant-label">{{ p }}</text>
            <line [attr.x1]="participantX(i)" y1="36"
                  [attr.x2]="participantX(i)" [attr.y2]="svgHeight() - 20"
                  class="participant-line"/>
          }

          @for (arrow of arrows(); track arrow.index) {
            <g class="message-group" (click)="onArrowClick(arrow.message)"
               [class.selected]="selectedMessage() === arrow.message">
              <text x="12" [attr.y]="arrow.y + 4"
                    class="timestamp-label">{{ formatTime(arrow.message.timestamp) }}</text>
              <line [attr.x1]="arrow.fromX" [attr.y1]="arrow.y"
                    [attr.x2]="arrow.toX" [attr.y2]="arrow.y"
                    [attr.stroke]="arrow.color" stroke-width="2"
                    [attr.marker-end]="'url(#ah-' + arrow.colorName + ')'"/>
              <text [attr.x]="(arrow.fromX + arrow.toX) / 2"
                    [attr.y]="arrow.y - 8"
                    text-anchor="middle" [attr.fill]="arrow.color"
                    class="method-label">{{ arrow.message.method_or_status }}</text>
            </g>
          }
        </svg>

        @if (selectedMessage(); as msg) {
          <div class="message-detail">
            <div class="detail-header">
              <span class="detail-method">{{ msg.method_or_status }}</span>
              <span class="detail-direction">{{ msg.direction }}</span>
              <span class="detail-time">{{ msg.timestamp }}</span>
            </div>
            <div class="detail-route">
              {{ msg.source }} &rarr; {{ msg.destination }}
            </div>
            @if (msg.raw_message) {
              <pre class="detail-raw">{{ msg.raw_message }}</pre>
            }
          </div>
        }
      } @else {
        <div class="no-data">No call ladder data available</div>
      }
    </div>
  `,
  styles: [`
    .ladder-container {
      overflow-x: auto;
      overflow-y: auto;
      max-height: calc(100vh - 200px);
      background: #0f0f23;
      border-radius: 8px;
      padding: 16px;
    }

    .ladder-svg {
      display: block;
      min-width: 600px;
    }

    .participant-label {
      fill: #fff;
      font-size: 13px;
      font-weight: 600;
    }

    .participant-line {
      stroke: rgba(255, 255, 255, 0.15);
      stroke-width: 1;
      stroke-dasharray: 4 2;
    }

    .timestamp-label {
      fill: rgba(255, 255, 255, 0.4);
      font-size: 10px;
      font-family: monospace;
    }

    .method-label {
      font-size: 12px;
      font-weight: 500;
      font-family: monospace;
    }

    .message-group {
      cursor: pointer;
    }

    .message-group:hover line {
      stroke-width: 3;
    }

    .message-group.selected line {
      stroke-width: 3;
    }

    .no-data {
      color: rgba(255, 255, 255, 0.5);
      text-align: center;
      padding: 48px;
      font-size: 16px;
    }

    .message-detail {
      margin-top: 16px;
      background: #16213e;
      border-radius: 8px;
      padding: 16px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .detail-header {
      display: flex;
      gap: 16px;
      align-items: center;
      margin-bottom: 8px;
    }

    .detail-method {
      font-weight: 600;
      color: #7c4dff;
      font-size: 15px;
    }

    .detail-direction {
      color: rgba(255, 255, 255, 0.5);
      font-size: 12px;
      text-transform: uppercase;
      background: rgba(255, 255, 255, 0.05);
      padding: 2px 8px;
      border-radius: 4px;
    }

    .detail-time {
      color: rgba(255, 255, 255, 0.4);
      font-size: 12px;
      font-family: monospace;
    }

    .detail-route {
      color: rgba(255, 255, 255, 0.7);
      font-size: 13px;
      margin-bottom: 12px;
    }

    .detail-raw {
      background: #0a0a1a;
      color: #a5d6a7;
      padding: 12px;
      border-radius: 4px;
      font-size: 11px;
      line-height: 1.5;
      max-height: 300px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
  `],
})
export class CallLadderDiagramComponent {
  readonly ladder = input<CallLadder | null>(null);
  readonly messageSelected = output<SipMessage>();

  readonly selectedMessage = signal<SipMessage | null>(null);

  private readonly participantSpacing = 200;
  private readonly leftMargin = 100;
  private readonly rowHeight = 50;
  private readonly topOffset = 60;

  readonly svgWidth = computed(() => {
    const ld = this.ladder();
    if (!ld) return 600;
    return this.leftMargin + ld.participants.length * this.participantSpacing + 50;
  });

  readonly svgHeight = computed(() => {
    const ld = this.ladder();
    if (!ld) return 200;
    return this.topOffset + ld.messages.length * this.rowHeight + 40;
  });

  readonly arrows = computed<ArrowLayout[]>(() => {
    const ld = this.ladder();
    if (!ld) return [];

    return ld.messages.map((msg, idx) => {
      const fromIdx = ld.participants.indexOf(msg.source);
      const toIdx = ld.participants.indexOf(msg.destination);
      const fromX = this.participantX(fromIdx >= 0 ? fromIdx : 0);
      const toX = this.participantX(toIdx >= 0 ? toIdx : ld.participants.length - 1);
      const y = this.topOffset + idx * this.rowHeight;
      const color = this.getArrowColor(msg.method_or_status);

      return {
        message: msg,
        y,
        fromX,
        toX,
        color,
        colorName: this.getColorName(color),
        index: idx,
      };
    });
  });

  participantX(index: number): number {
    return this.leftMargin + index * this.participantSpacing + this.participantSpacing / 2;
  }

  onArrowClick(msg: SipMessage): void {
    const current = this.selectedMessage();
    const next = current === msg ? null : msg;
    this.selectedMessage.set(next);
    this.messageSelected.emit(msg);
  }

  formatTime(timestamp: string): string {
    try {
      const d = new Date(timestamp);
      return d.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return timestamp;
    }
  }

  private getColorName(color: string): string {
    switch (color) {
      case '#9e9e9e': return 'gray';
      case '#4caf50': return 'green';
      case '#f44336': return 'red';
      default: return 'blue';
    }
  }

  private getArrowColor(methodOrStatus: string): string {
    const s = methodOrStatus.trim();
    if (/^1\d{2}/.test(s)) return '#9e9e9e';
    if (/^2\d{2}/.test(s)) return '#4caf50';
    if (/^[3-6]\d{2}/.test(s)) return '#f44336';
    return '#64b5f6';
  }
}
