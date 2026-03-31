import { Injectable, OnDestroy } from '@angular/core';
import { Observable, Subject, timer, EMPTY } from 'rxjs';
import { filter, switchMap, retry } from 'rxjs/operators';
import { webSocket, WebSocketSubject } from 'rxjs/webSocket';
import { WebSocketEvent } from '../models/sbc.models';

@Injectable({ providedIn: 'root' })
export class WebSocketService implements OnDestroy {
  private socket$: WebSocketSubject<WebSocketEvent> | null = null;
  private readonly events$ = new Subject<WebSocketEvent>();
  private readonly reconnectInterval = 3000;
  private reconnectSub: { unsubscribe(): void } | null = null;

  connect(): void {
    if (this.socket$) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;

    this.socket$ = webSocket<WebSocketEvent>({
      url: wsUrl,
      openObserver: {
        next: () => {
          console.log('[WebSocket] Connected');
          if (this.reconnectSub) {
            this.reconnectSub.unsubscribe();
            this.reconnectSub = null;
          }
        },
      },
      closeObserver: {
        next: () => {
          console.log('[WebSocket] Disconnected, scheduling reconnect');
          this.socket$ = null;
          this.scheduleReconnect();
        },
      },
    });

    this.socket$.subscribe({
      next: (event) => this.events$.next(event),
      error: (err) => {
        console.error('[WebSocket] Error:', err);
        this.socket$ = null;
        this.scheduleReconnect();
      },
    });
  }

  disconnect(): void {
    if (this.reconnectSub) {
      this.reconnectSub.unsubscribe();
      this.reconnectSub = null;
    }
    if (this.socket$) {
      this.socket$.complete();
      this.socket$ = null;
    }
  }

  on(eventType: WebSocketEvent['type']): Observable<WebSocketEvent> {
    return this.events$.pipe(filter((e) => e.type === eventType));
  }

  get allEvents$(): Observable<WebSocketEvent> {
    return this.events$.asObservable();
  }

  private scheduleReconnect(): void {
    if (this.reconnectSub) return;
    this.reconnectSub = timer(this.reconnectInterval)
      .pipe(
        switchMap(() => {
          this.connect();
          return EMPTY;
        }),
        retry(),
      )
      .subscribe();
  }

  ngOnDestroy(): void {
    this.disconnect();
    this.events$.complete();
  }
}
