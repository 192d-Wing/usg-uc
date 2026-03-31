import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  SystemStats,
  HealthStatus,
  Registration,
  DirectoryNumber,
  CdrRecord,
  CdrFilter,
  CallLadder,
  PaginatedResponse,
} from '../models/sbc.models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1';

  getStats(): Observable<SystemStats> {
    return this.http.get<SystemStats>(`${this.baseUrl}/stats`);
  }

  getHealth(): Observable<HealthStatus> {
    return this.http.get<HealthStatus>(`${this.baseUrl}/health`);
  }

  getRegistrations(): Observable<Registration[]> {
    return this.http.get<Registration[]>(`${this.baseUrl}/registrations`);
  }

  deleteRegistration(aor: string, contactUri: string): Observable<void> {
    const params = new HttpParams().set('contact', contactUri);
    return this.http.delete<void>(
      `${this.baseUrl}/registrations/${encodeURIComponent(aor)}`,
      { params },
    );
  }

  getDirectoryNumbers(): Observable<DirectoryNumber[]> {
    return this.http.get<DirectoryNumber[]>(`${this.baseUrl}/directory`);
  }

  addDirectoryNumber(dn: DirectoryNumber): Observable<DirectoryNumber> {
    return this.http.post<DirectoryNumber>(`${this.baseUrl}/directory`, dn);
  }

  updateDirectoryNumber(did: string, dn: Partial<DirectoryNumber>): Observable<DirectoryNumber> {
    return this.http.put<DirectoryNumber>(
      `${this.baseUrl}/directory/${encodeURIComponent(did)}`,
      dn,
    );
  }

  deleteDirectoryNumber(did: string): Observable<void> {
    return this.http.delete<void>(
      `${this.baseUrl}/directory/${encodeURIComponent(did)}`,
    );
  }

  getCdrs(filter: CdrFilter): Observable<PaginatedResponse<CdrRecord>> {
    let params = new HttpParams();
    if (filter.start_date) params = params.set('start_date', filter.start_date);
    if (filter.end_date) params = params.set('end_date', filter.end_date);
    if (filter.caller) params = params.set('caller', filter.caller);
    if (filter.callee) params = params.set('callee', filter.callee);
    if (filter.status) params = params.set('status', filter.status);
    if (filter.page != null) params = params.set('page', filter.page.toString());
    if (filter.page_size != null) params = params.set('page_size', filter.page_size.toString());
    return this.http.get<PaginatedResponse<CdrRecord>>(`${this.baseUrl}/cdrs`, { params });
  }

  getCallLadder(callId: string): Observable<CallLadder> {
    return this.http.get<CallLadder>(
      `${this.baseUrl}/calls/${encodeURIComponent(callId)}/ladder`,
    );
  }

  getActiveCalls(): Observable<CdrRecord[]> {
    return this.http.get<CdrRecord[]>(`${this.baseUrl}/calls/active`);
  }

  getRecentCallIds(): Observable<string[]> {
    return this.http.get<string[]>(`${this.baseUrl}/calls/recent`);
  }
}
