import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, map } from 'rxjs';
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
    return this.http.get<SystemStats>(`${this.baseUrl}/system/stats`);
  }

  getHealth(): Observable<HealthStatus> {
    return this.http.get<HealthStatus>(`${this.baseUrl}/system/health`);
  }

  getRegistrations(): Observable<Registration[]> {
    return this.http.get<any>(`${this.baseUrl}/registrations`).pipe(
      map(resp => {
        const regs = resp.registrations ?? resp;
        // Group flat registrations by AOR
        const byAor = new Map<string, Registration>();
        for (const r of regs) {
          if (!byAor.has(r.aor)) {
            byAor.set(r.aor, { aor: r.aor, contacts: [] });
          }
          byAor.get(r.aor)!.contacts.push({
            uri: r.contact ?? r.uri ?? '',
            expires: r.expires,
            source_address: r.source_address,
          });
        }
        return Array.from(byAor.values());
      })
    );
  }

  deleteRegistration(aor: string, contactUri: string): Observable<void> {
    const params = new HttpParams().set('contact', contactUri);
    return this.http.delete<void>(
      `${this.baseUrl}/registrations/${encodeURIComponent(aor)}`,
      { params },
    );
  }

  getDirectoryNumbers(): Observable<DirectoryNumber[]> {
    return this.http.get<any>(`${this.baseUrl}/directory`).pipe(
      map(resp => resp.directory_numbers ?? resp)
    );
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
    return this.http.get<any>(`${this.baseUrl}/calls`).pipe(
      map(resp => resp.calls ?? resp)
    );
  }

  getRecentCallIds(): Observable<string[]> {
    return this.http.get<string[]>(`${this.baseUrl}/calls/recent`);
  }

  getDialPlans(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/dialplans`).pipe(map(r => r.dial_plans ?? []));
  }
  getDialPlanEntries(planId: string): Observable<any> {
    return this.http.get<any>(`${this.baseUrl}/dialplans/${encodeURIComponent(planId)}/entries`);
  }
  addDialPlanEntry(planId: string, entry: any): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/dialplans/${encodeURIComponent(planId)}/entries`, entry);
  }
  deleteDialPlanEntry(planId: string, entryId: string): Observable<any> {
    return this.http.delete<any>(`${this.baseUrl}/dialplans/${encodeURIComponent(planId)}/entries/${encodeURIComponent(entryId)}`);
  }
  getTrunkGroups(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/trunkgroups`).pipe(map(r => r.trunk_groups ?? []));
  }
  addTrunkGroup(group: any): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/trunkgroups`, group);
  }
  deleteTrunkGroup(groupId: string): Observable<any> {
    return this.http.delete<any>(`${this.baseUrl}/trunkgroups/${encodeURIComponent(groupId)}`);
  }
  getTrunkGroup(groupId: string): Observable<any> {
    return this.http.get<any>(`${this.baseUrl}/trunkgroups/${encodeURIComponent(groupId)}`);
  }
  addTrunk(groupId: string, trunk: any): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/trunkgroups/${encodeURIComponent(groupId)}/trunks`, trunk);
  }
  updateTrunk(groupId: string, trunkId: string, trunk: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/trunkgroups/${encodeURIComponent(groupId)}/trunks/${encodeURIComponent(trunkId)}`, trunk);
  }
  deleteTrunk(groupId: string, trunkId: string): Observable<any> {
    return this.http.delete<any>(`${this.baseUrl}/trunkgroups/${encodeURIComponent(groupId)}/trunks/${encodeURIComponent(trunkId)}`);
  }

  // Users
  getUsers(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/users`).pipe(map(r => r.users ?? []));
  }
  createUser(user: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/users`, user);
  }
  updateUser(id: string, user: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/users/${encodeURIComponent(id)}`, user);
  }
  deleteUser(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/users/${encodeURIComponent(id)}`);
  }

  // Phones
  getPhones(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/phones`).pipe(map(r => r.phones ?? []));
  }
  createPhone(phone: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/phones`, phone);
  }
  getPhone(id: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/phones/${encodeURIComponent(id)}`);
  }
  updatePhone(id: string, phone: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/phones/${encodeURIComponent(id)}`, phone);
  }
  deletePhone(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/phones/${encodeURIComponent(id)}`);
  }
  rebootPhone(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/phones/${encodeURIComponent(id)}/reboot`, {});
  }
  getPhoneConfig(id: string): Observable<string> {
    return this.http.get(`${this.baseUrl}/phones/${encodeURIComponent(id)}/config`, { responseType: 'text' }) as Observable<string>;
  }

  // Partitions
  getPartitions(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/partitions`).pipe(map(r => r.partitions ?? []));
  }
  createPartition(p: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/partitions`, p);
  }
  deletePartition(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/partitions/${encodeURIComponent(id)}`);
  }

  // Calling Search Spaces
  getCss(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/css`).pipe(map(r => r.calling_search_spaces ?? []));
  }
  createCss(css: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/css`, css);
  }
  deleteCss(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/css/${encodeURIComponent(id)}`);
  }
  updateCss(id: string, css: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/css/${encodeURIComponent(id)}`, css);
  }

  // Route Patterns
  getRoutePatterns(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/routepatterns`).pipe(map(r => r.route_patterns ?? []));
  }
  createRoutePattern(rp: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/routepatterns`, rp);
  }
  updateRoutePattern(id: string, rp: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/routepatterns/${encodeURIComponent(id)}`, rp);
  }
  deleteRoutePattern(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/routepatterns/${encodeURIComponent(id)}`);
  }

  // Route Lists
  getRouteLists(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/routelists`).pipe(map(r => r.route_lists ?? []));
  }
  createRouteList(rl: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/routelists`, rl);
  }
  deleteRouteList(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/routelists/${encodeURIComponent(id)}`);
  }
  updateRouteList(id: string, rl: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/routelists/${encodeURIComponent(id)}`, rl);
  }
  updateTrunkGroup(id: string, group: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/trunkgroups/${encodeURIComponent(id)}`, group);
  }

  // Trunk Registration
  getTrunkRegistrationStatus(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/trunk-registration`).pipe(
      map(r => r.trunk_registrations ?? r.registrations ?? [])
    );
  }
  triggerTrunkRegister(trunkId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/trunk-registration/${encodeURIComponent(trunkId)}/register`, {});
  }

  // Trunk Health (OPTIONS ping)
  getTrunkHealth(): Observable<any[]> {
    return this.http.get<any>(`${this.baseUrl}/trunk-health`).pipe(
      map(r => r.trunk_health ?? r.trunks ?? [])
    );
  }
}
