import { useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { Phase6Hold, Phase6Policy, Phase6Status } from '../types';

export function Phase6GovernanceWorkspace({ organizationId, onUnauthorized }: { organizationId: string; onUnauthorized: () => void }) {
  const [status, setStatus] = useState<Phase6Status | null>(null);
  const [policies, setPolicies] = useState<Phase6Policy[]>([]);
  const [holds, setHolds] = useState<Phase6Hold[]>([]);
  const [days, setDays] = useState('365');
  const [reason, setReason] = useState('');
  const [records, setRecords] = useState('evidence:');
  const [message, setMessage] = useState('');

  const reload = async () => {
    try {
      const [nextStatus, nextPolicies, nextHolds] = await Promise.all([
        api.phase6Status(organizationId), api.phase6Policies(organizationId), api.phase6Holds(organizationId),
      ]);
      setStatus(nextStatus); setPolicies(nextPolicies.items); setHolds(nextHolds.items);
    } catch (error) { if (error instanceof UnauthorizedError) onUnauthorized(); else setMessage(error instanceof Error ? error.message : 'Unable to load Phase 6 governance.'); }
  };
  useEffect(() => { void reload(); }, [organizationId]);

  const createPolicy = async (event: React.FormEvent) => {
    event.preventDefault(); setMessage('');
    try { await api.createPhase6Policy(organizationId, { retention_days: Number(days) }); setMessage('Retention policy created.'); await reload(); }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Policy creation failed.'); }
  };
  const createHold = async (event: React.FormEvent) => {
    event.preventDefault(); setMessage('');
    const parsed = records.split(',').map((value) => value.trim().split(':', 2) as [string, string]).filter((value) => value[0] && value[1]);
    try { await api.createPhase6Hold(organizationId, { reason, records: parsed }); setReason(''); setMessage('Legal hold created.'); await reload(); }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Hold creation failed.'); }
  };
  return <div className="overview-grid" aria-label="Phase 6 evidence governance">
    <section className="panel">
      <div className="panel-heading"><div><h2>Execution isolation</h2><p>Backend-verified controls only.</p></div><span className={`status-badge module-${status?.hardened_enforced ? 'ready' : 'planned'}`}>{status?.hardened_enforced ? 'hardened' : 'blocked'}</span></div>
      <p>Platform: <strong>{status?.platform ?? 'Loading…'}</strong> · Profile: <strong>{status?.profile ?? '—'}</strong></p>
      <h3>Enforced controls</h3><p>{status?.enforced_controls.join(', ') || 'None verified'}</p>
      <h3>Unavailable controls</h3><p>{status?.unavailable_controls.join(', ') || 'None'}</p>
    </section>
    <section className="panel">
      <div className="panel-heading"><div><h2>Retention policies</h2><p>Organization-scoped policy versions.</p></div></div>
      <form onSubmit={createPolicy}><label htmlFor="phase6-days">Retention days</label><input id="phase6-days" type="number" min="1" max="36500" value={days} onChange={(event) => setDays(event.target.value)} /><button className="secondary-button">Create policy</button></form>
      <ul>{policies.map((policy) => <li key={policy.id}>{policy.retention_days} days · {policy.status}</li>)}</ul>
    </section>
    <section className="panel">
      <div className="panel-heading"><div><h2>Legal holds</h2><p>Active holds block routine evidence deletion.</p></div></div>
      <form onSubmit={createHold}><label htmlFor="phase6-reason">Reason</label><input id="phase6-reason" required maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} /><label htmlFor="phase6-records">Records (type:id, comma separated)</label><input id="phase6-records" required value={records} onChange={(event) => setRecords(event.target.value)} /><button className="secondary-button">Create hold</button></form>
      <ul>{holds.map((hold) => <li key={hold.id}>{hold.reason} · {hold.status} · {hold.record_count} records {hold.status === 'active' && <button className="text-button" onClick={async () => { await api.releasePhase6Hold(organizationId, hold.id); await reload(); }}>Release</button>}</li>)}</ul>
    </section>
    {message && <p role="status" className="status-banner">{message}</p>}
  </div>;
}
