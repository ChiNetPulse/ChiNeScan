import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { ExecutionJob, ExecutionProvenance, LogEvidence, LogSource } from '../types';

export function EngagementLogEvidenceWorkspace({
  organizationId, engagementId, onUnauthorized,
}: { organizationId: string; engagementId: string; onUnauthorized: () => void }) {
  const [sources, setSources] = useState<LogSource[]>([]);
  const [evidence, setEvidence] = useState<LogEvidence[]>([]);
  const [jobs, setJobs] = useState<ExecutionJob[]>([]);
  const [provenance, setProvenance] = useState<ExecutionProvenance | null>(null);
  const [sourceId, setSourceId] = useState('');
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    try {
      const [sourceResult, evidenceResult, jobResult] = await Promise.all([
        api.logEvidenceSources(organizationId, engagementId), api.logEvidence(organizationId, engagementId),
        api.governedExecutions(organizationId, engagementId),
      ]);
      setSources(sourceResult);
      setEvidence(evidenceResult.items);
      setJobs(jobResult.items.filter((item) => item.technique === 'log_analysis'));
      setSourceId((current) => sourceResult.some((item) => item.source_id === current)
        ? current : sourceResult[0]?.source_id ?? '');
      setError('');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load engagement log evidence.');
    }
  }, [organizationId, engagementId, onUnauthorized]);

  useEffect(() => { void refresh(); }, [refresh]);

  async function register(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError('');
    try {
      await api.registerLogEvidence(organizationId, engagementId, { source_id: sourceId, label });
      setLabel('');
      await refresh();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Evidence registration failed.');
    } finally { setBusy(false); }
  }

  async function start(assetId: string) {
    setBusy(true); setError('');
    try {
      await api.startGovernedLogAnalysis(organizationId, engagementId, assetId, crypto.randomUUID());
      await refresh();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Governed analysis was not admitted.');
    } finally { setBusy(false); }
  }

  async function manageEvidence(action: () => Promise<unknown>) {
    setBusy(true); setError('');
    try { await action(); await refresh(); }
    catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Evidence operation was rejected.');
    } finally { setBusy(false); }
  }

  return <section style={{ display: 'grid', gap: 12, marginTop: 18 }} aria-label="Governed log evidence">
    <div style={{ padding: 18, border: '1px solid #29404d', borderRadius: 8, background: '#0b1824' }}>
      <h2>Governed log evidence</h2>
      <p>Register a configured local source into an immutable, private snapshot. Analysis runs only after current engagement scope and authorization checks pass.</p>
      {error && <div className="alert-error" role="alert">{error}</div>}
      <form onSubmit={(event) => void register(event)} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'end' }}>
        <label>Configured source <select required value={sourceId} onChange={(event) => setSourceId(event.target.value)}>
          <option value="">Select source</option>{sources.map((item) => <option key={item.source_id} value={item.source_id}>{item.display_name}</option>)}
        </select></label>
        <label>Evidence label <input required maxLength={120} value={label} onChange={(event) => setLabel(event.target.value)} /></label>
        <button disabled={busy || !sourceId || !label.trim()}>Register snapshot</button>
      </form>
      {!sources.length && <p>No safe configured log sources are available.</p>}
      <h3>Registered snapshots</h3>
      {!evidence.length ? <p>No log evidence registered for this engagement.</p> : <ul>{evidence.map((item) => <li key={item.snapshot_id}>
        {item.label} · {item.source_format} · {item.file_count} file(s) · {item.size_bytes} bytes · SHA-256 {item.sha256} · {item.status}
        {item.legal_hold ? ' · held' : ''}
        {` · ${item.retention ?? 'retained until explicitly deleted'}`}
        {item.status === 'available' && <button type="button" disabled={busy} onClick={() => void start(item.asset_id)}>Run governed analysis</button>}
        {item.status === 'available' && <button type="button" disabled={busy || Boolean(item.legal_hold)} onClick={() => {
          const reason = window.prompt('Reason for retaining this evidence under legal/investigation hold');
          if (reason?.trim()) void manageEvidence(() => api.holdLogEvidence(organizationId, engagementId, item.asset_id, reason));
        }}>Place hold</button>}
        {item.deletion_eligible && <button type="button" disabled={busy} onClick={() => {
          if (window.confirm('Delete the managed evidence content? Provenance and audit metadata will remain.')) {
            void manageEvidence(() => api.deleteLogEvidence(organizationId, engagementId, item.asset_id));
          }
        }}>Delete evidence</button>}
      </li>)}</ul>}
      <h3>Governed analysis jobs</h3>
      {!jobs.length ? <p>No governed log analysis jobs.</p> : <ul>{jobs.map((job) => <li key={job.id}>
        {job.status} · {job.scan_id ? `result ${job.scan_id}` : 'result pending'}{job.error_code ? ` · ${job.error_code}` : ''}
        {['queued', 'claimed', 'running'].includes(job.status) && !job.cancellation_requested_at && <button type="button" disabled={busy} onClick={() => void manageEvidence(() => api.cancelGovernedExecution(organizationId, engagementId, job.id))}>Cancel</button>}
        <button type="button" disabled={busy} onClick={() => void api.governedExecutionProvenance(organizationId, engagementId, job.id).then(setProvenance).catch((reason) => setError(reason instanceof Error ? reason.message : 'Provenance unavailable.'))}>View provenance</button>
      </li>)}</ul>}
      {provenance && <pre aria-label="Log execution provenance">{JSON.stringify(provenance, null, 2)}</pre>}
      <p>Original evidence is not returned through this interface. The standalone local log workflow remains separate.</p>
    </div>
  </section>;
}
