import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { AuthorizationRecord, ExecutionJob, ExecutionProvenance, RegisteredLocalProject, RepositoryAsset, RepositoryQuota, RepositoryRetention, ScopeRevisionRecord } from '../types';

type Props = { organizationId: string; engagementId: string; scopes: ScopeRevisionRecord[]; authorizations: AuthorizationRecord[]; onUnauthorized: () => void };
const panel: React.CSSProperties = { padding: 16, border: '1px solid #29404d', borderRadius: 8, background: '#0b1824', display: 'grid', gap: 10 };

export function RepositoryAssessmentWorkspace({ organizationId, engagementId, scopes, authorizations, onUnauthorized }: Props) {
  const [projects, setProjects] = useState<RegisteredLocalProject[]>([]);
  const [assets, setAssets] = useState<RepositoryAsset[]>([]);
  const [quota, setQuota] = useState<RepositoryQuota | null>(null);
  const [retention, setRetention] = useState<RepositoryRetention[]>([]);
  const [statement, setStatement] = useState<{ version: string; text: string } | null>(null);
  const [jobs, setJobs] = useState<ExecutionJob[]>([]);
  const [provenance, setProvenance] = useState<ExecutionProvenance | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    try {
      const [p, a, q, r, t, j] = await Promise.all([
        api.repositoryProjects(organizationId, engagementId), api.repositoryAssets(organizationId, engagementId),
        api.repositoryQuota(organizationId, engagementId), api.repositoryRetention(organizationId, engagementId), api.repositoryAttestationText(organizationId, engagementId),
        api.governedExecutions(organizationId, engagementId),
      ]);
      setProjects(p.items); setAssets(a.items); setQuota(q); setRetention(r.items); setStatement(t); setJobs(j.items.filter((item) => item.asset_type === 'repository'));
      setError('');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Repository assessment data could not be loaded.');
    }
  }, [organizationId, engagementId, onUnauthorized]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!jobs.some((job) => ['queued', 'claimed', 'running'].includes(job.status))) return;
    const timer = window.setInterval(() => {
      void api.governedExecutions(organizationId, engagementId).then((result) => setJobs(result.items.filter((item) => item.asset_type === 'repository'))).catch(() => undefined);
    }, 1500);
    return () => window.clearInterval(timer);
  }, [jobs, organizationId, engagementId]);
  async function run(action: () => Promise<unknown>) {
    setBusy(true); setError('');
    try { await action(); await load(); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Repository operation was rejected.'); }
    finally { setBusy(false); }
  }
  const published = scopes.filter((item) => item.status === 'published');
  return <section style={{ display: 'grid', gap: 12, marginTop: 16 }} aria-label="Governed repository assessment">
    <div style={panel}>
      <h3>Local repository assessment</h3>
      <p>Only operator-registered local projects are available. The server snapshots source content and runs the built-in offline code rules against that immutable snapshot; no repository scripts or dependencies are executed.</p>
      {error && <div role="alert" className="alert-error">{error}</div>}
      {quota && <p>Snapshot storage: {quota.used_bytes.toLocaleString()} used, {quota.reserved_bytes.toLocaleString()} reserved of {quota.organization_limit_bytes.toLocaleString()} bytes. Per snapshot limit: {quota.snapshot_limit_bytes.toLocaleString()} bytes.</p>}
      <form onSubmit={(event) => { event.preventDefault(); const data = new FormData(event.currentTarget); void run(() => api.createRepositoryAsset(organizationId, engagementId, { description: String(data.get('description') ?? '') || undefined })); event.currentTarget.reset(); }}>
        <label>Notes <input name="description" maxLength={2000}/></label> <button disabled={busy}>Create repository asset</button>
      </form>
      {assets.map((asset) => <article key={asset.id} style={{ borderTop: '1px solid #29404d', paddingTop: 10 }}>
        <p>Repository asset <code>{asset.id}</code> · {asset.status}</p>
        {asset.binding_id ? <>
          <p>Snapshot: {asset.snapshot_status} · {asset.size_bytes?.toLocaleString()} bytes · SHA-256 <code>{asset.snapshot_sha256}</code> · manifest v{asset.manifest_version}</p>
          <p>Attestation: {asset.attestation_version} by <code>{asset.attested_at}</code> · scope <code>{asset.scope_revision_id}</code> · authorization <code>{asset.authorization_id}</code></p>
          <p>Retention: {retention.find((item) => item.snapshot_id === asset.snapshot_id)?.retention_state ?? (asset.delete_after ? `eligible after ${asset.delete_after}` : 'retained while engagement is open')}{asset.delete_after ? ` · ${asset.delete_after}` : ''}{asset.legal_hold ? ' · legal/investigation hold' : ''}</p>
          <button type="button" disabled={busy || asset.snapshot_status !== 'available'} onClick={() => void run(async () => { const job = await api.startRepositoryAssessment(organizationId, engagementId, { asset_id: asset.id, idempotency_key: crypto.randomUUID() }); setJobs((current) => [job, ...current.filter((item) => item.id !== job.id)]); })}>Start governed code assessment</button>
        </> : <form onSubmit={(event) => { event.preventDefault(); const data = new FormData(event.currentTarget); void run(() => api.bindRepositoryAsset(organizationId, engagementId, asset.id, { project_registry_id: String(data.get('project')), authorization_id: String(data.get('authorization')), scope_revision_id: String(data.get('scope')), attestation_text: statement?.text ?? '' })); }}>
          <label>Registered local project <select name="project" required>{projects.map((project) => <option key={project.project_registry_id} value={project.project_registry_id}>{project.display_label}</option>)}</select></label>
          <label>Published scope <select name="scope" required>{published.map((scope) => <option key={scope.id} value={scope.id}>Revision {scope.revision}</option>)}</select></label>
          <label>Authorization <select name="authorization" required>{authorizations.filter((item) => item.status === 'active').map((record) => <option key={record.id} value={record.id}>{record.authorization_reference} · scope {record.scope_revision_id}</option>)}</select></label>
          {statement && <fieldset><legend>Engagement lead attestation ({statement.version})</legend><p>{statement.text}</p><label><input type="checkbox" name="attest" required/> I make this attestation for this repository, authorization, and published scope revision.</label></fieldset>}
          <button disabled={busy || projects.length === 0 || published.length === 0 || !statement}>Create immutable snapshot and bind</button>
        </form>}
      </article>)}
      {assets.length === 0 && <p>No repository assets are registered for this engagement.</p>}
    </div>
    <div style={panel}><h4>Repository assessment jobs</h4><ul>{jobs.map((job) => <li key={job.id}>Snapshot-backed job <code>{job.id}</code> · {job.status}{job.error_code && ` · ${job.error_code}`}{job.scan_id && ` · scan ${job.scan_id}`}{job.cancellation_requested_at && ' · cancellation pending'}{['queued', 'claimed', 'running'].includes(job.status) && !job.cancellation_requested_at && <button type="button" disabled={busy} onClick={() => void run(() => api.cancelGovernedExecution(organizationId, engagementId, job.id))}>Cancel</button>}<button type="button" disabled={busy} onClick={() => void run(async () => { setProvenance(await api.governedExecutionProvenance(organizationId, engagementId, job.id)); })}>View provenance</button></li>)}</ul>{provenance && <pre aria-label="Repository execution provenance">{JSON.stringify(provenance.execution, null, 2)}{"\nResults: "}{provenance.results.map((item) => `${item.record_type}:${item.record_id}`).join(', ')}</pre>}</div>
  </section>;
}
