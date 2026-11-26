import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { ApprovalRecord, AuthorizationRecord, EngagementAsset, ExecutionJob, ExecutionProvenance, ScopeRevisionRecord } from '../types';
import { RepositoryAssessmentWorkspace } from './RepositoryAssessmentWorkspace';

type Props = { organizationId: string; engagementId: string; onUnauthorized: () => void };
const panel: React.CSSProperties = { padding: 18, border: '1px solid #29404d', borderRadius: 8, background: '#0b1824', display: 'grid', gap: 12 };
const form: React.CSSProperties = { display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'end' };

export function EngagementSecurityWorkspace({ organizationId, engagementId, onUnauthorized }: Props) {
  const [assets, setAssets] = useState<EngagementAsset[]>([]);
  const [scopes, setScopes] = useState<ScopeRevisionRecord[]>([]);
  const [authorizations, setAuthorizations] = useState<AuthorizationRecord[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [executionJobs, setExecutionJobs] = useState<ExecutionJob[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [cancellationPendingId, setCancellationPendingId] = useState<string | null>(null);
  const [cancellationMessage, setCancellationMessage] = useState('');
  const [provenanceByJob, setProvenanceByJob] = useState<Record<string, ExecutionProvenance>>({});
  const load = useCallback(async () => {
    try {
      const [a, s, z, p, jobs] = await Promise.all([
        api.engagementAssets(organizationId, engagementId), api.scopeRevisions(organizationId, engagementId),
        api.authorizationRecords(organizationId, engagementId), api.approvalRequests(organizationId, engagementId),
        api.governedExecutions(organizationId, engagementId),
      ]);
      setAssets(a.items); setScopes(s.items); setAuthorizations(z.items); setApprovals(p.items); setExecutionJobs(jobs.items); setError('');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load engagement security records.');
    }
  }, [organizationId, engagementId, onUnauthorized]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!executionJobs.some((job) => ['queued', 'claimed', 'running'].includes(job.status))) return;
    const timer = window.setInterval(() => {
      void Promise.all(executionJobs.filter((job) => ['queued', 'claimed', 'running'].includes(job.status)).map(async (job) => {
        try { return await api.governedExecution(organizationId, engagementId, job.id); }
        catch { return null; }
      })).then((updates) => setExecutionJobs((current) => {
        const byId = new Map(updates.filter((item): item is ExecutionJob => item !== null).map((item) => [item.id, item]));
        return current.map((item) => byId.get(item.id) ?? item);
      }));
    }, 1500);
    return () => window.clearInterval(timer);
  }, [executionJobs, organizationId, engagementId]);
  async function submit(event: React.FormEvent<HTMLFormElement>, action: (data: FormData) => Promise<unknown>) {
    event.preventDefault(); setBusy(true); setError(''); const element = event.currentTarget;
    try { await action(new FormData(element)); element.reset(); await load(); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'The request was rejected.'); }
    finally { setBusy(false); }
  }
  const latestScope = scopes.find((item) => item.status === 'published');
  const activeAssets = assets.filter((item) => item.status === 'active');
  const activeAuthorization = authorizations.find((item) => item.status === 'active' && item.scope_revision_id === latestScope?.id && Date.parse(item.effective_at) <= Date.now() && Date.parse(item.expires_at) > Date.now());
  const [policyResult, setPolicyResult] = useState<Record<string, unknown> | null>(null);
  async function startDomainAssessment(asset: EngagementAsset) {
    setBusy(true); setError('');
    try {
      const job = await api.startGovernedDomainAssessment(organizationId, engagementId, {
        asset_id: asset.id, idempotency_key: crypto.randomUUID(),
      });
      setExecutionJobs((current) => [job, ...current.filter((item) => item.id !== job.id)]);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'The governed assessment was rejected.');
    } finally { setBusy(false); }
  }
  async function cancelExecution(job: ExecutionJob) {
    if (cancellationPendingId || !['queued', 'claimed', 'running'].includes(job.status) || job.cancellation_requested_at) return;
    setCancellationPendingId(job.id); setCancellationMessage('Cancellation request is being processed.'); setError('');
    try {
      const updated = await api.cancelGovernedExecution(organizationId, engagementId, job.id);
      setExecutionJobs((current) => current.map((item) => item.id === updated.id ? updated : item));
      setCancellationMessage(updated.status === 'cancelled' ? 'Execution cancelled.' : 'Cancellation requested; the worker will stop at its next safe checkpoint.');
      await load();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      await load();
      if (!(reason instanceof UnauthorizedError)) setError(reason instanceof Error ? reason.message : 'Cancellation request was rejected.');
    } finally { setCancellationPendingId(null); }
  }
  async function loadProvenance(job: ExecutionJob) {
    setError('');
    try {
      const result = await api.governedExecutionProvenance(organizationId, engagementId, job.id);
      setProvenanceByJob((current) => ({ ...current, [job.id]: result }));
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load execution provenance.');
    }
  }
  return <section aria-label="Engagement security controls" style={{ display: 'grid', gap: 12, marginTop: 18 }}>
    <h2>Authorized assessment foundation</h2>
    <p>These records define policy only. Evaluating policy does not start a scan or contact the target.</p>
    <RepositoryAssessmentWorkspace organizationId={organizationId} engagementId={engagementId} scopes={scopes} authorizations={authorizations} onUnauthorized={onUnauthorized}/>
    {error && <div role="alert" className="alert-error">{error}</div>}
    {!activeAuthorization && <p role="status">No current authorization covers the latest published scope. Policy decisions deny governed assessment actions.</p>}
    <div style={panel}><h3>Assets</h3><ul>{assets.map((item) => <li key={item.id}>{item.asset_type}: <code>{item.target}</code> · {item.status}{item.asset_type === 'domain' && item.status === 'active' && <button type="button" disabled={busy} onClick={() => void startDomainAssessment(item)}>Start governed domain posture assessment</button>}{<button type="button" disabled={busy} onClick={async () => { setBusy(true); try { await api.updateEngagementAsset(organizationId, engagementId, item.id, { status: item.status === 'active' ? 'inactive' : 'active' }); await load(); } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Could not update asset.'); } finally { setBusy(false); } }}>{item.status === 'active' ? 'Deactivate' : 'Reactivate'}</button>}</li>)}</ul>
      <form style={form} onSubmit={(e) => void submit(e, (data) => api.createEngagementAsset(organizationId, engagementId, { asset_type: String(data.get('asset_type')), target: String(data.get('target')), description: String(data.get('description') ?? '') }))}>
        <label>Type <select name="asset_type"><option>domain</option><option>ip</option><option>cidr</option><option>url</option></select></label><label>Target <input name="target" required maxLength={2048}/></label><label>Notes <input name="description" maxLength={2000}/></label><button disabled={busy}>Add asset</button>
      </form>
    </div>
    <div style={panel}><h3>Scope revisions</h3><ul>{scopes.map((revision) => <li key={revision.id}>Revision {revision.revision} · {revision.status} · {revision.change_summary} <ul>{revision.rules.map((rule, index) => <li key={`${revision.id}-${index}`}>{rule.effect === 'exclude' ? 'Excluded' : 'Included'} {rule.asset_type_snapshot}: <code>{rule.target_snapshot}</code> · {rule.match_mode} · {rule.techniques.join(', ') || 'all techniques'}</li>)}</ul>{revision.status === 'draft' && <button disabled={busy} onClick={async () => { setBusy(true); try { await api.publishScopeRevision(organizationId, engagementId, revision.id); await load(); } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Could not publish scope.'); } finally { setBusy(false); } }}>Publish</button>}</li>)}</ul>
      <form style={form} onSubmit={(e) => void submit(e, (data) => api.createScopeRevision(organizationId, engagementId, { change_summary: String(data.get('summary')), rules: [{ asset_id: String(data.get('asset_id')), effect: String(data.get('effect')), match_mode: String(data.get('match_mode')), techniques: String(data.get('techniques')).split(',').map((value) => value.trim()).filter(Boolean) }] }))}>
        <label>Change summary <input name="summary" required maxLength={2000}/></label><label>Asset <select name="asset_id" required>{activeAssets.map((asset) => <option key={asset.id} value={asset.id}>{asset.asset_type}: {asset.target}</option>)}</select></label><label>Effect <select name="effect"><option value="include">Include</option><option value="exclude">Exclude</option></select></label><label>Match <select name="match_mode"><option value="exact">Exact</option><option value="subdomains">Domain and subdomains</option><option value="network">CIDR network</option><option value="url_prefix">URL path prefix</option></select></label><label>Permitted techniques (comma separated) <input name="techniques" defaultValue="dns_metadata,http_metadata,service_fingerprint"/></label><button disabled={busy || activeAssets.length === 0}>Create draft</button>
      </form>
      {!latestScope && <p role="status">No published scope. Policy decisions will deny assessment actions.</p>}
    </div>
    <div style={panel}><h3>Authorization records</h3><ul>{authorizations.map((record) => <li key={record.id}>{record.authorization_reference} · {record.status} · expires {record.expires_at}{record.document && <> · <a href={`/api/organizations/${encodeURIComponent(organizationId)}/engagements/${encodeURIComponent(engagementId)}/authorizations/${encodeURIComponent(record.id)}/document`}>Private document ({record.document.filename})</a></>}</li>)}</ul>
      <form style={form} onSubmit={(e) => void submit(e, (data) => api.createAuthorizationRecord(organizationId, engagementId, { scope_revision_id: String(data.get('scope_revision_id')), authorization_reference: String(data.get('reference')), authorizing_party: String(data.get('party')), permitted_techniques: String(data.get('techniques')).split(',').map((value) => value.trim()).filter(Boolean), effective_at: new Date(String(data.get('effective'))).toISOString(), expires_at: new Date(String(data.get('expires'))).toISOString() }))}>
        <label>Published scope <select name="scope_revision_id" required>{scopes.filter((item) => item.status === 'published').map((item) => <option key={item.id} value={item.id}>Revision {item.revision}</option>)}</select></label><label>Reference <input name="reference" required maxLength={160}/></label><label>Authorizing party <input name="party" required maxLength={200}/></label><label>Techniques <input name="techniques" defaultValue="dns_metadata,http_metadata,service_fingerprint"/></label><label>Effective <input name="effective" type="datetime-local" required/></label><label>Expires <input name="expires" type="datetime-local" required/></label><button disabled={busy || !latestScope}>Record authorization</button>
      </form><p>Authorization documents are private; this view exposes metadata and uses the authenticated download route.</p>
    </div>
    <div style={panel}><h3>Sensitive-action approvals</h3><ul>{approvals.map((approval) => <li key={approval.id}>{approval.technique} · <code>{approval.target}</code> · {approval.decision} · expires {approval.expires_at}{approval.decision === 'pending' && <><button disabled={busy} onClick={async () => { setBusy(true); try { await api.decideApprovalRequest(organizationId, engagementId, approval.id, 'approved'); await load(); } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Could not approve request.'); } finally { setBusy(false); } }}>Approve</button><button disabled={busy} onClick={async () => { setBusy(true); try { await api.decideApprovalRequest(organizationId, engagementId, approval.id, 'denied'); await load(); } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Could not deny request.'); } finally { setBusy(false); } }}>Deny</button></>}</li>)}</ul>
      <form style={form} onSubmit={(e) => void submit(e, (data) => api.createApprovalRequest(organizationId, engagementId, { asset_type: String(data.get('asset_type')), target: String(data.get('target')), technique: String(data.get('technique')) }))}>
        <label>Asset type <select name="asset_type"><option>domain</option><option>ip</option><option>cidr</option><option>url</option></select></label><label>Exact target <input name="target" required maxLength={2048}/></label><label>Sensitive technique <select name="technique"><option>exploit_verification</option><option>credential_testing</option><option>destructive_test</option></select></label><button disabled={busy || activeAssets.length === 0}>Request approval</button>
      </form>
    </div>
    <div style={panel}><h3>Policy check</h3><p>Read-only decision check. It cannot start assessment work or consume approval.</p><form style={form} onSubmit={(e) => void submit(e, async (data) => { const result = await api.evaluateEngagementPolicy(organizationId, engagementId, { asset_type: String(data.get('asset_type')), target: String(data.get('target')), technique: String(data.get('technique')) }); setPolicyResult(result); })}><label>Asset type <select name="asset_type"><option>domain</option><option>ip</option><option>cidr</option><option>url</option></select></label><label>Target <input name="target" required maxLength={2048}/></label><label>Technique <select name="technique"><option>http_metadata</option><option>service_fingerprint</option><option>exploit_verification</option></select></label><button disabled={busy}>Evaluate policy</button></form>{policyResult && <pre role="status">{String(policyResult.decision)} · {String(policyResult.reason_code)} — {String(policyResult.explanation)}</pre>}</div>
    <div style={panel}><h3>Governed domain executions</h3><p>Only registered active domain assets in current scope can be queued. Jobs revalidate authorization immediately before DNS and each HTTP request.</p>{cancellationMessage && <p role="status">{cancellationMessage}</p>}<ul>{executionJobs.map((job) => { const provenance = provenanceByJob[job.id]; return <li key={job.id}><code>{job.target}</code> · {job.status} · policy {job.policy_decision_id}{job.error_code && ` · ${job.error_code}`}{job.scan_id && ` · scan ${job.scan_id}`}{job.cancellation_requested_at && <small> · cancellation {job.cancellation_observed_at ? 'observed' : 'pending'}</small>}{['queued', 'claimed', 'running'].includes(job.status) && !job.cancellation_requested_at && <button type="button" disabled={cancellationPendingId !== null || busy} onClick={() => void cancelExecution(job)}>{cancellationPendingId === job.id ? 'Requesting cancellation…' : 'Cancel execution'}</button>}<button type="button" onClick={() => void loadProvenance(job)}>View provenance</button>{provenance && <div aria-label={`Provenance for ${job.id}`}><p>Governed result · {provenance.execution.outcome} · requester <code>{provenance.execution.requester_user_id}</code> · {provenance.execution.technique} ({provenance.execution.action_class})</p><p>Scope <code>{provenance.execution.scope_revision_id}</code> · authorization <code>{provenance.execution.authorization_id}</code>{provenance.execution.authorization_document_sha256 && <> · authorization document SHA-256 <code>{provenance.execution.authorization_document_sha256}</code></>} · approval {provenance.execution.approval_consumption_outcome}</p><ul>{provenance.results.map((item) => <li key={`${item.record_type}:${item.record_id}`}>{item.record_type}: <code>{item.record_id}</code>{item.record_type === 'finding' && ' · finding evidence remains attached to this originated finding'}</li>)}</ul>{provenance.results.length === 0 && <p>No result records were created by this execution.</p>}</div>}</li>; })}</ul></div>
  </section>;
}
