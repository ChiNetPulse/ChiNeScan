import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type {
  ApprovalRecord,
  AuthorizationRecord,
  ChainInfo,
  Engagement,
  EngagementAsset,
  EngagementAssignment,
  ExecutionJob,
  ExecutionQuota,
  MalwareEvidence,
  Organization,
  ScopeRevisionRecord,
} from '../types';
import { EngagementLogEvidenceWorkspace } from './EngagementLogEvidenceWorkspace';
import { EngagementSecurityWorkspace } from './EngagementSecurityWorkspace';
import { UnifiedJobsMonitor } from './UnifiedJobsMonitor';

export type EngagementSectionTab =
  | 'overview'
  | 'scope'
  | 'authorization'
  | 'repositories'
  | 'logs'
  | 'malware'
  | 'chain'
  | 'jobs'
  | 'findings'
  | 'reports'
  | 'audit';

type Props = {
  organization: Organization | null;
  engagement: Engagement | null;
  assignments: EngagementAssignment[];
  currentUserId: string;
  initialTab?: EngagementSectionTab;
  onUnauthorized: () => void;
  onOpenScan?: (scanId: string) => void;
  onOpenCases?: () => void;
};

export function UnifiedEngagementWorkspace({
  organization,
  engagement,
  assignments,
  currentUserId,
  initialTab = 'overview',
  onUnauthorized,
  onOpenScan,
  onOpenCases,
}: Props) {
  const [tab, setTab] = useState<EngagementSectionTab>(initialTab);
  const [assets, setAssets] = useState<EngagementAsset[]>([]);
  const [scopes, setScopes] = useState<ScopeRevisionRecord[]>([]);
  const [authorizations, setAuthorizations] = useState<AuthorizationRecord[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [quota, setQuota] = useState<ExecutionQuota | null>(null);
  const [malwareItems, setMalwareItems] = useState<MalwareEvidence[]>([]);
  const [chains, setChains] = useState<ChainInfo[]>([]);
  const [jobs, setJobs] = useState<ExecutionJob[]>([]);
  const [auditEvents, setAuditEvents] = useState<
    Array<{ action: string; decision: string | null; reason_code: string | null; occurred_at: string }>
  >([]);
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const orgId = organization?.id ?? '';
  const engId = engagement?.id ?? '';

  useEffect(() => {
    setTab(initialTab);
  }, [initialTab]);

  const loadWorkspace = useCallback(async () => {
    if (!orgId || !engId) {
      setAssets([]);
      setScopes([]);
      setAuthorizations([]);
      setApprovals([]);
      setQuota(null);
      setMalwareItems([]);
      setJobs([]);
      setAuditEvents([]);
      return;
    }
    setBusy(true);
    setError('');
    try {
      const [a, s, z, p, q, m, c, j, au] = await Promise.all([
        api.engagementAssets(orgId, engId),
        api.scopeRevisions(orgId, engId),
        api.authorizationRecords(orgId, engId),
        api.approvalRequests(orgId, engId),
        api.executionQuota(orgId, engId).catch(() => null),
        api.malwareEvidence(orgId, engId).catch(() => ({ items: [] as MalwareEvidence[] })),
        api.chainChains().catch(() => [] as ChainInfo[]),
        api.governedExecutions(orgId, engId),
        api.engagementAudit(orgId, engId).catch(() => ({ items: [] })),
      ]);
      setAssets(a.items);
      setScopes(s.items);
      setAuthorizations(z.items);
      setApprovals(p.items);
      setQuota(q);
      setMalwareItems(m.items);
      setChains(c);
      setJobs(j.items);
      setAuditEvents(au.items);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load engagement workspace.');
    } finally {
      setBusy(false);
    }
  }, [orgId, engId, onUnauthorized]);

  // Immediately purge stale tenant/engagement data before fetching new context
  useEffect(() => {
    setAssets([]);
    setScopes([]);
    setAuthorizations([]);
    setApprovals([]);
    setQuota(null);
    setMalwareItems([]);
    setJobs([]);
    setAuditEvents([]);
    setStatusMessage('');
    setError('');
    void loadWorkspace();
  }, [loadWorkspace]);

  if (!organization || !engagement) {
    return (
      <section className="panel-card" aria-label="Unified engagement workspace">
        <h2>Engagement Workspace</h2>
        <p className="muted-copy">
          Select an organization and engagement from the context bar above to open its governed workspace.
        </p>
      </section>
    );
  }

  const myAssignment = assignments.find(
    (item) => item.user_id === currentUserId && item.status === 'active'
  );
  const publishedScope = scopes.find((item) => item.status === 'published');
  const draftScopes = scopes.filter((item) => item.status === 'draft');
  const activeAuthorization = authorizations.find(
    (item) =>
      item.status === 'active' &&
      item.scope_revision_id === publishedScope?.id &&
      Date.parse(item.effective_at) <= Date.now() &&
      Date.parse(item.expires_at) > Date.now()
  );
  const chainAssets = assets.filter((item) => item.asset_type === 'chain_address' && item.status === 'active');
  const logAssets = assets.filter((item) => item.asset_type === 'log_evidence' && item.status === 'active');
  const completedJobs = jobs.filter((item) => item.scan_id);

  async function startMalwareTriage(assetId: string) {
    setBusy(true);
    setError('');
    setStatusMessage('');
    try {
      const job = await api.startGovernedMalwareTriage(orgId, engId, assetId, crypto.randomUUID());
      setStatusMessage(`Submitted static-only malware triage job ${job.id.slice(0, 8)} (${job.status}).`);
      await loadWorkspace();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Malware triage submission rejected.');
    } finally {
      setBusy(false);
    }
  }

  async function submitChainImport(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setStatusMessage('');
    const form = new FormData(event.currentTarget);
    try {
      const job = await api.startGovernedChainImport(orgId, engId, {
        asset_id: String(form.get('asset_id')),
        chain: String(form.get('chain')),
        seed: String(form.get('seed')),
        depth: Number(form.get('depth') || 1),
        idempotency_key: crypto.randomUUID(),
      });
      setStatusMessage(`Submitted governed local chain import job ${job.id.slice(0, 8)} (${job.status}).`);
      await loadWorkspace();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Chain import submission rejected.');
    } finally {
      setBusy(false);
    }
  }

  async function submitChainProviderLookup(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setStatusMessage('');
    const form = new FormData(event.currentTarget);
    try {
      const job = await api.startGovernedChainProviderLookup(orgId, engId, {
        asset_id: String(form.get('asset_id')),
        approval_id: String(form.get('approval_id')),
        idempotency_key: crypto.randomUUID(),
      });
      setStatusMessage(`Submitted approved external chain lookup job ${job.id.slice(0, 8)} (${job.status}).`);
      await loadWorkspace();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Chain provider lookup rejected.');
    } finally {
      setBusy(false);
    }
  }

  const tabs: Array<{ id: EngagementSectionTab; label: string }> = [
    { id: 'overview', label: 'Overview' },
    { id: 'scope', label: 'Scope & Assets' },
    { id: 'authorization', label: 'Authorization' },
    { id: 'repositories', label: 'Repository Assessments' },
    { id: 'logs', label: 'Log Evidence' },
    { id: 'malware', label: 'Malware Triage' },
    { id: 'chain', label: 'Chain Tracing' },
    { id: 'jobs', label: 'Execution Jobs' },
    { id: 'findings', label: 'Findings & Results' },
    { id: 'reports', label: 'Reports' },
    { id: 'audit', label: 'Audit History' },
  ];

  return (
    <div className="workspace-stack">
      <section className="panel-card" aria-label="Engagement context summary">
        <div className="panel-header-row">
          <div>
            <div className="eyebrow">
              {organization.name} ({organization.role}) · {engagement.name}
            </div>
            <h2>{engagement.name}</h2>
            <p className="muted-copy">
              Assignment: <strong>{myAssignment ? myAssignment.role : 'none (organization role only)'}</strong> ·
              Scope:{' '}
              {publishedScope ? (
                <span className="status-pill status-completed">Published Rev {publishedScope.revision}</span>
              ) : (
                <span className="status-pill status-blocked">No published scope</span>
              )}{' '}
              {draftScopes.length > 0 && (
                <span className="status-pill status-queued">Drafts: {draftScopes.length}</span>
              )}{' '}
              · Authorization:{' '}
              {activeAuthorization ? (
                <span className="status-pill status-completed">
                  Active ({activeAuthorization.authorization_reference})
                </span>
              ) : (
                <span className="status-pill status-failed">Missing / Expired</span>
              )}
            </p>
          </div>
          <button type="button" onClick={() => void loadWorkspace()} disabled={busy}>
            Refresh context
          </button>
        </div>

        <nav className="section-tabs" aria-label="Engagement workspace sections">
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`tab-pill ${tab === item.id ? 'active' : ''}`}
              aria-current={tab === item.id ? 'page' : undefined}
              onClick={() => setTab(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </section>

      {error && <div className="alert-error" role="alert">{error}</div>}
      {statusMessage && <div className="status-banner" role="status">{statusMessage}</div>}

      {tab === 'overview' && (
        <section className="panel-card" aria-label="Engagement overview">
          <h3>Operational Summary</h3>
          <div className="meta-grid">
            <span>Engagement status: <strong>{engagement.status}</strong></span>
            <span>Active assets: <strong>{assets.filter((a) => a.status === 'active').length}</strong></span>
            <span>Pending approvals: <strong>{approvals.filter((a) => a.decision === 'pending').length}</strong></span>
            <span>Governed jobs: <strong>{jobs.length}</strong></span>
          </div>
          {quota && (
            <div className="quota-strip">
              <span>Org active slots: <strong>{quota.active_jobs}/{quota.limits.per_org_active_limit}</strong></span>
              <span>Org queued+active: <strong>{quota.total_reserved_jobs}/{quota.limits.per_org_queued_limit}</strong></span>
              <span>Reconciliation held: <strong>{quota.reconciliation_required_jobs}</strong></span>
              <span>Default job deadline: <strong>{quota.limits.default_job_deadline_seconds}s</strong></span>
            </div>
          )}
          <p className="muted-copy">
            Policy records and authorization metadata govern admission; the backend enforces role, assignment, scope,
            one-use approval, and quota limits at submission and execution checkpoints.
          </p>
        </section>
      )}

      {(tab === 'scope' || tab === 'authorization' || tab === 'repositories') && (
        <EngagementSecurityWorkspace
          organizationId={orgId}
          engagementId={engId}
          onUnauthorized={onUnauthorized}
        />
      )}

      {tab === 'logs' && (
        <EngagementLogEvidenceWorkspace
          organizationId={orgId}
          engagementId={engId}
          onUnauthorized={onUnauthorized}
        />
      )}

      {tab === 'malware' && (
        <section className="panel-card" aria-label="Governed static malware triage">
          <div className="panel-header-row">
            <div>
              <h3>Governed Malware Triage (Static-Only)</h3>
              <p className="muted-copy">
                Static heuristic triage of registered engagement malware evidence. Samples are never executed,
                detonated, sandboxed, or uploaded externally.
              </p>
            </div>
            <span className="status-pill status-completed">Static-only · Passive</span>
          </div>
          <p className="muted-copy">
            Scope revision: {publishedScope ? `Published Rev ${publishedScope.revision}` : 'None'} ·
            Operation class: <code>passive</code> (no separate sensitive approval required)
          </p>
          {malwareItems.length === 0 ? (
            <p className="muted-copy">No governed malware evidence registered in this engagement.</p>
          ) : (
            <ul className="job-ledger-list">
              {malwareItems.map((item) => (
                <li key={item.asset_id} className="job-ledger-item">
                  <div className="job-ledger-top">
                    <strong>{item.original_filename}</strong>
                    <span className="status-pill status-completed">{item.status}</span>
                  </div>
                  <div className="job-ledger-meta">
                    <span>Asset: <code>{item.asset_id.slice(0, 8)}</code></span>
                    <span>SHA-256: <code>{item.sha256.slice(0, 16)}…</code></span>
                    <span>Size: {item.size_bytes} bytes</span>
                    <span>Classification: {item.classification}</span>
                  </div>
                  {item.status === 'available' && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void startMalwareTriage(item.asset_id)}
                    >
                      Run static triage
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {tab === 'chain' && (
        <section className="panel-card" aria-label="Governed chain tracing">
          <h3>Governed Chain Tracing</h3>
          <p className="muted-copy">
            Local imported evidence tracing (<code>chain_trace_import</code>, passive) is strictly separated from
            external provider lookups (<code>chain_provider_lookup</code>, sensitive — requires one-use approval).
          </p>
          <div className="meta-grid">
            <span>Supported chains: {chains.map((c) => c.name).join(', ') || 'None loaded'}</span>
            <span>Scope: {publishedScope ? `Published Rev ${publishedScope.revision}` : 'None'}</span>
          </div>
          <form className="form-row" onSubmit={(e) => void submitChainImport(e)}>
            <label>
              Log evidence asset{' '}
              <select name="asset_id" required>
                <option value="">Select log evidence</option>
                {logAssets.map((a) => (
                  <option key={a.id} value={a.id}>{a.target}</option>
                ))}
              </select>
            </label>
            <label>
              Chain{' '}
              <select name="chain" required>
                {chains.map((c) => (
                  <option key={c.name} value={c.name}>{c.name}</option>
                ))}
              </select>
            </label>
            <label>Seed address <input name="seed" required /></label>
            <label>Depth <input name="depth" type="number" min={1} max={6} defaultValue={1} /></label>
            <button disabled={busy || logAssets.length === 0}>Start local chain import</button>
          </form>

          <form className="form-row" onSubmit={(e) => void submitChainProviderLookup(e)}>
            <label>
              Chain address asset{' '}
              <select name="asset_id" required>
                <option value="">Select chain address</option>
                {chainAssets.map((a) => (
                  <option key={a.id} value={a.id}>{a.target}</option>
                ))}
              </select>
            </label>
            <label>
              One-use approval{' '}
              <select name="approval_id" required>
                <option value="">Select approved request</option>
                {approvals
                  .filter((ap) => ap.decision === 'approved')
                  .map((ap) => (
                    <option key={ap.id} value={ap.id}>
                      {ap.technique} · {ap.target}
                    </option>
                  ))}
              </select>
            </label>
            <button disabled={busy || chainAssets.length === 0}>Start approved provider lookup</button>
          </form>
        </section>
      )}

      {tab === 'jobs' && (
        <UnifiedJobsMonitor
          organizationId={orgId}
          engagementId={engId}
          onUnauthorized={onUnauthorized}
          onSelectScan={onOpenScan}
        />
      )}

      {tab === 'findings' && (
        <section className="panel-card" aria-label="Engagement findings and results">
          <h3>Engagement Results & Provenance</h3>
          {completedJobs.length === 0 ? (
            <p className="muted-copy">No persisted scan results linked to this engagement yet.</p>
          ) : (
            <ul className="job-ledger-list">
              {completedJobs.map((job) => (
                <li key={job.id} className="job-ledger-item">
                  <div className="job-ledger-top">
                    <span><strong>{job.technique}</strong> · <code>{job.target}</code></span>
                    <span className={`status-pill status-${job.status}`}>{job.status}</span>
                  </div>
                  <div className="job-ledger-meta">
                    <span>Result ID: <code>{job.scan_id}</code></span>
                    <span>Scope: <code>{job.scope_revision_id.slice(0, 8)}</code></span>
                    <span>Digest: <code>{job.request_digest.slice(0, 12)}</code></span>
                  </div>
                  {job.scan_id && onOpenScan && (
                    <button type="button" onClick={() => onOpenScan(job.scan_id!)}>
                      Open persisted scan
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {tab === 'reports' && (
        <section className="panel-card" aria-label="Engagement reports">
          <h3>Engagement Reports</h3>
          <p className="muted-copy">
            Organization: <strong>{organization.name}</strong> · Engagement: <strong>{engagement.name}</strong>.
            Reports are server-authorized and scoped to persisted tenant records.
          </p>
          {onOpenCases && (
            <button type="button" onClick={onOpenCases}>
              Open Cases & Report Exports
            </button>
          )}
        </section>
      )}

      {tab === 'audit' && (
        <section className="panel-card" aria-label="Engagement audit history">
          <h3>Engagement Audit History</h3>
          {auditEvents.length === 0 ? (
            <p className="muted-copy">No engagement audit events available.</p>
          ) : (
            <ul className="job-ledger-list">
              {auditEvents.map((ev, idx) => (
                <li key={`${ev.occurred_at}-${idx}`} className="job-ledger-item">
                  <strong>{ev.action}</strong> · {ev.decision ?? 'INFO'} ·{' '}
                  <code>{ev.reason_code ?? '—'}</code> · {new Date(ev.occurred_at).toLocaleString()}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}
