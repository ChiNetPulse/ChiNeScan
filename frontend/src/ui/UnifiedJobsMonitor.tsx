import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { ExecutionJob, ExecutionProvenance, ExecutionQuota } from '../types';

type Props = {
  organizationId: string;
  engagementId: string;
  onUnauthorized: () => void;
  onSelectScan?: (scanId: string) => void;
};

function formatDurationMs(start: string | null, end: string | null): string {
  if (!start) return '—';
  const startMs = Date.parse(start);
  const endMs = end ? Date.parse(end) : Date.now();
  if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs < startMs) return '—';
  const seconds = Math.round((endMs - startMs) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  return `${mins}m ${seconds % 60}s`;
}

export function UnifiedJobsMonitor({
  organizationId,
  engagementId,
  onUnauthorized,
  onSelectScan,
}: Props) {
  const [jobs, setJobs] = useState<ExecutionJob[]>([]);
  const [quota, setQuota] = useState<ExecutionQuota | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [provenanceByJob, setProvenanceByJob] = useState<Record<string, ExecutionProvenance>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!organizationId || !engagementId) {
      setJobs([]);
      setQuota(null);
      setProvenanceByJob({});
      setLoading(false);
      return;
    }
    try {
      const [jobsResult, quotaResult] = await Promise.all([
        api.governedExecutions(organizationId, engagementId),
        api.executionQuota(organizationId, engagementId).catch(() => null),
      ]);
      setJobs(jobsResult.items);
      setQuota(quotaResult);
      setError('');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load governed jobs.');
    } finally {
      setLoading(false);
    }
  }, [organizationId, engagementId, onUnauthorized]);

  // Reset state immediately when org or engagement context changes to prevent stale leakage
  useEffect(() => {
    setJobs([]);
    setQuota(null);
    setProvenanceByJob({});
    setMessage('');
    setError('');
    setLoading(true);
    void load();
  }, [load]);

  // Poll active jobs with clean teardown and failure recovery
  useEffect(() => {
    const active = jobs.filter((job) => ['queued', 'claimed', 'running'].includes(job.status));
    if (active.length === 0) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void Promise.all(
        active.map(async (job) => {
          try {
            return await api.governedExecution(organizationId, engagementId, job.id);
          } catch (reason) {
            if (reason instanceof UnauthorizedError && !cancelled) onUnauthorized();
            return null;
          }
        })
      ).then((updates) => {
        if (cancelled) return;
        const byId = new Map(
          updates.filter((item): item is ExecutionJob => item !== null).map((item) => [item.id, item])
        );
        setJobs((current) => current.map((item) => byId.get(item.id) ?? item));
      });
    }, 1500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [jobs, organizationId, engagementId, onUnauthorized]);

  async function requestCancel(job: ExecutionJob) {
    if (busyId || !['queued', 'claimed', 'running'].includes(job.status) || job.cancellation_requested_at) {
      return;
    }
    setBusyId(job.id);
    setError('');
    setMessage('');
    try {
      const updated = await api.cancelGovernedExecution(organizationId, engagementId, job.id);
      setJobs((current) => current.map((item) => (item.id === updated.id ? updated : item)));
      setMessage(
        updated.status === 'cancelled'
          ? `Job ${job.id.slice(0, 8)} cancelled before external dispatch.`
          : updated.status === 'reconciliation_required'
            ? `Job ${job.id.slice(0, 8)} requires operator reconciliation because an external action was in progress.`
            : `Cancellation requested for ${job.id.slice(0, 8)}; worker will stop at next safe checkpoint.`
      );
      await load();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Cancellation request was rejected.');
    } finally {
      setBusyId(null);
    }
  }

  async function inspectProvenance(job: ExecutionJob) {
    setError('');
    try {
      const prov = await api.governedExecutionProvenance(organizationId, engagementId, job.id);
      setProvenanceByJob((current) => ({ ...current, [job.id]: prov }));
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load execution provenance.');
    }
  }

  const visibleJobs = statusFilter ? jobs.filter((job) => job.status === statusFilter) : jobs;
  const reconciliationJobs = jobs.filter((job) => job.status === 'reconciliation_required');

  if (!organizationId || !engagementId) {
    return (
      <section className="panel-card" aria-label="Governed jobs monitor">
        <h2>Governed Execution Jobs</h2>
        <p className="muted-copy">Select an organization and engagement to monitor durable execution jobs.</p>
      </section>
    );
  }

  return (
    <section className="panel-card" aria-label="Governed jobs monitor">
      <div className="panel-header-row">
        <div>
          <h2>Governed Execution Jobs</h2>
          <p className="muted-copy">
            Authoritative durable job states across repository, log, malware static triage, chain, and domain workflows.
          </p>
        </div>
        <div className="toolbar-inline">
          <label>
            Status{' '}
            <select
              aria-label="Filter execution job status"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              <option value="">All states</option>
              <option value="queued">queued</option>
              <option value="claimed">claimed</option>
              <option value="running">running</option>
              <option value="completed">completed</option>
              <option value="failed">failed</option>
              <option value="blocked">blocked</option>
              <option value="cancelled">cancelled</option>
              <option value="reconciliation_required">reconciliation_required</option>
            </select>
          </label>
          <button type="button" onClick={() => void load()} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {quota && (
        <div className="quota-strip" aria-label="Organization execution quota">
          <span>Active: <strong>{quota.active_jobs}</strong> / {quota.limits.per_org_active_limit}</span>
          <span>Queued: <strong>{quota.queued_jobs}</strong></span>
          <span>Reserved: <strong>{quota.total_reserved_jobs}</strong> / {quota.limits.per_org_queued_limit}</span>
          <span>Reconciliation required: <strong>{quota.reconciliation_required_jobs}</strong></span>
          <span>Job deadline: <strong>{quota.limits.default_job_deadline_seconds}s</strong></span>
        </div>
      )}

      {reconciliationJobs.length > 0 && (
        <div className="alert-warning" role="alert">
          <strong>Reconciliation required ({reconciliationJobs.length}):</strong>{' '}
          An external action may have occurred before interruption or timeout. These jobs are halted and
          cannot be automatically retried or replayed.
        </div>
      )}

      {error && <div className="alert-error" role="alert">{error}</div>}
      {message && <div className="status-banner" role="status">{message}</div>}
      {loading && <p className="muted-copy">Loading durable execution jobs…</p>}

      {!loading && visibleJobs.length === 0 ? (
        <p className="muted-copy">No governed execution jobs match this filter.</p>
      ) : (
        <ul className="job-ledger-list">
          {visibleJobs.map((job) => {
            const prov = provenanceByJob[job.id];
            const isActive = ['queued', 'claimed', 'running'].includes(job.status);
            const queueWait = formatDurationMs(job.created_at, job.started_at ?? job.claimed_at ?? null);
            const execDuration = formatDurationMs(job.started_at, job.finished_at);
            return (
              <li
                key={job.id}
                className={`job-ledger-item ${job.status === 'reconciliation_required' ? 'job-reconciliation' : ''}`}
              >
                <div className="job-ledger-top">
                  <div>
                    <code>{job.id.slice(0, 8)}</code> · <strong>{job.technique}</strong> ({job.asset_type}) ·{' '}
                    <code>{job.target}</code>
                  </div>
                  <span className={`status-pill status-${job.status}`}>{job.status}</span>
                </div>
                <div className="job-ledger-meta">
                  <span>Org: <code>{job.organization_id.slice(0, 8)}</code></span>
                  <span>Engagement: <code>{job.engagement_id.slice(0, 8)}</code></span>
                  <span>Requester: <code>{job.requester_user_id.slice(0, 8)}</code></span>
                  <span>Submitted: {new Date(job.created_at).toLocaleString()}</span>
                  <span>Queue wait: {queueWait}</span>
                  <span>Execution: {execDuration}</span>
                  <span>Action class: {job.action_class}</span>
                  {job.approval_id && (
                    <span>
                      Approval: {job.approval_consumed_at ? 'consumed' : 'bound (unconsumed)'}
                    </span>
                  )}
                  {job.cancellation_requested_at && (
                    <span>
                      Cancellation: {job.cancellation_observed_at ? 'observed' : 'requested'}
                    </span>
                  )}
                  {job.error_code && <span>Code: <code>{job.error_code}</code></span>}
                </div>
                {job.status === 'reconciliation_required' && (
                  <p className="reconciliation-note" role="note">
                    External action outcome is uncertain. Operator reconciliation is required before any new action; automatic resubmission is disabled.
                  </p>
                )}
                <div className="toolbar-inline">
                  {isActive && !job.cancellation_requested_at && (
                    <button
                      type="button"
                      disabled={busyId === job.id}
                      onClick={() => void requestCancel(job)}
                    >
                      Cancel job
                    </button>
                  )}
                  <button type="button" onClick={() => void inspectProvenance(job)}>
                    Inspect provenance
                  </button>
                  {job.scan_id && onSelectScan && (
                    <button type="button" onClick={() => onSelectScan(job.scan_id!)}>
                      View linked result
                    </button>
                  )}
                </div>
                {prov && (
                  <div className="provenance-box">
                    <strong>Immutable Context & Provenance</strong> · Scope{' '}
                    <code>{prov.execution.scope_revision_id.slice(0, 8)}</code> · Auth{' '}
                    <code>{prov.execution.authorization_id.slice(0, 8)}</code> · Digest{' '}
                    <code>{prov.execution.request_digest.slice(0, 12)}</code> · Approval{' '}
                    <code>{prov.execution.approval_consumption_outcome}</code> · Linked records:{' '}
                    {prov.results.length}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
