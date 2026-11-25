import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, UnauthorizedError } from '../api';
import type {
  Engagement,
  EngagementAssignment,
  ExecutionJob,
  ExecutionQuota,
  Organization,
} from '../types';
import { AccountSecurityWorkspace } from './AccountSecurityWorkspace';
import { App } from './App';
import { UnifiedEngagementWorkspace } from './UnifiedEngagementWorkspace';
import { UnifiedJobsMonitor } from './UnifiedJobsMonitor';

afterEach(() => {
  vi.restoreAllMocks();
});

const ORG_A: Organization = {
  id: 'org-aaaa-1111',
  name: 'Alpha Sec',
  slug: 'alpha-sec',
  owner_user_id: 'user-1111',
  status: 'active',
  created_at: '2026-11-25T10:00:00Z',
  updated_at: '2026-11-25T10:00:00Z',
  role: 'owner',
};

const ORG_B: Organization = {
  id: 'org-bbbb-2222',
  name: 'Beta Ops',
  slug: 'beta-ops',
  owner_user_id: 'user-2222',
  status: 'active',
  created_at: '2026-11-25T10:00:00Z',
  updated_at: '2026-11-25T10:00:00Z',
  role: 'viewer',
};

const ENG_A: Engagement = {
  id: 'eng-aaaa-1111',
  organization_id: ORG_A.id,
  client_id: 'cli-1',
  name: 'Alpha Audit',
  description: 'Scope A',
  status: 'active',
  created_at: '2026-11-25T10:00:00Z',
  updated_at: '2026-11-25T10:00:00Z',
};

const ENG_B: Engagement = {
  id: 'eng-bbbb-2222',
  organization_id: ORG_B.id,
  client_id: 'cli-2',
  name: 'Beta Review',
  description: 'Scope B',
  status: 'active',
  created_at: '2026-11-25T10:00:00Z',
  updated_at: '2026-11-25T10:00:00Z',
};

function makeJob(id: string, status: ExecutionJob['status'], overrides: Partial<ExecutionJob> = {}): ExecutionJob {
  return {
    id,
    organization_id: ORG_A.id,
    engagement_id: ENG_A.id,
    requester_user_id: 'user-1111',
    asset_id: 'asset-1',
    target: `target-${status}.example.test`,
    asset_type: 'domain',
    technique: 'service_fingerprint',
    action_class: 'controlled_active',
    scope_revision_id: 'scope-rev-1',
    authorization_id: 'auth-1111',
    approval_id: null,
    policy_decision_id: 'dec-1',
    request_digest: 'a'.repeat(64),
    status,
    created_at: '2026-11-25T10:00:00Z',
    expires_at: '2026-11-25T12:00:00Z',
    started_at: status === 'queued' ? null : '2026-11-25T10:01:00Z',
    finished_at: ['completed', 'failed', 'blocked', 'cancelled', 'reconciliation_required'].includes(status)
      ? '2026-11-25T10:02:00Z'
      : null,
    scan_id: status === 'completed' ? 'scan-done-1' : null,
    error_code: status === 'reconciliation_required' ? 'EXTERNAL_OUTCOME_UNCERTAIN' : null,
    cancellation_requested_at: status === 'cancelled' ? '2026-11-25T10:01:30Z' : null,
    cancellation_requested_by: status === 'cancelled' ? 'user-1111' : null,
    cancellation_observed_at: status === 'cancelled' ? '2026-11-25T10:01:45Z' : null,
    ...overrides,
  };
}

describe('Phase 2F unified workspace', () => {
  it('displays all 8 durable job states, handles reconciliation_required without retry, and cancels active jobs', async () => {
    const quota: ExecutionQuota = {
      organization_id: ORG_A.id,
      queued_jobs: 1,
      active_jobs: 2,
      total_reserved_jobs: 3,
      reconciliation_required_jobs: 1,
      limits: {
        per_org_active_limit: 2,
        per_org_queued_limit: 4,
        default_job_deadline_seconds: 300,
        max_queue_wait_seconds: 900,
      },
    };
    const jobs: ExecutionJob[] = [
      makeJob('job-q-0001', 'queued'),
      makeJob('job-c-0002', 'claimed'),
      makeJob('job-r-0003', 'running'),
      makeJob('job-d-0004', 'completed'),
      makeJob('job-f-0005', 'failed'),
      makeJob('job-b-0006', 'blocked'),
      makeJob('job-x-0007', 'cancelled'),
      makeJob('job-u-0008', 'reconciliation_required', {
        approval_id: 'app-1',
        approval_consumed_at: '2026-11-25T10:01:10Z',
      }),
    ];
    vi.spyOn(api, 'governedExecutions').mockResolvedValue({ items: jobs });
    vi.spyOn(api, 'executionQuota').mockResolvedValue(quota);
    const cancelSpy = vi
      .spyOn(api, 'cancelGovernedExecution')
      .mockResolvedValue({ ...jobs[0], status: 'cancelled', cancellation_outcome: 'completed', idempotent: false });

    const onUnauthorized = vi.fn();
    render(
      <UnifiedJobsMonitor
        organizationId={ORG_A.id}
        engagementId={ENG_A.id}
        onUnauthorized={onUnauthorized}
      />
    );

    await waitFor(() => expect(screen.getByText(/Reconciliation required \(1\):/i)).toBeInTheDocument());
    for (const status of [
      'queued',
      'claimed',
      'running',
      'completed',
      'failed',
      'blocked',
      'cancelled',
      'reconciliation_required',
    ]) {
      expect(screen.getAllByText(status).length).toBeGreaterThan(0);
    }
    expect(screen.getByText(/cannot be automatically retried or replayed/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /retry|resubmit/i })).toBeNull();
    expect(screen.getByText(/300s/)).toBeInTheDocument();

    const cancelButtons = screen.getAllByRole('button', { name: /Cancel job/i });
    fireEvent.click(cancelButtons[0]);
    await waitFor(() => expect(cancelSpy).toHaveBeenCalledWith(ORG_A.id, ENG_A.id, 'job-q-0001'));
  });

  it('clears stale organization/engagement data on context switch and submits governed malware & chain jobs', async () => {
    const assignments: EngagementAssignment[] = [
      {
        id: 'assign-1',
        organization_id: ORG_A.id,
        engagement_id: ENG_A.id,
        user_id: 'user-1111',
        role: 'lead',
        status: 'active',
        created_at: '2026-11-25T10:00:00Z',
        updated_at: '2026-11-25T10:00:00Z',
      },
    ];
    vi.spyOn(api, 'engagementAssets').mockImplementation(async (orgId) => ({
      items:
        orgId === ORG_A.id
          ? [
              {
                id: 'asset-log-a',
                asset_type: 'log_evidence',
                target: 'log:alpha-only',
                description: 'Alpha logs',
                status: 'active',
              },
            ]
          : [],
    }));
    vi.spyOn(api, 'scopeRevisions').mockImplementation(async (orgId) => ({
      items:
        orgId === ORG_A.id
          ? [
              {
                id: 'scope-a',
                organization_id: ORG_A.id,
                engagement_id: ENG_A.id,
                revision: 1,
                status: 'published',
                change_summary: 'Alpha scope',
                created_by: 'user-1111',
                approved_by: 'user-2222',
                created_at: '2026-11-25T10:00:00Z',
                published_at: '2026-11-25T10:05:00Z',
                rules: [],
              },
            ]
          : [],
    }));
    vi.spyOn(api, 'authorizationRecords').mockResolvedValue({ items: [] });
    vi.spyOn(api, 'approvalRequests').mockResolvedValue({ items: [] });
    vi.spyOn(api, 'executionQuota').mockRejectedValue(new Error('unused'));
    vi.spyOn(api, 'malwareEvidence').mockImplementation(async (orgId) => ({
      items:
        orgId === ORG_A.id
          ? [
              {
                asset_id: 'mal-alpha-1',
                snapshot_id: 'snap-m-1',
                original_filename: 'alpha-sample.exe',
                sha256: 'b'.repeat(64),
                size_bytes: 2048,
                status: 'available',
                classification: 'malware_sample',
              },
            ]
          : [],
    }));
    vi.spyOn(api, 'chainChains').mockResolvedValue([
      {
        name: 'ethereum',
        family: 'evm',
        native_asset: 'ETH',
        credential_configured: false,
      },
    ]);
    vi.spyOn(api, 'governedExecutions').mockResolvedValue({ items: [] });
    vi.spyOn(api, 'engagementAudit').mockResolvedValue({ items: [] });
    const malwareSpy = vi
      .spyOn(api, 'startGovernedMalwareTriage')
      .mockResolvedValue(makeJob('job-mal-1', 'queued', { technique: 'malware_static_triage' }));

    const { rerender } = render(
      <UnifiedEngagementWorkspace
        organization={ORG_A}
        engagement={ENG_A}
        assignments={assignments}
        currentUserId="user-1111"
        initialTab="malware"
        onUnauthorized={vi.fn()}
      />
    );

    await waitFor(() => expect(screen.getByText('alpha-sample.exe')).toBeInTheDocument());
    expect(screen.getByText(/Samples are never executed, detonated, sandboxed/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Run static triage/i }));
    await waitFor(() =>
      expect(malwareSpy).toHaveBeenCalledWith(ORG_A.id, ENG_A.id, 'mal-alpha-1', expect.any(String))
    );

    // Switch to Org B -> Org A's malware sample must disappear immediately
    rerender(
      <UnifiedEngagementWorkspace
        organization={ORG_B}
        engagement={ENG_B}
        assignments={[]}
        currentUserId="user-1111"
        initialTab="malware"
        onUnauthorized={vi.fn()}
      />
    );
    await waitFor(() => expect(screen.queryByText('alpha-sample.exe')).toBeNull());
    expect(screen.getByText(/No governed malware evidence registered/i)).toBeInTheDocument();
  });

  it('switches organization/engagement context in App and hides local-operator diagnostics when denied', async () => {
    vi.spyOn(api, 'session').mockResolvedValue({
      authenticated: true,
      email_masked: 'op@example.test',
      signup_available: false,
    });
    vi.spyOn(api, 'csrf').mockResolvedValue({ csrf_token: 'csrf-2f' });
    vi.spyOn(api, 'overview').mockResolvedValue({
      scan_count: 0,
      finding_count: 0,
      findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings_by_verdict: { confirmed: 0, lead: 0, likely: 0 },
      top_fix_first: [],
      recent_scans: [],
    });
    vi.spyOn(api, 'dashboardScores').mockResolvedValue([]);
    vi.spyOn(api, 'alerts').mockResolvedValue([]);
    vi.spyOn(api, 'organizations').mockResolvedValue({ items: [ORG_A, ORG_B] });
    vi.spyOn(api, 'currentUser').mockResolvedValue({
      id: 'user-1111',
      email_normalized: 'op@example.test',
      display_name: 'Operator',
      status: 'active',
      created_at: '2026-11-25T10:00:00Z',
    });
    const engSpy = vi
      .spyOn(api, 'organizationEngagements')
      .mockImplementation(async (orgId) => ({
        items: orgId === ORG_A.id ? [ENG_A] : [ENG_B],
      }));
    vi.spyOn(api, 'engagementAssignments').mockResolvedValue({ items: [] });
    vi.spyOn(api, 'executionResourceDiagnostics').mockRejectedValue(new Error('Forbidden'));

    render(<App />);

    await waitFor(() => expect(screen.getByLabelText('Active organization')).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText('Active organization'), {
      target: { value: ORG_B.id },
    });
    await waitFor(() => expect(engSpy).toHaveBeenCalledWith(ORG_B.id));
    expect(screen.getByText(/Org role:/i)).toHaveTextContent('viewer');
  });

  it('supports AccountSecurityWorkspace password change, TOTP enrollment, and session expiry', async () => {
    vi.spyOn(api, 'currentUser').mockResolvedValue({
      id: 'user-1111',
      email_normalized: 'op@example.test',
      display_name: 'Operator',
      status: 'active',
      created_at: '2026-11-25T10:00:00Z',
    });
    vi.spyOn(api, 'totpStatus').mockResolvedValue({
      totp_enabled: false,
      recovery_codes_remaining: 0,
    });
    vi.spyOn(api, 'totpEnroll').mockResolvedValue({
      secret: 'JBSWY3DPEHPK3PXP',
      otpauth_uri: 'otpauth://totp/ChiNeScan:op?secret=JBSWY3DPEHPK3PXP',
    });
    const onUnauthorized = vi.fn();
    vi.spyOn(api, 'changePassword').mockRejectedValue(new UnauthorizedError('Session expired'));

    render(<AccountSecurityWorkspace onUnauthorized={onUnauthorized} />);

    await waitFor(() => expect(screen.getByText('op@example.test')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Enroll TOTP/i }));
    await waitFor(() => expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText(/Current password/i), {
      target: { value: 'Old-Password-123456!' },
    });
    fireEvent.change(screen.getByLabelText(/New password/i), {
      target: { value: 'New-Password-123456!' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Change password/i }));
    await waitFor(() => expect(onUnauthorized).toHaveBeenCalled());
  });
});
