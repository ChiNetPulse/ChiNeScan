import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { EngagementSecurityWorkspace } from './EngagementSecurityWorkspace';

const unauthorized = vi.fn();
function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));
}

describe('engagement security workspace', () => {
  beforeEach(() => { vi.restoreAllMocks(); unauthorized.mockReset(); setCsrfToken('csrf-test'); });

  it('loads policy records and creates a normalized-asset request through connected APIs', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path.endsWith('/assets') && init?.method === 'POST') return response({ id: 'asset-1', asset_type: 'domain', target: 'example.test', status: 'active', description: null }, 201);
      if (path.endsWith('/assets')) return response({ items: [{ id: 'asset-1', asset_type: 'domain', target: 'example.test', status: 'active', description: null }] });
      if (path.endsWith('/scope/revisions')) return response({ items: [] });
      if (path.endsWith('/authorizations')) return response({ items: [] });
      if (path.endsWith('/approvals')) return response({ items: [] });
      if (path.endsWith('/executions')) return response({ items: [] });
      if (path.endsWith('/repositories/projects')) return response({ items: [] });
      if (path.endsWith('/repositories/quota')) return response({ used_bytes: 0, reserved_bytes: 0, organization_limit_bytes: 10, snapshot_limit_bytes: 5, available_bytes: 10 });
      if (path.endsWith('/repositories/retention')) return response({ items: [] });
      if (path.endsWith('/repositories/attestation')) return response({ version: 'v1', text: 'attestation text' });
      if (path.endsWith('/repositories')) return response({ items: [] });
      throw new Error(`Unexpected request: ${path} ${init?.method ?? 'GET'}`);
    });
    render(<EngagementSecurityWorkspace organizationId="org-1" engagementId="eng-1" onUnauthorized={unauthorized}/>);
    expect(await screen.findByText('No published scope. Policy decisions will deny assessment actions.')).toBeInTheDocument();
    fireEvent.change(screen.getAllByLabelText('Target')[0], { target: { value: 'example.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add asset' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/organizations/org-1/engagements/eng-1/assets',
      expect.objectContaining({ method: 'POST', headers: expect.any(Headers) }),
    ));
    expect(await screen.findByText(/domain: example\.test/)).toBeInTheDocument();
    expect(unauthorized).not.toHaveBeenCalled();
  });

  it('shows immutable execution context and linked finding provenance', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path.endsWith('/assets')) return response({ items: [] });
      if (path.endsWith('/scope/revisions')) return response({ items: [] });
      if (path.endsWith('/authorizations')) return response({ items: [] });
      if (path.endsWith('/approvals')) return response({ items: [] });
      if (path.endsWith('/executions')) return response({ items: [{
        id: 'job-1', organization_id: 'org-1', engagement_id: 'eng-1', requester_user_id: 'user-1',
        asset_id: 'asset-1', target: 'example.test', asset_type: 'domain', technique: 'service_fingerprint',
        action_class: 'controlled_active', scope_revision_id: 'scope-1', authorization_id: 'auth-1',
        approval_id: null, policy_decision_id: 'decision-1', request_digest: 'digest', status: 'completed',
        created_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-01T00:10:00Z', started_at: '2026-01-01T00:00:01Z',
        finished_at: '2026-01-01T00:00:02Z', scan_id: 'scan-1', error_code: null,
        cancellation_requested_at: null, cancellation_requested_by: null, cancellation_observed_at: null,
      }] });
      if (path.endsWith('/repositories/projects')) return response({ items: [] });
      if (path.endsWith('/repositories/quota')) return response({ used_bytes: 0, reserved_bytes: 0, organization_limit_bytes: 10, snapshot_limit_bytes: 5, available_bytes: 10 });
      if (path.endsWith('/repositories/retention')) return response({ items: [] });
      if (path.endsWith('/repositories/attestation')) return response({ version: 'v1', text: 'attestation text' });
      if (path.endsWith('/repositories')) return response({ items: [] });
      if (path.endsWith('/job-1/provenance')) return response({
        execution: {
          job_id: 'job-1', organization_id: 'org-1', engagement_id: 'eng-1', requester_user_id: 'user-1',
          target: 'example.test', target_type: 'domain', technique: 'service_fingerprint',
          action_class: 'controlled_active', scope_revision_id: 'scope-1', authorization_id: 'auth-1',
          authorization_document_sha256: null, request_digest: 'digest', approval_id: null,
          approval_consumption_outcome: 'not_required', approval_consumed_at: null,
          created_at: '2026-01-01T00:00:00Z', started_at: '2026-01-01T00:00:01Z',
          finished_at: '2026-01-01T00:00:02Z', outcome: 'completed', scan_id: 'scan-1',
        },
        execution_context: { job_id: 'job-1' },
        results: [{ record_type: 'finding', record_id: 'finding-1', linked_at: '2026-01-01T00:00:02Z' }],
      });
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<EngagementSecurityWorkspace organizationId="org-1" engagementId="eng-1" onUnauthorized={unauthorized}/>);
    fireEvent.click(await screen.findByRole('button', { name: 'View provenance' }));
    expect(await screen.findByText(/Governed result · completed/)).toBeInTheDocument();
    expect(await screen.findByText('finding-1')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/organizations/org-1/engagements/eng-1/executions/job-1/provenance',
      expect.objectContaining({ credentials: 'same-origin' }),
    );
  });
});
