import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { EngagementLogEvidenceWorkspace } from './EngagementLogEvidenceWorkspace';

const evidence = {
  asset_id: 'asset-log-00000000000000000000000000000001',
  snapshot_id: 'snapshot-log-0000000000000000000000000001',
  label: 'Synthetic audit log', source_format: 'jsonl', sha256: 'a'.repeat(64),
  size_bytes: 123, file_count: 1, status: 'available', deletion_eligible: false,
};

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  }));
}

describe('engagement log evidence workspace', () => {
  beforeEach(() => { vi.restoreAllMocks(); setCsrfToken('csrf-test'); });

  it('registers configured sources and starts only governed analysis', async () => {
    const requests: Array<{ path: string; method: string }> = [];
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      const method = String(init?.method ?? 'GET');
      requests.push({ path, method });
      if (path.endsWith('/log-evidence/sources')) {
        return response({ items: [{ source_id: 'configured-logs', display_name: 'Audit logs' }] });
      }
      if (path.endsWith('/log-evidence') && method === 'GET') {
        return response({ items: [evidence] });
      }
      if (path.endsWith('/executions') && method === 'GET') return response({ items: [] });
      if (path.endsWith('/log-evidence') && method === 'POST') return response(evidence, 201);
      if (path.endsWith('/executions') && method === 'POST') return response({ id: 'job-1' }, 202);
      throw new Error(`Unexpected request: ${method} ${path}`);
    });
    render(<EngagementLogEvidenceWorkspace
      organizationId="org-1" engagementId="eng-1" onUnauthorized={vi.fn()}
    />);
    expect(await screen.findByText(/Synthetic audit log/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Evidence label'), { target: { value: 'New logs' } });
    fireEvent.click(screen.getByRole('button', { name: 'Register snapshot' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/log-evidence'), expect.objectContaining({ method: 'POST' }),
    ));
    fireEvent.click(screen.getAllByRole('button', { name: 'Run governed analysis' })[0]);
    await waitFor(() => expect(requests.some(
      (request) => request.method === 'POST' && request.path.endsWith('/executions'),
    )).toBe(true));
  });
});
