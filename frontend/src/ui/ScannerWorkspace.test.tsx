import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ScannerWorkspace } from './ScannerWorkspace';

function response(body: unknown) {
  return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }));
}

describe('scanner workspace', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('shows disabled and readiness states without exposing execution controls', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path.endsWith('/nmap/status')) {
        return response({ integration: 'Nmap', enabled: false, configuration_ready: false, readiness_code: null, profiles: ['host_discovery'], target_types: ['ip', 'cidr'], hostname_targets_supported: false });
      }
      return response({ integration: 'Nuclei', enabled: false, configuration_ready: false, readiness_code: null, profiles: [], approved_templates: [], target_types: ['ip', 'cidr'] });
    });
    render(<ScannerWorkspace organizationId="org-1" engagementId="eng-1" onUnauthorized={vi.fn()} />);
    expect(await screen.findByText('Governed Scanner Workspace')).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText('Disabled by administrator')).toHaveLength(2));
    expect(screen.queryByRole('button', { name: /run|start/i })).not.toBeInTheDocument();
  });
});
