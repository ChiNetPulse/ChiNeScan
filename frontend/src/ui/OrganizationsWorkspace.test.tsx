import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { OrganizationsWorkspace } from './OrganizationsWorkspace';

const owner = { id: 'org-personal', name: 'Personal workspace', slug: 'personal-owner', status: 'active', owner_user_id: 'user-owner', role: 'owner', created_at: '2026-11-22T00:00:00Z', updated_at: '2026-11-22T00:00:00Z' };
const created = { ...owner, id: 'org-client', name: 'Client Org', slug: 'client-org' };
const unauthorized = vi.fn();
function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));
}

describe('organization workspace', () => {
  beforeEach(() => { vi.restoreAllMocks(); unauthorized.mockReset(); setCsrfToken('csrf-test'); });

  it('loads the personal organization and creates an organization through the API', async () => {
    let organizations = [owner];
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/organizations' && init?.method === 'POST') {
        organizations = [...organizations, created];
        return response(created, 201);
      }
      if (path === '/api/organizations') return response({ items: organizations });
      if (path.endsWith('/clients')) return response({ items: [] });
      if (path.endsWith('/engagements')) return response({ items: [] });
      if (path.endsWith('/members')) return response({ items: [] });
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<OrganizationsWorkspace onUnauthorized={unauthorized} />);
    expect(
      await screen.findByRole('option', { name: 'Personal workspace · owner' }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('New organization'), { target: { value: 'Client Org' } });
    fireEvent.change(screen.getByLabelText('Slug'), { target: { value: 'client-org' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create organization' }));
    expect(await screen.findByRole('option', { name: 'Client Org · owner' })).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/organizations', expect.objectContaining({ method: 'POST' })));
    expect(unauthorized).not.toHaveBeenCalled();
  });
});
