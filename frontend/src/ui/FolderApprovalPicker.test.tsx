import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { FolderApprovalPicker } from './FolderApprovalPicker';

const project = { project_id: 'p1', name: 'web-project', kind: 'local' as const, configured_by: 'dashboard' as const, origin_label: 'This device', created_at: '', last_scan: null, last_scan_refs: [] };
const roots = { items: [{ directory_id: 'drive-id', name: 'C:\\', selectable: false }] };
const page = { directory_id: 'drive-id', name: 'C:\\', selectable: false, breadcrumbs: [], items: [{ directory_id: 'folder-id', name: 'web-project', selectable: true }], next_cursor: null, truncated: false };
function response(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })); }

describe('shared folder approval picker', () => {
  beforeEach(() => { vi.restoreAllMocks(); setCsrfToken('csrf-test'); });

  it('shows the resolved path and requires explicit confirmation before registration', async () => {
    const onApproved = vi.fn();
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/fs/picker-roots') return response(roots);
      if (path.startsWith('/api/fs/picker-list')) return response(page);
      if (path.startsWith('/api/fs/picker-preview')) return response({ directory_id: 'folder-id', name: 'web-project', resolved_path: 'C:\\work\\web-project' });
      if (path === '/api/projects/approve-folder' && init?.method === 'POST') return response(project, 201);
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<FolderApprovalPicker onClose={vi.fn()} onUnauthorized={vi.fn()} onApproved={onApproved} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open C:\\' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select this folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Review folder' }));
    expect(await screen.findByText('C:\\work\\web-project')).toBeInTheDocument();
    expect(screen.getByText('Approve this folder for assessment?')).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalledWith('/api/projects/approve-folder', expect.anything());
    fireEvent.click(screen.getByRole('button', { name: 'Approve folder' }));
    await waitFor(() => expect(onApproved).toHaveBeenCalledWith(project));
    expect(fetchMock).toHaveBeenCalledWith('/api/projects/approve-folder', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ directory_id: 'folder-id', name: 'web-project', approved: true, purpose: 'project' }),
    }));
  });

  it('shows backend validation errors without approving the folder', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/fs/picker-roots') return response(roots);
      if (path.startsWith('/api/fs/picker-list')) return response(page);
      if (path.startsWith('/api/fs/picker-preview')) return response({ detail: { code: 'system_directory', message: 'Windows system folders cannot be approved.' } }, 422);
      return response({});
    });
    render(<FolderApprovalPicker onClose={vi.fn()} onUnauthorized={vi.fn()} onApproved={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open C:\\' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select this folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Review folder' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Windows system folders cannot be approved.');
    expect(fetchMock).not.toHaveBeenCalledWith('/api/projects/approve-folder', expect.anything());
  });

  it('uploads a device folder via input fallback, excludes secret files, and registers the project', async () => {
    const uploadedProject = { ...project, kind: 'upload' as const, name: 'local-app' };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/fs/picker-roots') return response(roots);
      if (path === '/api/projects/upload-folder' && init?.method === 'POST') return response(uploadedProject, 201);
      throw new Error(`Unexpected request: ${path}`);
    });
    const onApproved = vi.fn();
    render(<FolderApprovalPicker onClose={vi.fn()} onUnauthorized={vi.fn()} onApproved={onApproved} />);

    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    expect(input).toBeTruthy();

    const makeFile = (relPath: string, content: string) => {
      const file = new File([content], relPath.split('/').pop() || 'file', { type: 'text/plain' });
      Object.defineProperty(file, 'webkitRelativePath', { value: relPath });
      return file;
    };

    fireEvent.change(input, {
      target: {
        files: [
          makeFile('local-app/src/index.ts', 'export const ok = true;'),
          makeFile('local-app/.env', 'SECRET=123'),
          makeFile('local-app/.git/HEAD', 'ref: refs/heads/main'),
        ],
      },
    });

    expect(await screen.findByText(/1\s+files/i)).toBeInTheDocument();
    expect(screen.getByText(/2 unsafe\/secret or oversized files excluded/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Approve folder' }));
    await waitFor(() => expect(onApproved).toHaveBeenCalledWith(uploadedProject));
    const uploadCall = fetchMock.mock.calls.find(([url]) => String(url) === '/api/projects/upload-folder');
    expect(uploadCall).toBeTruthy();
    const sentBody = JSON.parse(String(uploadCall?.[1]?.body));
    expect(sentBody.name).toBe('local-app');
    expect(sentBody.files).toHaveLength(1);
    expect(sentBody.files[0].path).toBe('src/index.ts');
  });

  it('shows an error if a selected device folder contains only excluded files', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input) === '/api/fs/picker-roots') return response(roots);
      return response({});
    });
    render(<FolderApprovalPicker onClose={vi.fn()} onUnauthorized={vi.fn()} onApproved={vi.fn()} />);
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    const envFile = new File(['SECRET=1'], '.env', { type: 'text/plain' });
    Object.defineProperty(envFile, 'webkitRelativePath', { value: 'empty-app/.env' });
    fireEvent.change(input, { target: { files: [envFile] } });
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'No eligible source files remained after excluding'
    );
  });
});
