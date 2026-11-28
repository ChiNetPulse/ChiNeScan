import { useEffect, useRef, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { ApprovedFolder, FolderPreview, FsDirectory, FsPage } from '../types';

type Purpose = 'project' | 'logs' | 'malware';
type DeviceUploadFile = { path: string; content_base64: string; size: number };
type DevicePreview = {
  folderName: string;
  files: DeviceUploadFile[];
  totalBytes: number;
  excludedCount: number;
};

const EXCLUDED_DIRS = new Set([
  '.git',
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  '.ruff_cache',
  'dist',
  'build',
  'target',
  '.next',
  '.nuxt',
  '.tox',
  '.eggs',
]);
const SECRET_NAMES = new Set([
  '.env',
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.htpasswd',
  'credentials.json',
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
]);
const SECRET_EXTS = ['.pem', '.key', '.p12', '.pfx', '.jks', '.keystore'];
const MAX_UPLOAD_FILES = 2000;
const MAX_UPLOAD_FILE_BYTES = 2 * 1024 * 1024;
const MAX_UPLOAD_TOTAL_BYTES = 25 * 1024 * 1024;

function isExcludedRelativePath(relPath: string): boolean {
  const parts = relPath.split('/').filter(Boolean);
  if (!parts.length) return true;
  const lowerParts = parts.map((p) => p.toLowerCase());
  const filename = lowerParts[lowerParts.length - 1];
  if (lowerParts.slice(0, -1).some((dir) => EXCLUDED_DIRS.has(dir))) return true;
  if (SECRET_NAMES.has(filename) || filename.startsWith('.env.')) return true;
  if (SECRET_EXTS.some((ext) => filename.endsWith(ext))) return true;
  return false;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

type DirectoryPickerHandle = {
  name: string;
  values: () => AsyncIterable<{
    kind: 'file' | 'directory';
    name: string;
    getFile?: () => Promise<File>;
    values?: () => AsyncIterable<unknown>;
  }>;
};

async function collectFromDirectoryHandle(
  handle: DirectoryPickerHandle,
  prefix = '',
  acc: Array<{ relPath: string; file: File }> = [],
): Promise<Array<{ relPath: string; file: File }>> {
  for await (const entry of handle.values()) {
    const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.kind === 'directory') {
      if (EXCLUDED_DIRS.has(entry.name.toLowerCase())) continue;
      await collectFromDirectoryHandle(entry as unknown as DirectoryPickerHandle, relPath, acc);
    } else if (entry.kind === 'file' && entry.getFile) {
      acc.push({ relPath, file: await entry.getFile() });
    }
    if (acc.length > MAX_UPLOAD_FILES * 2) break;
  }
  return acc;
}

export function FolderApprovalPicker({
  onClose,
  onUnauthorized,
  onApproved,
  purpose = 'project',
}: {
  onClose: () => void;
  onUnauthorized: () => void;
  onApproved: (project: ApprovedFolder) => void;
  purpose?: Purpose;
}) {
  const dialog = useRef<HTMLDivElement>(null);
  const directoryInputRef = useRef<HTMLInputElement>(null);
  const [roots, setRoots] = useState<FsDirectory[]>([]);
  const [page, setPage] = useState<FsPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [items, setItems] = useState<FsDirectory[]>([]);
  const [selected, setSelected] = useState<FsDirectory | null>(null);
  const [preview, setPreview] = useState<FolderPreview | null>(null);
  const [devicePreview, setDevicePreview] = useState<DevicePreview | null>(null);
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const supportsDirectoryPicker =
    typeof window !== 'undefined' &&
    typeof (window as unknown as { showDirectoryPicker?: unknown }).showDirectoryPicker === 'function';
  const supportsWebkitDirectory =
    typeof document !== 'undefined' &&
    'webkitdirectory' in document.createElement('input');

  useEffect(() => {
    let active = true;
    api.folderPickerRoots().then((result) => {
      if (active) setRoots(result.items);
    }).catch((reason: unknown) => {
      if (!active) return;
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Local folders could not be loaded.');
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [onUnauthorized]);

  useEffect(() => {
    const node = dialog.current;
    if (!node) return;
    const focusable = () => Array.from(node.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), [tabindex="0"]',
    ));
    focusable()[0]?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { onClose(); return; }
      if (event.key !== 'Tab') return;
      const controls = focusable();
      if (!controls.length) return;
      if (event.shiftKey && document.activeElement === controls[0]) {
        event.preventDefault(); controls.at(-1)?.focus();
      } else if (!event.shiftKey && document.activeElement === controls.at(-1)) {
        event.preventDefault(); controls[0].focus();
      }
    };
    document.addEventListener('keydown', trap);
    return () => document.removeEventListener('keydown', trap);
  }, [onClose, preview, devicePreview]);

  async function processSelectedFiles(folderName: string, entries: Array<{ relPath: string; file: File }>) {
    if (!entries.length) {
      setError('The selected folder is empty. Choose a folder with source files.');
      return;
    }
    const uploadFiles: DeviceUploadFile[] = [];
    let excludedCount = 0;
    let totalBytes = 0;

    for (const { relPath, file } of entries) {
      const normalizedPath = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
      if (isExcludedRelativePath(normalizedPath)) {
        excludedCount += 1;
        continue;
      }
      if (file.size > MAX_UPLOAD_FILE_BYTES) {
        excludedCount += 1;
        continue;
      }
      if (uploadFiles.length >= MAX_UPLOAD_FILES) {
        setError(`Folders are limited to ${MAX_UPLOAD_FILES.toLocaleString()} eligible files.`);
        return;
      }
      if (totalBytes + file.size > MAX_UPLOAD_TOTAL_BYTES) {
        setError('Total eligible folder size exceeds the 25 MiB upload limit.');
        return;
      }
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      uploadFiles.push({
        path: normalizedPath,
        content_base64: bytesToBase64(bytes),
        size: bytes.byteLength,
      });
      totalBytes += bytes.byteLength;
    }

    if (!uploadFiles.length) {
      setError('No eligible source files remained after excluding build, cache, and secret files.');
      return;
    }
    setDevicePreview({
      folderName,
      files: uploadFiles,
      totalBytes,
      excludedCount,
    });
    setName(folderName);
  }

  async function pickDeviceFolder() {
    setError('');
    if (supportsDirectoryPicker) {
      setLoading(true);
      try {
        const picker = (window as unknown as {
          showDirectoryPicker: (opts?: { mode?: 'read' }) => Promise<DirectoryPickerHandle>;
        }).showDirectoryPicker;
        const dirHandle = await picker({ mode: 'read' });
        const entries = await collectFromDirectoryHandle(dirHandle);
        await processSelectedFiles(dirHandle.name || 'local-folder', entries);
      } catch (reason: unknown) {
        if (reason instanceof DOMException && reason.name === 'AbortError') {
          setError('Folder selection was cancelled.');
        } else if (reason instanceof DOMException && reason.name === 'NotAllowedError') {
          setError('Permission to read the selected folder was denied by the browser.');
        } else {
          setError(reason instanceof Error ? reason.message : 'Unable to read the selected folder.');
        }
      } finally {
        setLoading(false);
      }
      return;
    }
    if (supportsWebkitDirectory && directoryInputRef.current) {
      directoryInputRef.current.value = '';
      directoryInputRef.current.click();
      return;
    }
    setError(
      'This browser does not support selecting a local folder. Use a Chromium-based browser or import a public GitHub repository instead.',
    );
  }

  async function handleFallbackInputChange(event: React.ChangeEvent<HTMLInputElement>) {
    const fileList = event.target.files;
    if (!fileList || fileList.length === 0) {
      setError('The selected folder is empty or selection was cancelled.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const entries: Array<{ relPath: string; file: File }> = [];
      let rootName = 'local-folder';
      for (const file of Array.from(fileList)) {
        const rel = file.webkitRelativePath || file.name;
        const slash = rel.indexOf('/');
        if (slash > 0) {
          rootName = rel.slice(0, slash);
          entries.push({ relPath: rel.slice(slash + 1), file });
        } else {
          entries.push({ relPath: rel, file });
        }
      }
      await processSelectedFiles(rootName, entries);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : 'Unable to read the selected folder.');
    } finally {
      setLoading(false);
    }
  }

  async function browse(directory: FsDirectory, append = false) {
    setLoading(true); setError('');
    try {
      const result = await api.folderPickerList(directory.directory_id, append ? cursor : null);
      setPage(result);
      setSelected({ directory_id: result.directory_id, name: result.name, selectable: result.selectable });
      setItems(append ? [...items, ...result.items] : result.items);
      setCursor(result.next_cursor);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Folder contents could not be loaded.');
    } finally { setLoading(false); }
  }

  async function prepareConfirmation() {
    if (!selected?.selectable) return;
    setLoading(true); setError('');
    try {
      const next = await api.folderPickerPreview(selected.directory_id);
      setPreview(next); setName(next.name);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'The selected folder could not be validated.');
    } finally { setLoading(false); }
  }

  async function approve() {
    if (!name.trim()) return;
    if (devicePreview) {
      setSaving(true); setError('');
      try {
        const created = await api.uploadFolder(
          name.trim(),
          devicePreview.files.map(({ path, content_base64 }) => ({ path, content_base64 })),
        );
        onApproved(created);
      } catch (reason) {
        if (reason instanceof UnauthorizedError) onUnauthorized();
        else setError(reason instanceof Error ? reason.message : 'The folder could not be uploaded.');
      } finally { setSaving(false); }
      return;
    }
    if (!preview) return;
    setSaving(true); setError('');
    try {
      onApproved(await api.approveFolder(preview.directory_id, name.trim(), purpose));
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'The folder could not be approved.');
    } finally { setSaving(false); }
  }

  const title = purpose === 'logs' ? 'Select a log folder' : purpose === 'malware' ? 'Select a project folder for static triage' : 'Select a project folder';
  return <div className="project-dialog-backdrop">
    <div className="project-dialog folder-picker" role="dialog" aria-modal="true" aria-labelledby="folder-approval-title" ref={dialog}>
      <div className="dialog-heading"><div><h2 id="folder-approval-title">{preview || devicePreview ? 'Approve folder' : title}</h2><p>{preview || devicePreview ? 'Review the selected folder before approving it.' : 'Select a folder from your device or browse host folders. Secret files and build artifacts are excluded.'}</p></div><button aria-label="Close folder picker" className="close-button" onClick={onClose}>×</button></div>
      {error && <div role="alert" aria-live="assertive" className="alert-error">{error}</div>}
      {devicePreview ? <section aria-label="Device folder approval confirmation">
        <p><strong>Approve this device folder for assessment?</strong></p>
        <p className="mono folder-resolved-path">{devicePreview.folderName}</p>
        <p>{devicePreview.files.length.toLocaleString()} files ({(devicePreview.totalBytes / 1024).toFixed(1)} KiB){devicePreview.excludedCount ? ` · ${devicePreview.excludedCount} unsafe/secret or oversized files excluded` : ''}</p>
        <label htmlFor="approved-folder-name">Project name</label>
        <input id="approved-folder-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} />
        <div className="project-actions"><button className="secondary-button" onClick={() => setDevicePreview(null)}>Back</button><button className="secondary-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={!name.trim() || saving} onClick={() => void approve()}>{saving ? 'Uploading…' : 'Approve folder'}</button></div>
      </section> : preview ? <section aria-label="Folder approval confirmation">
        <p><strong>Approve this folder for assessment?</strong></p>
        <p className="mono folder-resolved-path">{preview.resolved_path}</p>
        <label htmlFor="approved-folder-name">Project name</label>
        <input id="approved-folder-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} />
        <div className="project-actions"><button className="secondary-button" onClick={() => setPreview(null)}>Back</button><button className="secondary-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={!name.trim() || saving} onClick={() => void approve()}>{saving ? 'Approving…' : 'Approve folder'}</button></div>
      </section> : <>
        {purpose === 'project' && <section aria-label="Choose folder from this device" style={{ marginBottom: '14px' }}>
          <input
            ref={directoryInputRef}
            type="file"
            multiple
            style={{ display: 'none' }}
            // @ts-expect-error webkitdirectory is standard in Chromium/Firefox/Safari
            webkitdirectory=""
            onChange={(event) => void handleFallbackInputChange(event)}
          />
          <button type="button" className="primary-button" disabled={loading} onClick={() => void pickDeviceFolder()}>
            Choose folder from this device
          </button>
        </section>}
        {loading && !roots.length && <p role="status">Loading local folders…</p>}
        {!loading && !roots.length && !error && <p role="status">No host folders are exposed on the backend; use “Choose folder from this device” above or import from GitHub.</p>}
        {roots.length > 0 && !page && <section aria-label="Local drives and allowed roots"><h3>Local drives and allowed roots</h3><ul className="folder-list">{roots.map((root) => <li key={root.directory_id}><button className="text-button" onClick={() => void browse(root)}>Open {root.name}</button>{root.selectable && <button className="secondary-button" onClick={() => setSelected(root)}>Select this folder</button>}</li>)}</ul></section>}
        {page && <section aria-label="Folder contents"><nav aria-label="Folder breadcrumbs" className="folder-breadcrumbs">{page.breadcrumbs.map((crumb, index) => <button key={`${crumb.directory_id}-${index}`} className="text-button" onClick={() => void browse(crumb)}>{crumb.name}</button>)}</nav>{page.truncated && <p role="status">Folder listing reached its directory-entry cap; results may be incomplete.</p>}{items.length ? <ul className="folder-list">{items.map((item) => <li key={item.directory_id}><button className="text-button" onClick={() => void browse(item)}>Open {item.name}</button>{item.selectable && <button className="secondary-button" onClick={() => setSelected(item)}>Select this folder</button>}</li>)}</ul> : <p className="empty-copy">No subfolders in this folder.</p>}{cursor && <button className="secondary-button" disabled={loading} onClick={() => void browse({ directory_id: page.directory_id, name: page.name, selectable: page.selectable }, true)}>Load more</button>}</section>}
        {selected && <p role="status">Selected: {selected.name}</p>}
        <div className="project-actions"><button className="secondary-button" onClick={onClose}>Cancel</button>{roots.length > 0 && <button className="primary-button" disabled={!selected?.selectable || loading} onClick={() => void prepareConfirmation()}>Review folder</button>}</div>
      </>}
    </div>
  </div>;
}
