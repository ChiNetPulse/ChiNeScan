import { useCallback, useEffect, useState } from 'react';
import { api, setCsrfToken, UnauthorizedError } from '../api';
import type { Client, Engagement, EngagementAssignment, Organization, OrganizationInvitation, OrganizationMember, TotpStatus } from '../types';
import { EngagementSecurityWorkspace } from './EngagementSecurityWorkspace';
import { EngagementLogEvidenceWorkspace } from './EngagementLogEvidenceWorkspace';

export function OrganizationsWorkspace({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [items, setItems] = useState<Organization[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [clients, setClients] = useState<Client[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [latestInviteToken, setLatestInviteToken] = useState('');
  const [totp, setTotp] = useState<TotpStatus | null>(null);
  const [pendingSecret, setPendingSecret] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [accountStatus, setAccountStatus] = useState('');
  const [assignments, setAssignments] = useState<EngagementAssignment[]>([]);
  const [selectedEngagement, setSelectedEngagement] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const selected = items.find((item) => item.id === selectedId);

  const load = useCallback(async () => {
    try {
      const result = await api.organizations();
      setItems(result.items);
      setSelectedId((current) => result.items.some((item) => item.id === current) ? current : result.items[0]?.id ?? '');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load organizations.');
    }
  }, [onUnauthorized]);

  const loadOrganization = useCallback(async (id: string) => {
    if (!id) return;
    try {
      const [clientResult, engagementResult, memberResult, inviteResult] = await Promise.all([
        api.organizationClients(id), api.organizationEngagements(id), api.organizationMembers(id),
        api.organizationInvitations(id).catch(() => ({ items: [] as OrganizationInvitation[] })),
      ]);
      setClients(clientResult.items); setEngagements(engagementResult.items); setMembers(memberResult.items);
      setInvitations(inviteResult.items);
      setSelectedEngagement((current) => engagementResult.items.some((item) => item.id === current)
        ? current : engagementResult.items[0]?.id ?? '');
      setError('');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load organization details.');
    }
  }, [onUnauthorized]);

  useEffect(() => {
    void load();
    api.totpStatus().then(setTotp).catch(() => setTotp(null));
  }, [load]);
  useEffect(() => { setAssignments([]); void loadOrganization(selectedId); }, [selectedId, loadOrganization]);
  useEffect(() => {
    if (!selectedId || !selectedEngagement) { setAssignments([]); return; }
    api.engagementAssignments(selectedId, selectedEngagement).then((result) => setAssignments(result.items))
      .catch((reason: unknown) => {
        if (reason instanceof UnauthorizedError) onUnauthorized();
        else setError(reason instanceof Error ? reason.message : 'Could not load assignments.');
      });
  }, [selectedId, selectedEngagement, onUnauthorized]);

  async function submit(event: React.FormEvent<HTMLFormElement>, action: (form: FormData) => Promise<void>) {
    event.preventDefault(); setBusy(true); setError('');
    const formElement = event.currentTarget;
    try { await action(new FormData(formElement)); formElement.reset(); }
    catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'The operation failed.');
    } finally { setBusy(false); }
  }

  const sectionStyle: React.CSSProperties = { display: 'grid', gap: 12, marginTop: 18 };
  const panelStyle: React.CSSProperties = { padding: 18, border: '1px solid #29404d', borderRadius: 8, background: '#0b1824' };
  const formStyle: React.CSSProperties = { display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' };

  return <div className="organizations-workspace" style={{ maxWidth: 1100 }}>
    {error && <div className="alert-error" role="alert">{error}</div>}
    <section style={sectionStyle} aria-label="Organization selection and creation">
      <div style={panelStyle}>
        <h2>Organizations</h2>
        <label>Current organization <select value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>
          {items.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.role}</option>)}
        </select></label>
        {selected && <p>{selected.slug} · {selected.status} · {selected.role}</p>}
        <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
          await api.createOrganization(String(form.get('name')), String(form.get('slug'))); await load();
        })}>
          <label>New organization <input name="name" required maxLength={160} /></label>
          <label>Slug <input name="slug" required pattern="[A-Za-z0-9-]+" maxLength={100} /></label>
          <button disabled={busy}>Create organization</button>
        </form>
      </div>
      {selected && <div style={panelStyle}>
        <h2>Members</h2>
        <ul>{members.map((member) => <li key={member.id}>
          {member.display_name} · {member.role} · {member.status}
          {selected.role === 'owner' || selected.role === 'admin' ? <>
            <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
              await api.updateOrganizationMember(selected.id, member.user_id, { role: String(form.get('role')) });
              await loadOrganization(selected.id); await load();
            })}>
              <select name="role" defaultValue={member.role} aria-label={`Role for ${member.display_name}`}>
                <option value="owner">Owner</option><option value="admin">Admin</option><option value="member">Member</option><option value="auditor">Auditor</option><option value="viewer">Viewer</option>
              </select>
              <button disabled={busy}>Update role</button>
              {member.status === 'active' && member.role !== 'owner' && <button type="button" disabled={busy} onClick={async () => {
                try { await api.updateOrganizationMember(selected.id, member.user_id, { status: 'revoked' }); await loadOrganization(selected.id); }
                catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Could not revoke membership.'); }
              }}>Revoke</button>}
            </form>
          </> : null}
        </li>)}</ul>
        <p>Invite new users by email or add existing persistent accounts. Invited accounts activate only with a one-use invitation token.</p>
        {(selected.role === 'owner' || selected.role === 'admin') && <>
          <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
            const created = await api.createOrganizationInvitation(selected.id, String(form.get('email')), String(form.get('role')));
            setLatestInviteToken(created.token || '');
            await loadOrganization(selected.id);
          })}>
            <label>Invite email <input name="email" type="email" required maxLength={254} /></label>
            <label>Role <select name="role"><option value="member">Member</option><option value="auditor">Auditor</option><option value="viewer">Viewer</option><option value="admin">Admin</option></select></label>
            <button disabled={busy}>Send invitation</button>
          </form>
          {latestInviteToken && <p role="status">One-time invitation token (copy now, shown once): <code>{latestInviteToken}</code></p>}
          {invitations.length > 0 && <ul>{invitations.map((inv) => <li key={inv.id}>
            {inv.email_normalized} · {inv.role} · {inv.status} · expires {inv.expires_at}
            {inv.status === 'pending' && <button type="button" disabled={busy} onClick={async () => {
              try { await api.revokeOrganizationInvitation(selected.id, inv.id); await loadOrganization(selected.id); }
              catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Could not revoke invitation.'); }
            }}>Revoke</button>}
          </li>)}</ul>}
          <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
            await api.addOrganizationMember(selected.id, String(form.get('user_id')), String(form.get('role')));
            await loadOrganization(selected.id);
          })}>
            <label>Existing user ID <input name="user_id" required minLength={36} maxLength={36} /></label>
            <label>Role <select name="role"><option value="member">Member</option><option value="auditor">Auditor</option><option value="viewer">Viewer</option><option value="admin">Admin</option></select></label>
            <button disabled={busy}>Add member</button>
          </form>
        </>}
      </div>}
      {selected && <div style={panelStyle}>
        <h2>Clients</h2>
        {clients.length ? <ul>{clients.map((client) => <li key={client.id}>{client.name} · {client.status}{client.description ? ` · ${client.description}` : ''}</li>)}</ul> : <p>No clients yet.</p>}
        <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
          await api.createOrganizationClient(selected.id, String(form.get('name')), String(form.get('description') ?? ''));
          await loadOrganization(selected.id);
        })}>
          <label>Client name <input name="name" required maxLength={160} /></label>
          <label>Description <input name="description" maxLength={2000} /></label>
          <button disabled={busy}>Add client</button>
        </form>
      </div>}
      {selected && <div style={panelStyle}>
        <h2>Engagements</h2>
        {engagements.length ? <ul>{engagements.map((item) => <li key={item.id}>
          <button type="button" onClick={() => setSelectedEngagement(item.id)} aria-pressed={selectedEngagement === item.id}>{item.name}</button> · {item.status}
        </li>)}</ul> : <p>No engagements yet.</p>}
        <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
          const clientId = String(form.get('client_id') ?? '');
          await api.createOrganizationEngagement(selected.id, String(form.get('name')),
            String(form.get('description') ?? ''), clientId || null);
          await loadOrganization(selected.id);
        })}>
          <label>Engagement name <input name="name" required maxLength={160} /></label>
          <label>Client <select name="client_id"><option value="">No client</option>{clients.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
          <label>Description <input name="description" maxLength={4000} /></label>
          <button disabled={busy}>Create engagement</button>
        </form>
      </div>}
      {selected && selectedEngagement && <div style={panelStyle}>
        <h2>Assignments</h2>
        {assignments.length ? <ul>{assignments.map((item) => <li key={item.id}>
          {item.display_name ?? item.user_id} · {item.role} · {item.status}
          {item.status === 'active' && item.user_id !== selected.owner_user_id && <button type="button" onClick={async () => {
            try { await api.updateEngagementAssignment(selected.id, selectedEngagement, item.user_id, 'revoked');
              const result = await api.engagementAssignments(selected.id, selectedEngagement); setAssignments(result.items); }
            catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Could not revoke assignment.'); }
          }}>Revoke</button>}
        </li>)}</ul> : <p>No assignments.</p>}
        <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
          await api.createEngagementAssignment(selected.id, selectedEngagement,
            String(form.get('user_id')), String(form.get('role')));
          const result = await api.engagementAssignments(selected.id, selectedEngagement); setAssignments(result.items);
        })}>
          <label>Organization member <select name="user_id" required>{members.filter((item) => item.status === 'active').map((item) => <option key={item.user_id} value={item.user_id}>{item.display_name}</option>)}</select></label>
          <label>Role <select name="role"><option value="assessor">Assessor</option><option value="reviewer">Reviewer</option><option value="observer">Observer</option><option value="lead">Lead</option></select></label>
          <button disabled={busy || members.length === 0}>Assign member</button>
        </form>
      </div>}
      {selected && selectedEngagement && <EngagementSecurityWorkspace
        organizationId={selected.id} engagementId={selectedEngagement} onUnauthorized={onUnauthorized}
      />}
      {selected && selectedEngagement && <EngagementLogEvidenceWorkspace
        organizationId={selected.id} engagementId={selectedEngagement} onUnauthorized={onUnauthorized}
      />}
      <div style={panelStyle}>
        <h2>Account security</h2>
        {accountStatus && <p role="status">{accountStatus}</p>}
        <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
          const res = await api.changePassword(String(form.get('current_password')), String(form.get('new_password')));
          setCsrfToken(res.csrf_token);
          setAccountStatus('Password updated and other sessions invalidated.');
        })}>
          <label>Current password <input name="current_password" type="password" required /></label>
          <label>New password <input name="new_password" type="password" required minLength={12} maxLength={128} /></label>
          <button disabled={busy}>Change password</button>
        </form>
        {totp && <div style={{ marginTop: 12 }}>
          <p>Authenticator TOTP: <strong>{totp.totp_enabled ? 'Enabled' : 'Disabled'}</strong> · Recovery codes remaining: {totp.recovery_codes_remaining}</p>
          {!totp.totp_enabled && !pendingSecret && <button type="button" disabled={busy} onClick={async () => {
            try { const res = await api.totpEnroll(); setPendingSecret(res.secret); setAccountStatus(''); }
            catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not start TOTP enrollment.'); }
          }}>Enroll authenticator</button>}
          {pendingSecret && <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
            const res = await api.totpConfirm(String(form.get('code')));
            setPendingSecret(''); setRecoveryCodes(res.recovery_codes);
            setTotp(await api.totpStatus()); setAccountStatus('Authenticator enabled.');
          })}>
            <span>Secret: <code>{pendingSecret}</code></span>
            <label>Verification code <input name="code" required minLength={6} maxLength={64} /></label>
            <button disabled={busy}>Confirm TOTP</button>
          </form>}
          {totp.totp_enabled && <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
            const res = await api.totpRegenerateRecoveryCodes(String(form.get('code')));
            setRecoveryCodes(res.recovery_codes); setTotp(await api.totpStatus());
            setAccountStatus('Recovery codes regenerated.');
          })}>
            <label>TOTP code <input name="code" required minLength={6} maxLength={64} /></label>
            <button disabled={busy}>Regenerate recovery codes</button>
            <button type="button" disabled={busy} onClick={async (event) => {
              const form = event.currentTarget.form;
              const code = form ? String(new FormData(form).get('code') ?? '') : '';
              if (!code) { setError('Enter a current TOTP or recovery code.'); return; }
              try { await api.totpDisable(code); setTotp(await api.totpStatus()); setAccountStatus('Authenticator disabled.'); }
              catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not disable TOTP.'); }
            }}>Disable TOTP</button>
          </form>}
          {recoveryCodes.length > 0 && <p role="status">One-time recovery codes: <code>{recoveryCodes.join(' ')}</code></p>}
        </div>}
      </div>
    </section>
  </div>;
}
