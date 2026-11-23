import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { Client, Engagement, EngagementAssignment, Organization, OrganizationMember } from '../types';

export function OrganizationsWorkspace({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [items, setItems] = useState<Organization[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [clients, setClients] = useState<Client[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
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
      const [clientResult, engagementResult, memberResult] = await Promise.all([
        api.organizationClients(id), api.organizationEngagements(id), api.organizationMembers(id),
      ]);
      setClients(clientResult.items); setEngagements(engagementResult.items); setMembers(memberResult.items);
      setSelectedEngagement((current) => engagementResult.items.some((item) => item.id === current)
        ? current : engagementResult.items[0]?.id ?? '');
      setError('');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load organization details.');
    }
  }, [onUnauthorized]);

  useEffect(() => { void load(); }, [load]);
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
        <p>Members can be added when their persistent user account already exists. Invitations and signup are not part of Phase 1B.</p>
        {(selected.role === 'owner' || selected.role === 'admin') && <form style={formStyle} onSubmit={(event) => void submit(event, async (form) => {
          await api.addOrganizationMember(selected.id, String(form.get('user_id')), String(form.get('role')));
          await loadOrganization(selected.id);
        })}>
          <label>Existing user ID <input name="user_id" required minLength={36} maxLength={36} /></label>
          <label>Role <select name="role"><option value="member">Member</option><option value="auditor">Auditor</option><option value="viewer">Viewer</option><option value="admin">Admin</option></select></label>
          <button disabled={busy}>Add member</button>
        </form>}
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
    </section>
  </div>;
}
