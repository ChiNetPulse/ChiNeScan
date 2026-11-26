import { useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';

type ScannerStatus = {
  integration: string;
  enabled: boolean;
  configuration_ready: boolean;
  readiness_code: string | null;
  profiles: unknown[];
  approved_templates?: string[];
  target_types: string[];
};

export function ScannerWorkspace({
  organizationId,
  engagementId,
  onUnauthorized,
}: {
  organizationId: string;
  engagementId: string;
  onUnauthorized: () => void;
}) {
  const [statuses, setStatuses] = useState<ScannerStatus[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setStatuses([]);
    setError('');
    if (!organizationId || !engagementId) return () => { active = false; };
    Promise.all([api.nmapStatus(), api.nucleiStatus()])
      .then((values) => { if (active) setStatuses(values); })
      .catch((reason: unknown) => {
        if (reason instanceof UnauthorizedError) onUnauthorized();
        else if (active) setError(reason instanceof Error ? reason.message : 'Scanner status unavailable.');
      });
    return () => { active = false; };
  }, [organizationId, engagementId, onUnauthorized]);

  if (!organizationId || !engagementId) {
    return <section className="panel-card" aria-label="Governed scanner workspace"><h3>Governed Scanners</h3><p className="muted-copy">Select an active engagement to inspect scanner readiness.</p></section>;
  }
  return (
    <section className="panel-card" aria-label="Governed scanner workspace">
      <div className="panel-header-row"><div><h3>Governed Scanner Workspace</h3><p className="muted-copy">Only administrator-enabled, scope-bound integrations can execute. Status never grants execution permission.</p></div><span className="status-pill status-completed">Server-authorized</span></div>
      {error && <div className="alert-error" role="alert">{error}</div>}
      <div className="meta-grid">
        {statuses.map((status) => (
          <article key={status.integration} className="panel-card">
            <h4>{status.integration}</h4>
            <p><strong>{status.enabled ? (status.configuration_ready ? 'Ready for governed admission' : 'Enabled but blocked') : 'Disabled by administrator'}</strong></p>
            {status.readiness_code && <p className="muted-copy">Readiness: {status.readiness_code}</p>}
            <p className="muted-copy">Targets: {status.target_types.join(', ')} · Profiles: {status.profiles.length}</p>
            {status.approved_templates && <p className="muted-copy">Approved templates: {status.approved_templates.length}</p>}
          </article>
        ))}
      </div>
      <p className="muted-copy">Execution controls remain subject to membership, engagement assignment, immutable scope, approval, quota, and worker isolation checks.</p>
    </section>
  );
}
