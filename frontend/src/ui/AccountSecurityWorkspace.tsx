import { useCallback, useEffect, useState } from 'react';
import { api, setCsrfToken, UnauthorizedError } from '../api';
import type { TotpStatus } from '../types';

type Props = {
  onUnauthorized: () => void;
  onAccountChanged?: () => void;
};

export function AccountSecurityWorkspace({ onUnauthorized, onAccountChanged }: Props) {
  const [me, setMe] = useState<{
    id: string;
    email_normalized: string;
    display_name: string;
    status: string;
    created_at: string;
  } | null>(null);
  const [totp, setTotp] = useState<TotpStatus | null>(null);
  const [pendingSecret, setPendingSecret] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [userResult, totpResult] = await Promise.all([
        api.currentUser().catch(() => null),
        api.totpStatus().catch(() => null),
      ]);
      setMe(userResult);
      setTotp(totpResult);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Could not load account status.');
    }
  }, [onUnauthorized]);

  useEffect(() => {
    void load();
  }, [load]);

  async function runAction(
    event: React.FormEvent<HTMLFormElement>,
    fn: (form: FormData) => Promise<void>
  ) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setStatusMessage('');
    const formEl = event.currentTarget;
    try {
      await fn(new FormData(formEl));
      formEl.reset();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Operation failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="workspace-stack" style={{ maxWidth: 960 }}>
      {error && <div className="alert-error" role="alert">{error}</div>}
      {statusMessage && <div className="status-banner" role="status">{statusMessage}</div>}

      <section className="panel-card" aria-label="Account profile and status">
        <h2>Account Profile & Status</h2>
        {me ? (
          <div className="meta-grid">
            <span>Email: <strong>{me.email_normalized}</strong></span>
            <span>Display name: <strong>{me.display_name}</strong></span>
            <span>Account status: <strong>{me.status}</strong></span>
            <span>User ID: <code>{me.id}</code></span>
          </div>
        ) : (
          <p className="muted-copy">Active local session authenticated.</p>
        )}
      </section>

      <section className="panel-card" aria-label="Password management">
        <h2>Change Password</h2>
        <form
          className="form-row"
          onSubmit={(event) =>
            void runAction(event, async (form) => {
              const res = await api.changePassword(
                String(form.get('current_password')),
                String(form.get('new_password'))
              );
              setCsrfToken(res.csrf_token);
              setStatusMessage('Password updated and session rotated.');
            })
          }
        >
          <label>
            Current password{' '}
            <input name="current_password" type="password" required autoComplete="current-password" />
          </label>
          <label>
            New password{' '}
            <input
              name="new_password"
              type="password"
              required
              minLength={16}
              autoComplete="new-password"
            />
          </label>
          <button disabled={busy}>Change password</button>
        </form>
      </section>

      <section className="panel-card" aria-label="Two-factor authentication">
        <h2>Two-Factor Authentication (TOTP)</h2>
        <p>
          Status:{' '}
          <strong>
            {totp?.totp_enabled
              ? `Enabled (${totp.recovery_codes_remaining} recovery codes remaining)`
              : 'Disabled'}
          </strong>
        </p>
        {!totp?.totp_enabled && (
          <div className="toolbar-inline">
            <button
              type="button"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setError('');
                try {
                  const enrolled = await api.totpEnroll();
                  setPendingSecret(enrolled.secret);
                  setStatusMessage('TOTP secret generated. Confirm with a 6-digit code from your authenticator.');
                } catch (reason) {
                  if (reason instanceof UnauthorizedError) onUnauthorized();
                  else setError(reason instanceof Error ? reason.message : 'TOTP enrollment failed.');
                } finally {
                  setBusy(false);
                }
              }}
            >
              Enroll TOTP
            </button>
          </div>
        )}
        {pendingSecret && (
          <form
            className="form-row"
            onSubmit={(event) =>
              void runAction(event, async (form) => {
                const confirmed = await api.totpConfirm(String(form.get('code')));
                setPendingSecret('');
                setRecoveryCodes(confirmed.recovery_codes);
                await load();
                setStatusMessage('TOTP enabled. Save your one-use recovery codes securely.');
              })
            }
          >
            <span>
              Enrollment secret: <code>{pendingSecret}</code>
            </span>
            <label>
              Verification code <input name="code" required minLength={6} maxLength={8} />
            </label>
            <button disabled={busy}>Confirm TOTP</button>
          </form>
        )}
        {totp?.totp_enabled && (
          <div className="workspace-stack">
            <form
              className="form-row"
              onSubmit={(event) =>
                void runAction(event, async (form) => {
                  const res = await api.totpRegenerateRecoveryCodes(String(form.get('code')));
                  setRecoveryCodes(res.recovery_codes);
                  await load();
                  setStatusMessage('Recovery codes regenerated. Previous unused codes are invalidated.');
                })
              }
            >
              <label>
                TOTP code{' '}
                <input name="code" required minLength={6} maxLength={8} />
              </label>
              <button disabled={busy}>Regenerate recovery codes</button>
            </form>
            <form
              className="form-row"
              onSubmit={(event) =>
                void runAction(event, async (form) => {
                  await api.totpDisable(String(form.get('code')));
                  setRecoveryCodes([]);
                  await load();
                  setStatusMessage('TOTP disabled.');
                })
              }
            >
              <label>
                Confirm disable with TOTP code{' '}
                <input name="code" required minLength={6} maxLength={8} />
              </label>
              <button disabled={busy}>Disable TOTP</button>
            </form>
          </div>
        )}
        {recoveryCodes.length > 0 && (
          <div className="status-banner" role="status">
            <strong>One-use recovery codes (not persisted in browser storage):</strong>{' '}
            <code>{recoveryCodes.join(' · ')}</code>
          </div>
        )}
      </section>

      <section className="panel-card" aria-label="Invitation acceptance">
        <h2>Accept Organization Invitation</h2>
        <p className="muted-copy">
          Accounts are invitation-only. Enter a one-use invitation token to join an organization.
        </p>
        <form
          className="form-row"
          onSubmit={(event) =>
            void runAction(event, async (form) => {
              const accepted = await api.acceptInvitation(
                String(form.get('token')),
                String(form.get('password') ?? '') || undefined,
                String(form.get('display_name') ?? '') || undefined
              );
              setCsrfToken(accepted.csrf_token);
              setStatusMessage(`Joined organization ${accepted.organization_id} as ${accepted.role}.`);
              onAccountChanged?.();
            })
          }
        >
          <label>
            Invitation token <input name="token" required />
          </label>
          <label>
            Display name (new account) <input name="display_name" />
          </label>
          <label>
            Password (new account, min 16 chars) <input name="password" type="password" />
          </label>
          <button disabled={busy}>Accept invitation</button>
        </form>
      </section>
    </div>
  );
}
