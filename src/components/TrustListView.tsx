import { Ban, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import { useMemo, useState, type FormEvent } from 'react';
import type { TrustRule } from '../../shared/types';

interface TrustListViewProps {
  rules: TrustRule[];
  onUpsert: (domain: string, status: 'trusted' | 'blocked', note: string) => Promise<void>;
  onDelete: (rule: TrustRule) => Promise<void>;
}

export function TrustListView({ rules, onUpsert, onDelete }: TrustListViewProps) {
  const [domainInput, setDomainInput] = useState('');
  const [statusInput, setStatusInput] = useState<'trusted' | 'blocked'>('trusted');
  const [noteInput, setNoteInput] = useState('');
  const [filter, setFilter] = useState<'all' | 'trusted' | 'blocked'>('all');
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rules.filter((r) => {
      if (filter !== 'all' && r.status !== filter) return false;
      if (q && !r.domain.toLowerCase().includes(q) && !r.note.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [rules, filter, search]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await onUpsert(domainInput, statusInput, noteInput);
      setDomainInput('');
      setNoteInput('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save domain rule');
    }
  };

  return (
    <section aria-labelledby="trust-heading">
      <div className="view-header">
        <div>
          <h1 id="trust-heading" className="view-title">
            Trust List ({rules.length})
          </h1>
          <p className="view-subtitle">
            Manage domains you explicitly trust or block during Safety Gate inspection.
          </p>
        </div>
      </div>

      <form className="card" onSubmit={handleSubmit} style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="field" style={{ flex: '1 1 220px' }}>
            <label htmlFor="trust-domain-in" className="field-label">
              Domain or Host
            </label>
            <input
              id="trust-domain-in"
              type="text"
              className="input"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="e.g. github.com or releases.ubuntu.com"
            />
          </div>

          <div className="field" style={{ flex: '0 1 150px' }}>
            <label htmlFor="trust-status-in" className="field-label">
              Rule Type
            </label>
            <select
              id="trust-status-in"
              className="select"
              value={statusInput}
              onChange={(e) => setStatusInput(e.target.value as 'trusted' | 'blocked')}
            >
              <option value="trusted">Trusted</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>

          <div className="field" style={{ flex: '1 1 220px' }}>
            <label htmlFor="trust-note-in" className="field-label">
              Note (optional)
            </label>
            <input
              id="trust-note-in"
              type="text"
              className="input"
              value={noteInput}
              onChange={(e) => setNoteInput(e.target.value)}
              placeholder="Why you trust or block this host"
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={!domainInput.trim()}>
            <Plus size={15} aria-hidden="true" />
            Add Rule
          </button>
        </div>

        {error && (
          <div style={{ marginTop: 8, color: 'var(--danger)', fontSize: 12.5 }} role="alert">
            {error}
          </div>
        )}
      </form>

      {rules.length > 0 && (
        <div className="toolbar">
          <div className="toolbar-group">
            <label htmlFor="trust-search" className="sr-only">
              Search domain rules
            </label>
            <input
              id="trust-search"
              type="search"
              className="input"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter domains…"
            />
          </div>

          <div className="pill-tabs" role="group" aria-label="Filter trust rules">
            {(['all', 'trusted', 'blocked'] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                className={`pill-tab ${filter === tab ? 'active' : ''}`}
                onClick={() => setFilter(tab)}
              >
                {tab[0]!.toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="card empty-card">
          <div className="empty-icon">
            <ShieldCheck size={24} aria-hidden="true" />
          </div>
          <h2 style={{ margin: 0, fontSize: 17 }}>No custom domain rules yet</h2>
          <p style={{ margin: 0, maxWidth: 460, color: 'var(--text-muted)' }}>
            Add trusted publishers here or use &ldquo;Trust Domain &amp; Download&rdquo; directly inside the Safety Gate.
          </p>
        </div>
      ) : (
        <div className="card-stack">
          {filtered.map((rule) => (
            <article key={rule.domain} className="card">
              <div className="card-top">
                <div className="card-title-group">
                  <div className="filename-row">
                    <span className="item-title mono">{rule.domain}</span>
                    {rule.status === 'trusted' ? (
                      <span className="badge badge-ok">
                        <ShieldCheck size={12} aria-hidden="true" />
                        Trusted
                      </span>
                    ) : (
                      <span className="badge badge-danger">
                        <Ban size={12} aria-hidden="true" />
                        Blocked
                      </span>
                    )}
                  </div>
                  {rule.note && (
                    <div style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>{rule.note}</div>
                  )}
                </div>

                <div className="action-group">
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() =>
                      void onUpsert(
                        rule.domain,
                        rule.status === 'trusted' ? 'blocked' : 'trusted',
                        rule.note
                      )
                    }
                  >
                    Switch to {rule.status === 'trusted' ? 'Blocked' : 'Trusted'}
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-danger-ghost btn-icon"
                    aria-label={`Delete rule for ${rule.domain}`}
                    onClick={() => void onDelete(rule)}
                  >
                    <Trash2 size={14} aria-hidden="true" />
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
