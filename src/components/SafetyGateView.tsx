import {
  AlertTriangle,
  ArrowRight,
  Ban,
  Check,
  ChevronDown,
  ChevronUp,
  Info,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Zap,
} from 'lucide-react';
import { useState } from 'react';
import type { DownloadItem } from '../../shared/types';
import { categoryLabel, formatBytes, riskMeta } from '../utils/format';

interface SafetyGateViewProps {
  items: DownloadItem[];
  onApprove: (
    id: string,
    opts: { filename?: string; connections?: number; trustDomain?: boolean }
  ) => Promise<void>;
  onApproveBatch: (ids: string[]) => Promise<void>;
  onReject: (id: string, blockDomain?: boolean) => Promise<void>;
  onReprobe: (id: string) => Promise<void>;
  onInspectDrawer: (item: DownloadItem) => void;
  onRunBenchmark: () => Promise<void>;
  onFocusPaste: () => void;
}

export function SafetyGateView({
  items,
  onApprove,
  onApproveBatch,
  onReject,
  onReprobe,
  onInspectDrawer,
  onRunBenchmark,
  onFocusPaste,
}: SafetyGateViewProps) {
  const [editedNames, setEditedNames] = useState<Record<string, string>>({});
  const [editedConns, setEditedConns] = useState<Record<string, number>>({});
  const [expandedDetails, setExpandedDetails] = useState<Record<string, boolean>>({});
  const [busyId, setBusyId] = useState<string | null>(null);

  const lowRiskIds = items
    .filter((d) => d.status === 'pending_review' && d.safety?.riskLevel === 'safe')
    .map((d) => d.id);

  if (items.length === 0) {
    return (
      <section aria-labelledby="gate-heading">
        <div className="view-header">
          <div>
            <h1 id="gate-heading" className="view-title">
              Safety Gate
            </h1>
            <p className="view-subtitle">
              Every pasted link is inspected before a single byte of payload is written to disk.
            </p>
          </div>
        </div>

        <div className="card empty-card">
          <div className="empty-icon">
            <ShieldCheck size={24} aria-hidden="true" />
          </div>
          <h2 style={{ margin: 0, fontSize: 17 }}>No links waiting for review</h2>
          <p style={{ margin: 0, maxWidth: 480, color: 'var(--text-muted)' }}>
            Paste any URL above (or press <kbd>Ctrl+V</kbd> anywhere). BoltGate will inspect redirects,
            TLS certificates, true file types, and range acceleration before asking you to deem it safe.
          </p>
          <div className="action-group" style={{ marginTop: 8, justifyContent: 'center' }}>
            <button type="button" className="btn btn-primary" onClick={onFocusPaste}>
              Paste a Link
            </button>
            <button type="button" className="btn" onClick={() => void onRunBenchmark()}>
              <Zap size={15} aria-hidden="true" />
              Run 20 MB Local Speed Benchmark
            </button>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section aria-labelledby="gate-heading">
      <div className="view-header">
        <div>
          <h1 id="gate-heading" className="view-title">
            Safety Gate ({items.length})
          </h1>
          <p className="view-subtitle">
            Review link evidence below. Downloads start only when you deem them safe.
          </p>
        </div>

        {items.length >= 2 && (
          <div className="toolbar-group">
            {lowRiskIds.length > 0 && (
              <button
                type="button"
                className="btn btn-ok"
                onClick={() => void onApproveBatch(lowRiskIds)}
              >
                <Sparkles size={15} aria-hidden="true" />
                Deem {lowRiskIds.length} Low-Risk Safe
              </button>
            )}
          </div>
        )}
      </div>

      <div className="card-stack">
        {items.map((item) => {
          if (item.status === 'probing' || !item.safety) {
            return (
              <article key={item.id} className="card" aria-busy="true">
                <div className="card-top">
                  <div className="card-title-group">
                    <div className="item-title">Inspecting {item.filename}…</div>
                    <div className="url-trace mono">{item.originalUrl}</div>
                    <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                      <div className="skeleton-line" style={{ width: 120 }} />
                      <div className="skeleton-line" style={{ width: 140 }} />
                      <div className="skeleton-line" style={{ width: 100 }} />
                    </div>
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm btn-danger-ghost"
                    onClick={() => void onReject(item.id, false)}
                  >
                    <Trash2 size={14} aria-hidden="true" />
                    Cancel
                  </button>
                </div>
              </article>
            );
          }

          const safety = item.safety;
          const risk = riskMeta(safety.riskLevel);
          const currentFilename = editedNames[item.id] ?? item.filename;
          const currentConns = editedConns[item.id] ?? (item.supportsRanges ? item.connections : 1);
          const showDetails = Boolean(expandedDetails[item.id]);
          const isHighRisk = safety.riskLevel === 'high_risk' || safety.riskLevel === 'error';
          const isBusy = busyId === item.id;

          return (
            <article
              key={item.id}
              className={`card card-risk-${safety.riskLevel}`}
              aria-label={`Safety review for ${item.filename}`}
            >
              <div className="card-top">
                <div className="card-title-group">
                  <div className="filename-row">
                    <span className={`badge badge-${risk.tone}`}>
                      {isHighRisk ? (
                        <ShieldAlert size={13} aria-hidden="true" />
                      ) : safety.riskLevel === 'caution' ? (
                        <AlertTriangle size={13} aria-hidden="true" />
                      ) : (
                        <ShieldCheck size={13} aria-hidden="true" />
                      )}
                      {risk.label}
                    </span>

                    <label htmlFor={`fn-${item.id}`} className="sr-only">
                      Filename for {item.filename}
                    </label>
                    <input
                      id={`fn-${item.id}`}
                      type="text"
                      className="filename-input"
                      value={currentFilename}
                      onChange={(e) =>
                        setEditedNames((prev) => ({ ...prev, [item.id]: e.target.value }))
                      }
                    />
                  </div>

                  <div className="meta-line">
                    <span className="num" style={{ fontWeight: 600, color: 'var(--text)' }}>
                      {formatBytes(safety.totalBytes)}
                    </span>
                    <span>•</span>
                    <span>{categoryLabel(safety.category)}</span>
                    <span>•</span>
                    <span className="mono">
                      {safety.initialHost}
                      {safety.finalHost !== safety.initialHost && (
                        <>
                          {' '}
                          <ArrowRight size={12} style={{ verticalAlign: 'middle' }} aria-hidden="true" />{' '}
                          <strong>{safety.finalHost}</strong>
                        </>
                      )}
                    </span>
                    {safety.statusCode !== undefined && (
                      <>
                        <span>•</span>
                        <span className="num">HTTP {safety.statusCode}</span>
                      </>
                    )}
                  </div>

                  <div className="url-trace mono" title={safety.finalUrl}>
                    {safety.finalUrl}
                  </div>
                  {safety.mirrorReports && safety.mirrorReports.length > 1 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 4 }}>
                      <span className="badge badge-info">
                        {safety.mirrorReports.filter((m) => m.included).length} /{' '}
                        {safety.mirrorReports.length} Mirrors Verified
                      </span>
                      {safety.mirrorReports.map((m, idx) => (
                        <span
                          key={`${m.url}-${idx}`}
                          className={`badge ${m.included ? 'badge-ok' : 'badge-warn'}`}
                          title={m.excludeReason ?? `Verified ${formatBytes(m.totalBytes)}`}
                        >
                          {m.host}: {m.included ? 'Active Mirror' : m.excludeReason ?? 'Excluded'}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => onInspectDrawer(item)}
                >
                  Inspect Headers
                </button>
              </div>

              <div className="signal-grid" aria-label="Safety evidence signals">
                {safety.signals.map((sig) => (
                  <span
                    key={sig.id}
                    className={`signal-chip ${sig.level}`}
                    title={sig.detail}
                  >
                    {sig.level === 'ok' ? (
                      <Check size={13} aria-hidden="true" />
                    ) : sig.level === 'danger' ? (
                      <ShieldAlert size={13} aria-hidden="true" />
                    ) : sig.level === 'warn' ? (
                      <AlertTriangle size={13} aria-hidden="true" />
                    ) : (
                      <Info size={13} aria-hidden="true" />
                    )}
                    {sig.title}
                  </span>
                ))}
              </div>

              <div style={{ marginTop: 10 }}>
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-expanded={showDetails}
                  onClick={() =>
                    setExpandedDetails((prev) => ({ ...prev, [item.id]: !prev[item.id] }))
                  }
                >
                  {showDetails ? (
                    <>
                      <ChevronUp size={14} aria-hidden="true" /> Hide Evidence Details
                    </>
                  ) : (
                    <>
                      <ChevronDown size={14} aria-hidden="true" /> Why this rating? ({safety.signals.length} checks)
                    </>
                  )}
                </button>
              </div>

              {showDetails && (
                <div className="signal-details-list">
                  {safety.signals.map((sig) => (
                    <div key={sig.id} className="signal-detail-item">
                      <span className={`badge badge-${sig.level === 'ok' ? 'ok' : sig.level === 'warn' ? 'warn' : sig.level === 'danger' ? 'danger' : 'info'}`}>
                        {sig.title}
                      </span>
                      <span>{sig.detail}</span>
                    </div>
                  ))}
                </div>
              )}

              <div className="card-actions">
                <div className="action-group">
                  <label
                    htmlFor={`streams-${item.id}`}
                    style={{ fontSize: 12.5, color: 'var(--text-muted)', fontWeight: 600 }}
                  >
                    Streams:
                  </label>
                  <select
                    id={`streams-${item.id}`}
                    className="select"
                    style={{ minHeight: 32, padding: '2px 8px' }}
                    disabled={!item.supportsRanges}
                    value={currentConns}
                    onChange={(e) =>
                      setEditedConns((prev) => ({ ...prev, [item.id]: Number(e.target.value) }))
                    }
                  >
                    {[1, 2, 4, 8, 12, 16].map((n) => (
                      <option key={n} value={n}>
                        {n} {n === 1 ? 'stream' : 'streams'}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="action-group">
                  {safety.riskLevel === 'error' && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={isBusy}
                      onClick={async () => {
                        setBusyId(item.id);
                        try {
                          await onReprobe(item.id);
                        } finally {
                          setBusyId(null);
                        }
                      }}
                    >
                      <RefreshCw size={14} aria-hidden="true" />
                      Re-check
                    </button>
                  )}

                  <button
                    type="button"
                    className="btn btn-sm btn-danger-ghost"
                    disabled={isBusy}
                    onClick={async () => {
                      setBusyId(item.id);
                      try {
                        await onReject(item.id, true);
                      } finally {
                        setBusyId(null);
                      }
                    }}
                  >
                    <Ban size={14} aria-hidden="true" />
                    Block Domain
                  </button>

                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={isBusy}
                    onClick={async () => {
                      setBusyId(item.id);
                      try {
                        await onReject(item.id, false);
                      } finally {
                        setBusyId(null);
                      }
                    }}
                  >
                    <Trash2 size={14} aria-hidden="true" />
                    Reject
                  </button>

                  {!isHighRisk && safety.domainTrust !== 'trusted' && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={isBusy}
                      onClick={async () => {
                        setBusyId(item.id);
                        try {
                          await onApprove(item.id, {
                            filename: currentFilename,
                            connections: currentConns,
                            trustDomain: true,
                          });
                        } finally {
                          setBusyId(null);
                        }
                      }}
                    >
                      <ShieldCheck size={14} aria-hidden="true" />
                      Trust Domain &amp; Download
                    </button>
                  )}

                  <button
                    type="button"
                    className={`btn btn-sm ${isHighRisk ? 'btn-warn' : 'btn-ok'}`}
                    disabled={isBusy}
                    onClick={async () => {
                      setBusyId(item.id);
                      try {
                        await onApprove(item.id, {
                          filename: currentFilename,
                          connections: currentConns,
                          trustDomain: false,
                        });
                      } finally {
                        setBusyId(null);
                      }
                    }}
                  >
                    <Check size={14} aria-hidden="true" />
                    {isHighRisk ? 'I Trust This — Download' : 'Deem Safe & Download'}
                  </button>
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
