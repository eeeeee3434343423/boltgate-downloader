import {
  AlertTriangle,
  ArrowRight,
  Ban,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Info,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  Zap,
} from 'lucide-react';
import { useState } from 'react';
import {
  type BulkApprovalEntry,
  buildBulkApprovalEntries,
  normalizeCapabilities,
} from '../../shared/compat';
import type { CompanionCapabilities, DownloadEngine, DownloadItem } from '../../shared/types';
import { categoryLabel, formatBytes, formatSpeed, riskMeta } from '../utils/format';

interface SafetyGateViewProps {
  items: DownloadItem[];
  capabilities: CompanionCapabilities;
  onRefreshCapabilities: () => Promise<void>;
  onApprove: (
    id: string,
    opts: {
      filename?: string;
      connections?: number;
      trustDomain?: boolean;
      engine?: DownloadEngine;
      selectFile?: string;
      expectedSha256?: string;
    }
  ) => Promise<void>;
  /** Bulk approval carrying each row's edits (SHA-256, torrent file selection, filename, …). */
  onApproveBatch: (entries: BulkApprovalEntry[]) => Promise<void>;
  onReject: (id: string, blockDomain?: boolean) => Promise<void>;
  onReprobe: (id: string) => Promise<void>;
  onInspectDrawer: (item: DownloadItem) => void;
  onRunBenchmark: () => Promise<void>;
  onFocusPaste: () => void;
}

export function SafetyGateView({
  items,
  capabilities: rawCapabilities,
  onRefreshCapabilities,
  onApprove,
  onApproveBatch,
  onReject,
  onReprobe,
  onInspectDrawer,
  onRunBenchmark,
  onFocusPaste,
}: SafetyGateViewProps) {
  const capabilities = normalizeCapabilities(rawCapabilities);
  const [editedNames, setEditedNames] = useState<Record<string, string>>({});
  const [editedConns, setEditedConns] = useState<Record<string, number>>({});
  const [editedEngines, setEditedEngines] = useState<Record<string, DownloadEngine>>({});
  const [editedSelectFiles, setEditedSelectFiles] = useState<Record<string, string>>({});
  const [editedExpectedSha256, setEditedExpectedSha256] = useState<Record<string, string>>({});
  const [expandedDetails, setExpandedDetails] = useState<Record<string, boolean>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const lowRiskIds = items
    .filter(
      (d) =>
        d.status === 'pending_review' &&
        d.safety?.riskLevel === 'safe' &&
        !(d.safety?.isP2P && !capabilities.aria2Available)
    )
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
              Every pasted URL, MD5 hash, IPFS CID, or torrent is resolved, benchmarked, and safety-checked before writing bytes to disk.
            </p>
          </div>
        </div>

        <div className="card empty-card">
          <div className="empty-icon">
            <ShieldCheck size={24} aria-hidden="true" />
          </div>
          <h2 style={{ margin: 0, fontSize: 17 }}>No links waiting for review</h2>
          <p style={{ margin: 0, maxWidth: 520, color: 'var(--text-muted)' }}>
            Paste any URL, Anna&apos;s Archive link or 32-char MD5, multi-line mirrors, <code className="mono">magnet:?</code>, or <code className="mono">ipfs://</code> URI above (or press <kbd>Ctrl+V</kbd> anywhere).
          </p>
          <div className="action-group" style={{ marginTop: 8, justifyContent: 'center' }}>
            <button type="button" className="btn btn-primary" onClick={onFocusPaste}>
              Paste a Source
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
            Review resolved sources, benchmarked throughput, and link evidence. Downloads start only when you deem them safe.
          </p>
        </div>

        {items.length >= 2 && (
          <div className="toolbar-group">
            {lowRiskIds.length > 0 && (
              <button
                type="button"
                className="btn btn-ok"
                onClick={() =>
                  void onApproveBatch(
                    buildBulkApprovalEntries(lowRiskIds, {
                      names: editedNames,
                      connections: editedConns,
                      engines: editedEngines,
                      selectFiles: editedSelectFiles,
                      expectedSha256: editedExpectedSha256,
                    })
                  )
                }
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
                    <div className="item-title">
                      {item.expectedMd5
                        ? `Resolving fast sources & benchmarking mirrors for MD5 ${item.expectedMd5.slice(0, 10)}…`
                        : `Inspecting ${item.filename}…`}
                    </div>
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
          const currentEngine = editedEngines[item.id] ?? item.engine ?? 'node';
          const currentSelectFile = editedSelectFiles[item.id] ?? item.selectFile ?? '';
          const currentExpectedSha256 = editedExpectedSha256[item.id] ?? item.expectedSha256 ?? '';
          const showDetails = Boolean(expandedDetails[item.id]);
          const isHighRisk = safety.riskLevel === 'high_risk' || safety.riskLevel === 'error';
          const isBusy = busyId === item.id;
          const p2pNeedsAria2 = Boolean(safety.isP2P && !capabilities.aria2Available);

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

                    {item.sourceBadge && (
                      <span className="badge badge-info">{item.sourceBadge}</span>
                    )}

                    {item.expectedMd5 && (
                      <span className="badge mono" title={`Expected MD5: ${item.expectedMd5}`}>
                        MD5: {item.expectedMd5.slice(0, 10)}…
                      </span>
                    )}

                    {(item.torrentInfoHash || safety.torrentInfoHash) && (
                      <span
                        className="badge badge-ok mono"
                        title={`Pinned Torrent InfoHash: ${item.torrentInfoHash ?? safety.torrentInfoHash}`}
                      >
                        Pinned: {(item.torrentInfoHash ?? safety.torrentInfoHash)!.slice(0, 10)}…
                      </span>
                    )}

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

                  {safety.mirrorReports && safety.mirrorReports.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 4 }}>
                      {safety.mirrorReports.length > 1 && (
                        <span className="badge badge-info num">
                          {safety.mirrorReports.filter((m) => m.included).length} /{' '}
                          {safety.mirrorReports.length} Sources Active
                        </span>
                      )}
                      {safety.mirrorReports.map((m, idx) => (
                        <span
                          key={`${m.url}-${idx}`}
                          className={`badge ${m.included ? 'badge-ok' : 'badge-warn'}`}
                          title={m.excludeReason ?? `Verified ${formatBytes(m.totalBytes)}`}
                        >
                          {m.label ?? m.host}
                          {m.probeSpeedBps && m.probeSpeedBps > 0 ? ` • ${formatSpeed(m.probeSpeedBps)}` : ''}
                          {!m.included ? ` (${m.excludeReason ?? 'Excluded'})` : ''}
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

              {p2pNeedsAria2 && (
                <div className="install-hint-box" style={{ marginTop: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                    <strong style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <Terminal size={14} aria-hidden="true" />
                      Install aria2c for Magnet / .torrent P2P ({capabilities.installHint.label})
                    </strong>
                    <div className="action-group">
                      <code className="mono">{capabilities.installHint.command}</code>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => {
                          void navigator.clipboard.writeText(capabilities.installHint.command);
                          setCopiedId(item.id);
                          setTimeout(() => setCopiedId((c) => (c === item.id ? null : c)), 1800);
                        }}
                      >
                        {copiedId === item.id ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
                        {copiedId === item.id ? 'Copied' : 'Copy'}
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => void onRefreshCapabilities()}
                      >
                        <RefreshCw size={13} aria-hidden="true" />
                        Re-check
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {item.torrentFiles && item.torrentFiles.length > 1 && (
                <div className="field" style={{ marginTop: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                    <span className="field-label">
                      Pinned Torrent Manifest Selection ({item.torrentFiles.length} files)
                    </span>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() =>
                          setEditedSelectFiles((prev) => ({ ...prev, [item.id]: '' }))
                        }
                      >
                        All Files
                      </button>
                    </div>
                  </div>
                  <div
                    className="signal-details-list"
                    style={{ marginTop: 4, maxHeight: 168, overflowY: 'auto', gap: 6 }}
                  >
                    {item.torrentFiles.map((tf) => {
                      const selectedSet = new Set(
                        currentSelectFile
                          ? currentSelectFile
                              .split(',')
                              .map((s) => Number(s.trim()))
                              .filter((n) => Number.isInteger(n))
                          : item.torrentFiles!.map((f) => f.index)
                      );
                      const checked = selectedSet.has(tf.index);
                      return (
                        <label
                          key={tf.index}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            fontSize: 12.5,
                            cursor: 'pointer',
                            minHeight: 24,
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => {
                              const next = new Set(selectedSet);
                              if (checked) {
                                if (next.size > 1) next.delete(tf.index);
                              } else {
                                next.add(tf.index);
                              }
                              const allSelected = next.size === item.torrentFiles!.length;
                              const spec = allSelected
                                ? ''
                                : Array.from(next)
                                    .sort((a, b) => a - b)
                                    .join(',');
                              setEditedSelectFiles((prev) => ({ ...prev, [item.id]: spec }));
                            }}
                          />
                          <span className="mono" style={{ flex: 1, wordBreak: 'break-all' }}>
                            #{tf.index}: {tf.path}
                          </span>
                          <span className="num" style={{ color: 'var(--text-muted)' }}>
                            {formatBytes(tf.length)}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>
              )}

              {!safety.isP2P && (
                <div className="field" style={{ marginTop: 8 }}>
                  <label htmlFor={`sha-${item.id}`} className="field-label" style={{ fontSize: 12 }}>
                    Expected SHA-256 (optional — verified before publishing)
                  </label>
                  <input
                    id={`sha-${item.id}`}
                    type="text"
                    className="input mono"
                    style={{ fontSize: 12 }}
                    placeholder="Paste optional 64-character SHA-256 digest to enforce before publish"
                    value={currentExpectedSha256}
                    onChange={(e) =>
                      setEditedExpectedSha256((prev) => ({ ...prev, [item.id]: e.target.value }))
                    }
                  />
                </div>
              )}

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
                      <span
                        className={`badge badge-${sig.level === 'ok' ? 'ok' : sig.level === 'warn' ? 'warn' : sig.level === 'danger' ? 'danger' : 'info'}`}
                      >
                        {sig.title}
                      </span>
                      <span>{sig.detail}</span>
                    </div>
                  ))}

                  {item.routingLog && item.routingLog.length > 0 && (
                    <div className="routing-log" style={{ marginTop: 6 }}>
                      {item.routingLog.map((entry, idx) => (
                        <div key={idx} className="routing-log-row">
                          <span className={`badge badge-${entry.level}`}>{entry.level.toUpperCase()}</span>
                          <span>{entry.message}</span>
                        </div>
                      ))}
                    </div>
                  )}
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

                  {capabilities.aria2Available && !safety.isP2P && (
                    <>
                      <label
                        htmlFor={`engine-${item.id}`}
                        style={{ fontSize: 12.5, color: 'var(--text-muted)', fontWeight: 600 }}
                      >
                        Engine:
                      </label>
                      <select
                        id={`engine-${item.id}`}
                        className="select"
                        style={{ minHeight: 32, padding: '2px 8px' }}
                        value={currentEngine}
                        onChange={(e) =>
                          setEditedEngines((prev) => ({
                            ...prev,
                            [item.id]: e.target.value as DownloadEngine,
                          }))
                        }
                      >
                        <option value="node">Pure Node Swarm</option>
                        <option value="aria2">aria2c (16 conn)</option>
                      </select>
                    </>
                  )}
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

                  {!isHighRisk && safety.domainTrust !== 'trusted' && !safety.isP2P && (
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={isBusy || p2pNeedsAria2}
                      onClick={async () => {
                        setBusyId(item.id);
                        try {
                          await onApprove(item.id, {
                            filename: currentFilename,
                            connections: currentConns,
                            trustDomain: true,
                            engine: currentEngine,
                            selectFile: currentSelectFile || undefined,
                            expectedSha256: currentExpectedSha256.trim() || undefined,
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
                    disabled={isBusy || p2pNeedsAria2}
                    onClick={async () => {
                      setBusyId(item.id);
                      try {
                        await onApprove(item.id, {
                          filename: currentFilename,
                          connections: currentConns,
                          trustDomain: false,
                          engine: currentEngine,
                          selectFile: currentSelectFile || undefined,
                          expectedSha256: currentExpectedSha256.trim() || undefined,
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
