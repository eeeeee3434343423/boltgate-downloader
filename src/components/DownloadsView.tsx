import {
  Activity,
  ArrowDown,
  ArrowUp,
  ArrowUpToLine,
  ChevronDown,
  ChevronUp,
  Download,
  Eye,
  Pause,
  Play,
  RotateCcw,
  Trash2,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import type { DownloadItem, FileCategory } from '../../shared/types';
import { categoryLabel, formatBytes, formatEta, formatSpeed } from '../utils/format';

interface DownloadsViewProps {
  items: DownloadItem[];
  onPause: (id: string) => Promise<void>;
  onResume: (id: string, startNow?: boolean) => Promise<void>;
  onPriority: (id: string, action: 'top' | 'up' | 'down') => Promise<void>;
  onRemove: (id: string, deleteFile: boolean) => Promise<void>;
  onBulkAction: (action: 'pauseAll' | 'resumeAll' | 'retryFailed') => Promise<void>;
  onInspectDrawer: (item: DownloadItem) => void;
  onGoToGate: () => void;
}

type StatusFilter = 'all' | 'active' | 'queued' | 'paused' | 'failed';

export function DownloadsView({
  items,
  onPause,
  onResume,
  onPriority,
  onRemove,
  onBulkAction,
  onInspectDrawer,
  onGoToGate,
}: DownloadsViewProps) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [categoryFilter, setCategoryFilter] = useState<'all' | FileCategory>('all');
  const [expandedTelemetry, setExpandedTelemetry] = useState<Record<string, boolean>>({});

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items
      .filter((item) => {
        if (statusFilter === 'active' && item.status !== 'downloading' && item.status !== 'verifying') {
          return false;
        }
        if (statusFilter !== 'all' && statusFilter !== 'active' && item.status !== statusFilter) {
          return false;
        }
        if (categoryFilter !== 'all' && item.category !== categoryFilter) {
          return false;
        }
        if (q && !item.filename.toLowerCase().includes(q) && !item.finalUrl.toLowerCase().includes(q)) {
          return false;
        }
        return true;
      })
      .sort((a, b) => {
        const rank = (s: DownloadItem['status']) =>
          s === 'downloading' || s === 'verifying' ? 0 : s === 'queued' ? 1 : s === 'paused' ? 2 : 3;
        const dr = rank(a.status) - rank(b.status);
        return dr !== 0 ? dr : a.priority - b.priority;
      });
  }, [items, search, statusFilter, categoryFilter]);

  const hasActive = items.some((i) => i.status === 'downloading' || i.status === 'queued');
  const hasPaused = items.some((i) => i.status === 'paused');
  const hasFailed = items.some((i) => i.status === 'failed');

  return (
    <section aria-labelledby="downloads-heading">
      <div className="view-header">
        <div>
          <h1 id="downloads-heading" className="view-title">
            Downloads ({items.length})
          </h1>
          <p className="view-subtitle">
            Adaptive multi-mirror swarming, rolling speed-floor switching, .part.meta crash resume, and work-stealing.
          </p>
        </div>

        {items.length > 0 && (
          <div className="toolbar-group">
            {hasActive && (
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => void onBulkAction('pauseAll')}
              >
                <Pause size={14} aria-hidden="true" />
                Pause All
              </button>
            )}
            {hasPaused && (
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={() => void onBulkAction('resumeAll')}
              >
                <Play size={14} aria-hidden="true" />
                Resume All
              </button>
            )}
            {hasFailed && (
              <button
                type="button"
                className="btn btn-sm btn-warn"
                onClick={() => void onBulkAction('retryFailed')}
              >
                <RotateCcw size={14} aria-hidden="true" />
                Retry Failed
              </button>
            )}
          </div>
        )}
      </div>

      {items.length > 0 && (
        <div className="toolbar">
          <div className="toolbar-group">
            <label htmlFor="dl-search" className="sr-only">
              Search active downloads
            </label>
            <input
              id="dl-search"
              type="search"
              className="input"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter filename or URL…"
            />

            <label htmlFor="dl-cat-filter" className="sr-only">
              Filter by category
            </label>
            <select
              id="dl-cat-filter"
              className="select"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as 'all' | FileCategory)}
            >
              <option value="all">All categories</option>
              <option value="ebook">Ebook</option>
              <option value="video">Video</option>
              <option value="audio">Audio</option>
              <option value="archive">Archive</option>
              <option value="disk">Disk Image</option>
              <option value="software">Software</option>
              <option value="document">Document</option>
              <option value="image">Image</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div className="pill-tabs" role="group" aria-label="Status filter">
            {(['all', 'active', 'queued', 'paused', 'failed'] as StatusFilter[]).map((st) => (
              <button
                key={st}
                type="button"
                className={`pill-tab ${statusFilter === st ? 'active' : ''}`}
                onClick={() => setStatusFilter(st)}
              >
                {st[0]!.toUpperCase() + st.slice(1)}
              </button>
            ))}
          </div>
        </div>
      )}

      {items.length === 0 ? (
        <div className="card empty-card">
          <div className="empty-icon">
            <Download size={24} aria-hidden="true" />
          </div>
          <h2 style={{ margin: 0, fontSize: 17 }}>No active or queued downloads</h2>
          <p style={{ margin: 0, maxWidth: 440, color: 'var(--text-muted)' }}>
            Paste a link above or approve pending items in the Safety Gate to start multi-stream downloading.
          </p>
          <button type="button" className="btn btn-primary" onClick={onGoToGate}>
            Open Safety Gate
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="card empty-card">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>No downloads match your current filters.</p>
        </div>
      ) : (
        <div className="card-stack">
          {filtered.map((item) => {
            const pct =
              item.totalBytes && item.totalBytes > 0
                ? Math.min(100, Math.round((item.downloadedBytes / item.totalBytes) * 100))
                : 0;
            const activeWorkers =
              item.segments.filter((s) => s.status === 'active').length ||
              item.mirrorTelemetry?.reduce((sum, m) => sum + m.activeWorkers, 0) ||
              0;
            const activeMirrorsCount =
              item.mirrorTelemetry?.filter((m) => m.activeWorkers > 0).length ?? 0;
            const latestRoute =
              item.routingLog && item.routingLog.length > 0
                ? item.routingLog[item.routingLog.length - 1]
                : null;
            const hasTelemetryDetails = Boolean(
              (item.mirrorTelemetry && item.mirrorTelemetry.length > 0) ||
                (item.routingLog && item.routingLog.length > 0)
            );
            const isExpanded = Boolean(expandedTelemetry[item.id]);

            let displayHost = item.safety?.finalHost ?? 'source';
            if (!item.safety?.finalHost) {
              try {
                displayHost = new URL(item.finalUrl).hostname || 'source';
              } catch {
                displayHost = 'p2p';
              }
            }

            return (
              <article key={item.id} className="card">
                <div className="card-top">
                  <div className="card-title-group">
                    <div className="filename-row">
                      <span className="item-title">{item.filename}</span>
                      <span
                        className={`badge ${
                          item.status === 'downloading'
                            ? 'badge-info'
                            : item.status === 'verifying'
                              ? 'badge-ok'
                              : item.status === 'paused'
                                ? 'badge-warn'
                                : item.status === 'failed'
                                  ? 'badge-danger'
                                  : ''
                        }`}
                      >
                        {item.status === 'verifying'
                          ? 'Verifying MD5 & SHA-256'
                          : item.status === 'downloading'
                            ? `Downloading (${activeWorkers} worker${activeWorkers === 1 ? '' : 's'})`
                            : item.status[0]!.toUpperCase() + item.status.slice(1)}
                      </span>
                      <span className="badge">{categoryLabel(item.category)}</span>
                      {item.sourceBadge && (
                        <span className="badge badge-info num">{item.sourceBadge}</span>
                      )}
                      {item.sourceProvenance && (
                        <span className="badge mono" title={`Provenance: ${item.sourceProvenance}`}>
                          {item.sourceProvenance}
                        </span>
                      )}
                      {activeMirrorsCount >= 2 && !item.sourceBadge?.includes('Swarming') && (
                        <span className="badge badge-info num">
                          Swarming {activeMirrorsCount} mirrors
                        </span>
                      )}
                      {item.telemetry?.throttledByLocalCap && (
                        <span className="badge badge-warn num">
                          Local cap ({formatSpeed(item.telemetry.localCapBps)})
                        </span>
                      )}
                      {item.telemetry && item.telemetry.backingOffHosts.length > 0 && (
                        <span className="badge badge-warn">
                          Backoff: {item.telemetry.backingOffHosts.join(', ')}
                        </span>
                      )}
                    </div>

                    <div className="meta-line num">
                      <span>
                        {formatBytes(item.downloadedBytes)} / {formatBytes(item.totalBytes)} ({pct}%)
                      </span>
                      {item.status === 'downloading' && (
                        <>
                          <span>•</span>
                          <strong style={{ color: 'var(--accent-text)' }}>
                            Net {formatSpeed(item.telemetry?.networkSpeedBps ?? item.speedBps)}
                          </strong>
                          {item.telemetry && item.telemetry.diskSpeedBps > 0 && (
                            <>
                              <span>•</span>
                              <span>Disk {formatSpeed(item.telemetry.diskSpeedBps)}</span>
                            </>
                          )}
                          <span>•</span>
                          <span>ETA {formatEta(item.etaSeconds)}</span>
                        </>
                      )}
                      <span>•</span>
                      <span className="mono">{displayHost}</span>
                    </div>
                  </div>

                  <div className="action-group">
                    {(item.status === 'downloading' || item.status === 'queued') && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => void onPause(item.id)}
                      >
                        <Pause size={14} aria-hidden="true" />
                        Pause
                      </button>
                    )}

                    {(item.status === 'paused' || item.status === 'failed') && (
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        onClick={() => void onResume(item.id)}
                      >
                        {item.status === 'failed' ? (
                          <>
                            <RotateCcw size={14} aria-hidden="true" /> Retry
                          </>
                        ) : (
                          <>
                            <Play size={14} aria-hidden="true" /> Resume
                          </>
                        )}
                      </button>
                    )}

                    {(item.status === 'queued' || item.status === 'paused') && (
                      <>
                        <button
                          type="button"
                          className="btn btn-sm btn-icon"
                          title="Start immediately"
                          aria-label={`Start ${item.filename} immediately`}
                          onClick={() => void onResume(item.id, true)}
                        >
                          <ArrowUpToLine size={14} aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          className="btn btn-sm btn-icon"
                          title="Move up in queue"
                          aria-label={`Move ${item.filename} up in queue`}
                          onClick={() => void onPriority(item.id, 'up')}
                        >
                          <ArrowUp size={14} aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          className="btn btn-sm btn-icon"
                          title="Move down in queue"
                          aria-label={`Move ${item.filename} down in queue`}
                          onClick={() => void onPriority(item.id, 'down')}
                        >
                          <ArrowDown size={14} aria-hidden="true" />
                        </button>
                      </>
                    )}

                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => onInspectDrawer(item)}
                    >
                      <Eye size={14} aria-hidden="true" />
                      Inspect
                    </button>

                    <button
                      type="button"
                      className="btn btn-sm btn-danger-ghost btn-icon"
                      title="Remove from list"
                      aria-label={`Remove ${item.filename}`}
                      onClick={() => void onRemove(item.id, false)}
                    >
                      <Trash2 size={14} aria-hidden="true" />
                    </button>
                  </div>
                </div>

                <div className="progress-wrap">
                  <div
                    className="progress-track"
                    role="progressbar"
                    aria-label={`Progress for ${item.filename}`}
                    aria-valuenow={pct}
                    aria-valuemin={0}
                    aria-valuemax={100}
                  >
                    <div
                      className={`progress-fill ${item.status}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>

                  {item.segments.length > 1 && (
                    <div
                      className="segments-strip"
                      title={`${item.segments.length} parallel segment lanes`}
                      aria-hidden="true"
                    >
                      {item.segments.map((seg) => {
                        const segTotal = seg.end >= 0 ? seg.end - seg.start + 1 : 0;
                        const segPct =
                          segTotal > 0 ? Math.min(100, (seg.downloaded / segTotal) * 100) : 0;
                        return (
                          <div key={seg.id} className="segment-lane">
                            <div
                              className={`segment-lane-fill ${seg.status}`}
                              style={{ width: `${segPct}%` }}
                            />
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {latestRoute && (
                  <div className="route-summary-line">
                    <Activity size={13} aria-hidden="true" />
                    <span>{latestRoute.message}</span>
                  </div>
                )}

                {hasTelemetryDetails && (
                  <div style={{ marginTop: 8 }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      aria-expanded={isExpanded}
                      onClick={() =>
                        setExpandedTelemetry((prev) => ({ ...prev, [item.id]: !prev[item.id] }))
                      }
                    >
                      {isExpanded ? (
                        <>
                          <ChevronUp size={14} aria-hidden="true" /> Hide Sources &amp; Routing Log
                        </>
                      ) : (
                        <>
                          <ChevronDown size={14} aria-hidden="true" /> Sources &amp; Routing Log
                          {item.mirrorTelemetry && item.mirrorTelemetry.length > 0
                            ? ` (${item.mirrorTelemetry.length})`
                            : ''}
                        </>
                      )}
                    </button>

                    {isExpanded && (
                      <div className="signal-details-list">
                        {item.mirrorTelemetry && item.mirrorTelemetry.length > 0 && (
                          <table className="kv-table source-breakdown-table">
                            <thead>
                              <tr>
                                <th>Source</th>
                                <th>Status</th>
                                <th>Workers</th>
                                <th>Downloaded</th>
                                <th>Speed</th>
                              </tr>
                            </thead>
                            <tbody>
                              {item.mirrorTelemetry.map((m, idx) => (
                                <tr key={`${m.url}-${idx}`}>
                                  <td>
                                    <div style={{ fontWeight: 600 }}>{m.label}</div>
                                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                      {m.host} ({m.tier})
                                    </div>
                                  </td>
                                  <td>
                                    <span
                                      className={`badge ${
                                        m.status === 'active'
                                          ? 'badge-ok'
                                          : m.status === 'evicted' || m.status === 'cooldown'
                                            ? 'badge-warn'
                                            : m.status === 'failed'
                                              ? 'badge-danger'
                                              : ''
                                      }`}
                                    >
                                      {m.status}
                                    </span>
                                  </td>
                                  <td className="num">{m.activeWorkers}</td>
                                  <td className="num">{formatBytes(m.downloadedBytes)}</td>
                                  <td className="num">{formatSpeed(m.speedBps)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}

                        {item.routingLog && item.routingLog.length > 0 && (
                          <div className="routing-log">
                            {item.routingLog.map((entry, idx) => (
                              <div key={idx} className="routing-log-row">
                                <span className="mono num" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                  {new Date(entry.timestamp).toLocaleTimeString()}
                                </span>
                                <span className={`badge badge-${entry.level}`}>{entry.level.toUpperCase()}</span>
                                <span>{entry.message}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {item.status === 'downloading' &&
                  item.startedAt &&
                  Date.now() - item.startedAt > 4000 &&
                  item.speedBps > 0 &&
                  item.speedBps < 512 * 1024 &&
                  (!item.mirrorTelemetry || item.mirrorTelemetry.length <= 1) && (
                    <div
                      className="badge badge-warn"
                      style={{ marginTop: 8, borderRadius: 8, padding: '6px 10px', whiteSpace: 'normal' }}
                    >
                      {!item.supportsRanges
                        ? 'Host disabled byte-range acceleration (single stream) — transfer speed is capped by the remote server.'
                        : `Remote mirror is serving at ${formatSpeed(item.speedBps)} across ${activeWorkers} worker(s) (likely server-side bandwidth cap). Paste an Anna’s Archive link/MD5 or combine alternate direct mirrors for MB/s speeds.`}
                    </div>
                  )}

                {item.error && (
                  <div
                    className="badge badge-danger"
                    style={{ marginTop: 10, borderRadius: 8, padding: '6px 10px' }}
                  >
                    {item.error}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
