import {
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FolderOpen,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import type { DownloadItem, FileCategory } from '../../shared/types';
import { categoryLabel, formatBytes, formatRelativeTime, formatSpeed } from '../utils/format';

interface CompletedViewProps {
  items: DownloadItem[];
  onOpenFolder: (id: string) => Promise<void>;
  onOpenFile: (id: string) => Promise<void>;
  onVerifyHash: (id: string, expectedHash: string) => Promise<{ match: boolean; actual: string }>;
  onRedownload: (id: string) => Promise<void>;
  onRemove: (id: string, deleteFile: boolean) => Promise<void>;
  onClearCompleted: () => Promise<void>;
  onInspectDrawer: (item: DownloadItem) => void;
}

export function CompletedView({
  items,
  onOpenFolder,
  onOpenFile,
  onVerifyHash,
  onRedownload,
  onRemove,
  onClearCompleted,
  onInspectDrawer,
}: CompletedViewProps) {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'all' | FileCategory>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [verifyOpenId, setVerifyOpenId] = useState<string | null>(null);
  const [hashInput, setHashInput] = useState<Record<string, string>>({});
  const [hashError, setHashError] = useState<Record<string, string>>({});

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items
      .filter((item) => {
        if (categoryFilter !== 'all' && item.category !== categoryFilter) return false;
        if (q && !item.filename.toLowerCase().includes(q) && !item.finalUrl.toLowerCase().includes(q)) {
          return false;
        }
        return true;
      })
      .sort((a, b) => (b.completedAt ?? b.createdAt) - (a.completedAt ?? a.createdAt));
  }, [items, search, categoryFilter]);

  const copyText = async (id: string, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
  };

  return (
    <section aria-labelledby="completed-heading">
      <div className="view-header">
        <div>
          <h1 id="completed-heading" className="view-title">
            Completed ({items.length})
          </h1>
          <p className="view-subtitle">
            Verified files with automatic MD5 &amp; SHA-256 checksums, format checks, and safe folder launch.
          </p>
        </div>

        {items.length > 0 && (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void onClearCompleted()}
          >
            <Trash2 size={14} aria-hidden="true" />
            Clear List
          </button>
        )}
      </div>

      {items.length > 0 && (
        <div className="toolbar">
          <div className="toolbar-group">
            <label htmlFor="comp-search" className="sr-only">
              Search completed downloads
            </label>
            <input
              id="comp-search"
              type="search"
              className="input"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search completed files…"
            />

            <label htmlFor="comp-cat" className="sr-only">
              Filter completed by category
            </label>
            <select
              id="comp-cat"
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
        </div>
      )}

      {items.length === 0 ? (
        <div className="card empty-card">
          <div className="empty-icon">
            <CheckCircle2 size={24} aria-hidden="true" />
          </div>
          <h2 style={{ margin: 0, fontSize: 17 }}>No completed downloads yet</h2>
          <p style={{ margin: 0, maxWidth: 440, color: 'var(--text-muted)' }}>
            Finished downloads appear here with their MD5 / SHA-256 checksums and direct folder access.
          </p>
        </div>
      ) : (
        <div className="card-stack">
          {filtered.map((item) => {
            const isExec = Boolean(item.safety?.isExecutable);
            const isVerifyOpen = verifyOpenId === item.id;
            const integrity = item.integrity;
            const isBroken =
              integrity?.status === 'html_trap' || integrity?.status === 'corrupted';

            return (
              <article
                key={item.id}
                className={`card ${isBroken ? 'card-risk-high_risk' : ''}`}
              >
                <div className="card-top">
                  <div className="card-title-group">
                    <div className="filename-row">
                      <span className="item-title">{item.filename}</span>
                      <span className="badge badge-ok">Completed</span>
                      <span className="badge">{categoryLabel(item.category)}</span>
                      {item.sourceBadge && (
                        <span className="badge badge-info">{item.sourceBadge}</span>
                      )}
                      {item.md5Verified === true && (
                        <span className="badge badge-ok" title={`Verified MD5 ${item.md5 ?? ''}`}>
                          <ShieldCheck size={12} aria-hidden="true" />
                          MD5 Verified
                        </span>
                      )}
                      {item.md5Verified === false && (
                        <span className="badge badge-danger">
                          <ShieldAlert size={12} aria-hidden="true" />
                          MD5 Mismatch
                        </span>
                      )}
                      {integrity?.status === 'valid' && (
                        <span className="badge badge-ok" title={integrity.summary}>
                          <ShieldCheck size={12} aria-hidden="true" />
                          {integrity.format} Verified
                        </span>
                      )}
                      {integrity?.status === 'html_trap' && (
                        <span className="badge badge-danger" title={integrity.summary}>
                          <ShieldAlert size={12} aria-hidden="true" />
                          HTML Trap — Not a Book!
                        </span>
                      )}
                      {integrity?.status === 'corrupted' && (
                        <span className="badge badge-danger" title={integrity.summary}>
                          <ShieldAlert size={12} aria-hidden="true" />
                          Corrupted / Truncated
                        </span>
                      )}
                      {isExec && (
                        <span className="badge badge-warn">
                          <ShieldAlert size={12} aria-hidden="true" />
                          Executable
                        </span>
                      )}
                    </div>

                    <div className="meta-line num">
                      <strong>{formatBytes(item.totalBytes)}</strong>
                      <span>•</span>
                      <span>Avg {formatSpeed(item.avgSpeedBps)}</span>
                      <span>•</span>
                      <span>{formatRelativeTime(item.completedAt)}</span>
                      <span>•</span>
                      <span className="mono">{item.savedPath}</span>
                    </div>

                    {item.verifiedFilePath && (item.publishedFiles?.length ?? 0) > 1 && (
                      <div className="meta-line" style={{ marginTop: 4 }}>
                        <span style={{ fontWeight: 600 }}>Checksums &amp; Open apply to:</span>
                        <code className="mono" style={{ wordBreak: 'break-all' }}>
                          {item.verifiedFileIndex ? `#${item.verifiedFileIndex} ` : ''}
                          {item.verifiedFilePath}
                        </code>
                      </div>
                    )}

                    {item.md5 && (
                      <div className="meta-line" style={{ marginTop: 4 }}>
                        <span style={{ fontWeight: 600 }}>MD5:</span>
                        <code className="mono" style={{ wordBreak: 'break-all' }}>
                          {item.md5}
                        </code>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void copyText(`${item.id}-md5`, item.md5!)}
                        >
                          {copiedId === `${item.id}-md5` ? (
                            <>
                              <Check size={13} aria-hidden="true" /> Copied
                            </>
                          ) : (
                            <>
                              <Copy size={13} aria-hidden="true" /> Copy
                            </>
                          )}
                        </button>
                      </div>
                    )}

                    {item.sha256 && (
                      <div className="meta-line" style={{ marginTop: 4 }}>
                        <span style={{ fontWeight: 600 }}>SHA-256:</span>
                        <code className="mono" style={{ wordBreak: 'break-all' }}>
                          {item.sha256}
                        </code>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void copyText(item.id, item.sha256!)}
                        >
                          {copiedId === item.id ? (
                            <>
                              <Check size={13} aria-hidden="true" /> Copied
                            </>
                          ) : (
                            <>
                              <Copy size={13} aria-hidden="true" /> Copy
                            </>
                          )}
                        </button>
                        {item.verifiedHashMatch === true && (
                          <span className="badge badge-ok">Exact Match</span>
                        )}
                        {item.verifiedHashMatch === false && (
                          <span className="badge badge-danger">Checksum Mismatch</span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="action-group">
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      onClick={() => void onOpenFolder(item.id)}
                    >
                      <FolderOpen size={14} aria-hidden="true" />
                      Show in Folder
                    </button>

                    {!isExec && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => void onOpenFile(item.id)}
                      >
                        <ExternalLink size={14} aria-hidden="true" />
                        Open
                      </button>
                    )}

                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => setVerifyOpenId(isVerifyOpen ? null : item.id)}
                    >
                      <ShieldCheck size={14} aria-hidden="true" />
                      Verify Checksum
                    </button>

                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => onInspectDrawer(item)}
                    >
                      Details
                    </button>

                    <button
                      type="button"
                      className="btn btn-sm btn-icon"
                      title="Re-inspect and download again"
                      aria-label={`Re-download ${item.filename}`}
                      onClick={() => void onRedownload(item.id)}
                    >
                      <RefreshCw size={14} aria-hidden="true" />
                    </button>

                    <button
                      type="button"
                      className="btn btn-sm btn-danger-ghost btn-icon"
                      title="Remove from history (keeps file on disk)"
                      aria-label={`Remove ${item.filename} from history`}
                      onClick={() => void onRemove(item.id, false)}
                    >
                      <Trash2 size={14} aria-hidden="true" />
                    </button>
                  </div>
                </div>

                {isBroken && integrity && (
                  <div
                    className="signal-details-list"
                    style={{
                      borderColor: 'var(--danger-border)',
                      background: 'var(--danger-bg)',
                      color: 'var(--danger)',
                    }}
                  >
                    <div style={{ fontWeight: 600 }}>{integrity.summary}</div>
                    <div className="action-group">
                      <button
                        type="button"
                        className="btn btn-sm btn-danger-ghost"
                        onClick={() => void onRemove(item.id, true)}
                      >
                        <Trash2 size={14} aria-hidden="true" />
                        Delete Broken File
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => void onRedownload(item.id)}
                      >
                        <RefreshCw size={14} aria-hidden="true" />
                        Re-inspect &amp; Retry
                      </button>
                    </div>
                  </div>
                )}

                {isVerifyOpen && (
                  <form
                    style={{
                      marginTop: 12,
                      paddingTop: 12,
                      borderTop: '1px solid var(--border)',
                      display: 'flex',
                      gap: 8,
                      flexWrap: 'wrap',
                      alignItems: 'center',
                    }}
                    onSubmit={async (e) => {
                      e.preventDefault();
                      setHashError((prev) => ({ ...prev, [item.id]: '' }));
                      try {
                        await onVerifyHash(item.id, hashInput[item.id] ?? '');
                      } catch (err) {
                        setHashError((prev) => ({
                          ...prev,
                          [item.id]: err instanceof Error ? err.message : 'Verification failed',
                        }));
                      }
                    }}
                  >
                    <label htmlFor={`hash-in-${item.id}`} className="sr-only">
                      Paste expected SHA-256 or MD5 checksum
                    </label>
                    <input
                      id={`hash-in-${item.id}`}
                      type="text"
                      className="input mono"
                      style={{ flex: '1 1 320px' }}
                      value={hashInput[item.id] ?? ''}
                      onChange={(e) =>
                        setHashInput((prev) => ({ ...prev, [item.id]: e.target.value }))
                      }
                      placeholder="Paste 64-char SHA-256 or 32-char MD5 hex digest…"
                    />
                    <button type="submit" className="btn btn-sm btn-primary">
                      Compare Hash
                    </button>
                    {hashError[item.id] && (
                      <span style={{ color: 'var(--danger)', fontSize: 12.5 }}>
                        {hashError[item.id]}
                      </span>
                    )}
                  </form>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
