import { Shield, X } from 'lucide-react';
import { useEffect, useRef } from 'react';
import type { DownloadItem } from '../../shared/types';
import { categoryLabel, formatBytes, formatSpeed, riskMeta } from '../utils/format';

interface InspectDrawerProps {
  item: DownloadItem | null;
  onClose: () => void;
}

export function InspectDrawer({ item, onClose }: InspectDrawerProps) {
  const closeBtnRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!item) return;
    closeBtnRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [item, onClose]);

  if (!item) return null;

  const safety = item.safety;
  const risk = safety ? riskMeta(safety.riskLevel) : null;

  return (
    <div
      className="drawer-backdrop"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
      >
        <div className="drawer-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <Shield size={18} aria-hidden="true" />
            <h2 id="drawer-title" style={{ margin: 0, fontSize: 16, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              Technical Inspector
            </h2>
          </div>
          <button
            ref={closeBtnRef}
            type="button"
            className="btn btn-sm btn-icon"
            aria-label="Close technical inspector"
            onClick={onClose}
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>

        <div className="drawer-body">
          <div>
            <div style={{ fontWeight: 700, fontSize: 15, wordBreak: 'break-word' }}>{item.filename}</div>
            <div className="meta-line" style={{ marginTop: 4 }}>
              <span className="badge">{categoryLabel(item.category)}</span>
              {risk && <span className={`badge badge-${risk.tone}`}>{risk.label}</span>}
              <span className="badge num">{formatBytes(item.totalBytes)}</span>
            </div>
          </div>

          <section>
            <h3 style={{ margin: '0 0 8px', fontSize: 13.5 }}>Endpoints & Storage</h3>
            <table className="kv-table">
              <tbody>
                <tr>
                  <th>Original URL</th>
                  <td className="mono" style={{ wordBreak: 'break-all' }}>{item.originalUrl}</td>
                </tr>
                <tr>
                  <th>Final URL</th>
                  <td className="mono" style={{ wordBreak: 'break-all' }}>{item.finalUrl}</td>
                </tr>
                <tr>
                  <th>Save Path</th>
                  <td className="mono" style={{ wordBreak: 'break-all' }}>{item.savedPath}</td>
                </tr>
                <tr>
                  <th>Range Resume</th>
                  <td>{item.supportsRanges ? 'Supported (multi-stream + pause/resume)' : 'Single-stream only'}</td>
                </tr>
                <tr>
                  <th>Content-Type</th>
                  <td className="mono">{safety?.contentType ?? '—'}</td>
                </tr>
                <tr>
                  <th>ETag</th>
                  <td className="mono">{item.etag ?? '—'}</td>
                </tr>
                {item.sha256 && (
                  <tr>
                    <th>SHA-256</th>
                    <td className="mono" style={{ wordBreak: 'break-all' }}>{item.sha256}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </section>

          {item.integrity && (
            <section>
              <h3 style={{ margin: '0 0 8px', fontSize: 13.5 }}>
                File Integrity &amp; Format Checks
              </h3>
              <div className="signal-details-list" style={{ marginTop: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span
                    className={`badge ${
                      item.integrity.status === 'valid'
                        ? 'badge-ok'
                        : item.integrity.status === 'unchecked'
                          ? 'badge-info'
                          : 'badge-danger'
                    }`}
                  >
                    {item.integrity.status === 'valid'
                      ? `${item.integrity.format} Valid`
                      : item.integrity.status === 'html_trap'
                        ? 'HTML Trap Detected'
                        : item.integrity.status === 'corrupted'
                          ? 'Corrupted / Truncated'
                          : `${item.integrity.format} (Unchecked Format)`}
                  </span>
                  <span style={{ fontWeight: 600 }}>{item.integrity.summary}</span>
                </div>
                {item.integrity.checks.map((chk, idx) => (
                  <div key={idx} style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
                    • {chk}
                  </div>
                ))}
              </div>
            </section>
          )}

          {safety?.tls && (
            <section>
              <h3 style={{ margin: '0 0 8px', fontSize: 13.5 }}>TLS Certificate</h3>
              <table className="kv-table">
                <tbody>
                  <tr>
                    <th>Verified</th>
                    <td>{safety.tls.authorized ? 'Yes (Valid Chain)' : 'No — Failed Verification'}</td>
                  </tr>
                  {safety.tls.issuer && (
                    <tr>
                      <th>Issuer</th>
                      <td>{safety.tls.issuer}</td>
                    </tr>
                  )}
                  {safety.tls.subjectCN && (
                    <tr>
                      <th>Subject CN</th>
                      <td className="mono">{safety.tls.subjectCN}</td>
                    </tr>
                  )}
                  {safety.tls.validTo && (
                    <tr>
                      <th>Expires</th>
                      <td>{safety.tls.validTo}</td>
                    </tr>
                  )}
                  {safety.tls.error && (
                    <tr>
                      <th>Error</th>
                      <td style={{ color: 'var(--danger)' }}>{safety.tls.error}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </section>
          )}

          {safety && safety.redirectChain.length > 0 && (
            <section>
              <h3 style={{ margin: '0 0 8px', fontSize: 13.5 }}>
                Redirect Trace ({safety.redirectChain.length})
              </h3>
              <div className="signal-details-list" style={{ marginTop: 0 }}>
                {safety.redirectChain.map((hop, idx) => (
                  <div key={`${hop.url}-${idx}`} className="mono" style={{ wordBreak: 'break-all' }}>
                    {idx + 1}. [{hop.statusCode}] {hop.url}
                  </div>
                ))}
                <div className="mono" style={{ wordBreak: 'break-all', fontWeight: 600 }}>
                  Final: [{safety.statusCode ?? '—'}] {safety.finalUrl}
                </div>
              </div>
            </section>
          )}

          {item.segments.length > 0 && (
            <section>
              <h3 style={{ margin: '0 0 8px', fontSize: 13.5 }}>
                Parallel Segments ({item.segments.length})
              </h3>
              <table className="kv-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Byte Range</th>
                    <th>Progress</th>
                    <th>Speed</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {item.segments.map((seg) => {
                    const segTotal = seg.end >= 0 ? seg.end - seg.start + 1 : null;
                    const pct =
                      segTotal && segTotal > 0
                        ? Math.min(100, Math.round((seg.downloaded / segTotal) * 100))
                        : null;
                    return (
                      <tr key={seg.id}>
                        <td className="num">#{seg.id + 1}</td>
                        <td className="mono num">
                          {seg.start.toLocaleString()}–{seg.end >= 0 ? seg.end.toLocaleString() : '∞'}
                        </td>
                        <td className="num">
                          {formatBytes(seg.downloaded)} {pct !== null ? `(${pct}%)` : ''}
                        </td>
                        <td className="num">{formatSpeed(seg.speedBps)}</td>
                        <td>
                          {seg.status}
                          {seg.retries > 0 ? ` (retries: ${seg.retries})` : ''}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </section>
          )}

          {item.error && (
            <section>
              <h3 style={{ margin: '0 0 6px', fontSize: 13.5, color: 'var(--danger)' }}>
                Last Error
              </h3>
              <div className="badge badge-danger" style={{ borderRadius: 8, padding: '8px 10px' }}>
                {item.error}
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
