import { BookOpen, Gauge, HardDrive, Shield, Zap } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { AppSettings, DiskSpaceInfo, SpeedPreset } from '../../shared/types';
import { formatBytes } from '../utils/format';

interface SettingsViewProps {
  settings: AppSettings;
  diskSpace: DiskSpaceInfo;
  onUpdate: (patch: Partial<AppSettings>) => Promise<void>;
}

const PRESETS: Array<{
  id: Exclude<SpeedPreset, 'custom'>;
  title: string;
  desc: string;
  specs: string;
}> = [
  {
    id: 'balanced',
    title: 'Balanced',
    desc: 'Great daily throughput without saturating browsing or disk I/O.',
    specs: '3 concurrent • 2/host • 8 streams/file • Unlimited',
  },
  {
    id: 'turbo',
    title: 'Turbo Large Files',
    desc: 'Maximum multi-segment saturation for multi-GB ISOs, videos, and archives.',
    specs: '4 concurrent • 4/host • 16 streams/file • Unlimited',
  },
  {
    id: 'books',
    title: 'Digital Books (Anti-Corrupt)',
    desc: 'Polite per-mirror queue for Anna’s Archive & book mirrors with EPUB/PDF/MOBI format checks.',
    specs: '3 concurrent • 1 per mirror host • 4 streams/file',
  },
  {
    id: 'background',
    title: 'Background Friendly',
    desc: 'Quiet background transfers leaving bandwidth headroom for calls and streaming.',
    specs: '2 concurrent • 1/host • 4 streams/file • 2.0 MB/s cap',
  },
];

export function SettingsView({ settings, diskSpace, onUpdate }: SettingsViewProps) {
  const [downloadDir, setDownloadDir] = useState(settings.downloadDir);
  const [speedInputKBps, setSpeedInputKBps] = useState(String(settings.speedLimitKBps));
  const [saveFeedback, setSaveFeedback] = useState<string | null>(null);

  useEffect(() => {
    setDownloadDir(settings.downloadDir);
    setSpeedInputKBps(String(settings.speedLimitKBps));
  }, [settings.downloadDir, settings.speedLimitKBps]);

  const applyPatch = async (patch: Partial<AppSettings>, message = 'Settings saved') => {
    await onUpdate(patch);
    setSaveFeedback(message);
    setTimeout(() => setSaveFeedback(null), 2000);
  };

  return (
    <section aria-labelledby="settings-heading">
      <div className="view-header">
        <div>
          <h1 id="settings-heading" className="view-title">
            Settings &amp; Speed Presets
          </h1>
          <p className="view-subtitle">
            Tune multi-segment acceleration, storage folder, bandwidth caps, and Safety Gate policy.
          </p>
        </div>
        {saveFeedback && <span className="badge badge-ok">{saveFeedback}</span>}
      </div>

      <h2 style={{ fontSize: 15, margin: '0 0 10px' }}>1-Click Acceleration Presets</h2>
      <div className="preset-grid">
        {PRESETS.map((preset) => {
          const active = settings.speedPreset === preset.id;
          return (
            <button
              key={preset.id}
              type="button"
              className={`preset-card ${active ? 'active' : ''}`}
              aria-pressed={active}
              onClick={() => void applyPatch({ speedPreset: preset.id }, `Applied ${preset.title} preset`)}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <strong style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  {preset.id === 'turbo' ? (
                    <Zap size={15} aria-hidden="true" />
                  ) : preset.id === 'books' ? (
                    <BookOpen size={15} aria-hidden="true" />
                  ) : (
                    <Gauge size={15} aria-hidden="true" />
                  )}
                  {preset.title}
                </strong>
                {active && <span className="badge badge-info">Active</span>}
              </div>
              <span style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>{preset.desc}</span>
              <span className="num" style={{ fontSize: 12, fontWeight: 600 }}>
                {preset.specs}
              </span>
            </button>
          );
        })}
      </div>

      <div className="settings-grid">
        <div className="card">
          <h2 style={{ margin: '0 0 12px', fontSize: 15, display: 'flex', alignItems: 'center', gap: 7 }}>
            <HardDrive size={16} aria-hidden="true" />
            Storage &amp; Organization
          </h2>

          <div className="field">
            <label htmlFor="set-dir" className="field-label">
              Download Folder
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                id="set-dir"
                type="text"
                className="input mono"
                style={{ flex: 1, minWidth: 0 }}
                value={downloadDir}
                onChange={(e) => setDownloadDir(e.target.value)}
              />
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => void applyPatch({ downloadDir }, 'Download folder updated')}
              >
                Save
              </button>
            </div>
            <div className="field-help num">
              Free space on target drive: <strong>{formatBytes(diskSpace.freeBytes)}</strong> of{' '}
              {formatBytes(diskSpace.totalBytes)}
            </div>
          </div>

          <div className="toggle-row" style={{ marginTop: 12 }}>
            <div>
              <span id="set-organize-label" className="field-label" style={{ display: 'block' }}>
                Organize into category subfolders
              </span>
              <span className="field-help">
                Saves into video/, archive/, software/, etc. inside your download folder.
              </span>
            </div>
            <button
              id="set-organize"
              type="button"
              role="switch"
              aria-checked={settings.organizeByCategory}
              aria-labelledby="set-organize-label"
              className="switch-btn"
              onClick={() => void applyPatch({ organizeByCategory: !settings.organizeByCategory })}
            >
              <span className="switch-thumb" aria-hidden="true" />
            </button>
          </div>
        </div>

        <div className="card">
          <h2 style={{ margin: '0 0 12px', fontSize: 15, display: 'flex', alignItems: 'center', gap: 7 }}>
            <Zap size={16} aria-hidden="true" />
            Engine &amp; Concurrency
          </h2>

          <div className="field" style={{ marginBottom: 12 }}>
            <label htmlFor="set-concurrent" className="field-label">
              Max Concurrent Downloads: <span className="num">{settings.maxConcurrentDownloads}</span>
            </label>
            <select
              id="set-concurrent"
              className="select"
              value={settings.maxConcurrentDownloads}
              onChange={(e) =>
                void applyPatch({ maxConcurrentDownloads: Number(e.target.value) })
              }
            >
              {[1, 2, 3, 4, 5, 6, 8].map((n) => (
                <option key={n} value={n}>
                  {n} simultaneous download{n === 1 ? '' : 's'}
                </option>
              ))}
            </select>
          </div>

          <div className="field" style={{ marginBottom: 12 }}>
            <label htmlFor="set-perhost" className="field-label">
              Max Concurrent per Mirror Host: <span className="num">{settings.maxConcurrentPerHost}</span>
            </label>
            <select
              id="set-perhost"
              className="select"
              value={settings.maxConcurrentPerHost}
              onChange={(e) =>
                void applyPatch({ maxConcurrentPerHost: Number(e.target.value) })
              }
            >
              {[1, 2, 3, 4, 8].map((n) => (
                <option key={n} value={n}>
                  {n} active download{n === 1 ? '' : 's'} per mirror host
                </option>
              ))}
            </select>
            <span className="field-help">
              Keeping 1 per host avoids triggering 429 rate-limits or HTML wait screens when pasting bulk book links.
            </span>
          </div>

          <div className="field" style={{ marginBottom: 12 }}>
            <label htmlFor="set-segments" className="field-label">
              Parallel Streams per File: <span className="num">{settings.segmentsPerDownload}</span>
            </label>
            <select
              id="set-segments"
              className="select"
              value={settings.segmentsPerDownload}
              onChange={(e) =>
                void applyPatch({ segmentsPerDownload: Number(e.target.value) })
              }
            >
              {[1, 2, 4, 8, 12, 16].map((n) => (
                <option key={n} value={n}>
                  {n} stream{n === 1 ? '' : 's'} (auto-steals slow tails)
                </option>
              ))}
            </select>
          </div>

          <div className="field">
            <label htmlFor="set-speedcap" className="field-label">
              Global Speed Cap (KB/s — 0 for Unlimited)
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                id="set-speedcap"
                type="number"
                min={0}
                step={256}
                className="input num"
                style={{ flex: 1 }}
                value={speedInputKBps}
                onChange={(e) => setSpeedInputKBps(e.target.value)}
              />
              <button
                type="button"
                className="btn"
                onClick={() =>
                  void applyPatch({ speedLimitKBps: Math.max(0, Number(speedInputKBps) || 0) })
                }
              >
                Apply
              </button>
              {settings.speedLimitKBps > 0 && (
                <button
                  type="button"
                  className="btn"
                  onClick={() => void applyPatch({ speedLimitKBps: 0 })}
                >
                  Unlimited
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="card">
          <h2 style={{ margin: '0 0 12px', fontSize: 15, display: 'flex', alignItems: 'center', gap: 7 }}>
            <Shield size={16} aria-hidden="true" />
            Safety Gate Policy &amp; Appearance
          </h2>

          <div className="toggle-row" style={{ borderTop: 'none', paddingTop: 0 }}>
            <div>
              <span id="set-auto-approve-label" className="field-label" style={{ display: 'block' }}>
                Auto-approve Low-Risk links from Trusted Domains
              </span>
              <span className="field-help">
                Only skips manual review when domain is on your Trust List AND zero warnings/executables are detected.
              </span>
            </div>
            <button
              id="set-auto-approve"
              type="button"
              role="switch"
              aria-checked={settings.autoApproveTrusted}
              aria-labelledby="set-auto-approve-label"
              className="switch-btn"
              onClick={() => void applyPatch({ autoApproveTrusted: !settings.autoApproveTrusted })}
            >
              <span className="switch-thumb" aria-hidden="true" />
            </button>
          </div>

          <div className="toggle-row">
            <div>
              <span className="field-label" style={{ display: 'block' }}>
                Color Theme
              </span>
              <span className="field-help">High-contrast WCAG 2.2 AA Light or Dark mode.</span>
            </div>
            <div className="pill-tabs">
              <button
                type="button"
                className={`pill-tab ${settings.theme === 'light' ? 'active' : ''}`}
                onClick={() => void applyPatch({ theme: 'light' })}
              >
                Light
              </button>
              <button
                type="button"
                className={`pill-tab ${settings.theme === 'dark' ? 'active' : ''}`}
                onClick={() => void applyPatch({ theme: 'dark' })}
              >
                Dark
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
