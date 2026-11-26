import {
  BookOpen,
  Check,
  Copy,
  Eye,
  EyeOff,
  Gauge,
  Globe,
  HardDrive,
  RefreshCw,
  Shield,
  Terminal,
  Zap,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  type CapabilityBinding,
  DEFAULT_PUBLIC_IPFS_GATEWAYS,
  type PinnedSecretWriteContext,
  buildSettingsDraftSnapshot,
  buildTemplatePatchEntries,
  mergeSettingsDrafts,
  normalizeCapabilities,
  normalizeSettings,
} from '../../shared/compat';
import type {
  AppSettings,
  CompanionCapabilities,
  DiskSpaceInfo,
  SettingsPatch,
  SpeedPreset,
} from '../../shared/types';
import { formatBytes } from '../utils/format';

interface SettingsViewProps {
  settings: AppSettings;
  diskSpace: DiskSpaceInfo;
  capabilities: CompanionCapabilities;
  /** Origin + session the settings snapshot was loaded from (credential writes are pinned here). */
  pairedBinding: CapabilityBinding;
  /** Origin + session the capability flags were observed on. */
  capabilityBinding: CapabilityBinding;
  onRefreshCapabilities: () => Promise<void>;
  onUpdate: (patch: SettingsPatch) => Promise<void>;
  onUpdateSecret: (patch: SettingsPatch, pinned: PinnedSecretWriteContext) => Promise<void>;
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

export function SettingsView({
  settings: rawSettings,
  diskSpace,
  capabilities: rawCapabilities,
  pairedBinding,
  capabilityBinding,
  onRefreshCapabilities,
  onUpdate,
  onUpdateSecret,
}: SettingsViewProps) {
  const settings = useMemo(() => normalizeSettings(rawSettings), [rawSettings]);
  const capabilities = useMemo(() => normalizeCapabilities(rawCapabilities), [rawCapabilities]);
  const supportsWriteOnlySecrets = capabilities.features?.writeOnlySecrets === true;
  const savedDrafts = useMemo(() => buildSettingsDraftSnapshot(settings), [settings]);
  const prevSavedRef = useRef(savedDrafts);

  const [downloadDir, setDownloadDir] = useState(savedDrafts.downloadDir);
  const [speedInputKBps, setSpeedInputKBps] = useState(savedDrafts.speedInputKBps);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [annasBaseInput, setAnnasBaseInput] = useState(savedDrafts.annasBaseInput);
  const [customMirrorsText, setCustomMirrorsText] = useState(savedDrafts.customMirrorsText);
  const [ipfsGatewaysText, setIpfsGatewaysText] = useState(savedDrafts.ipfsGatewaysText);
  const [speedFloorInput, setSpeedFloorInput] = useState(savedDrafts.speedFloorInput);
  const [saveFeedback, setSaveFeedback] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  // Sync only individual draft fields whose persisted server value actually changed,
  // so SSE telemetry updates and unrelated re-renders never reset form inputs while typing.
  useEffect(() => {
    const prevSaved = prevSavedRef.current;
    const nextDraft = mergeSettingsDrafts(
      {
        downloadDir,
        speedInputKBps,
        annasBaseInput,
        customMirrorsText,
        ipfsGatewaysText,
        speedFloorInput,
      },
      prevSaved,
      savedDrafts
    );
    prevSavedRef.current = savedDrafts;
    if (nextDraft.downloadDir !== downloadDir) setDownloadDir(nextDraft.downloadDir);
    if (nextDraft.speedInputKBps !== speedInputKBps) setSpeedInputKBps(nextDraft.speedInputKBps);
    if (nextDraft.annasBaseInput !== annasBaseInput) setAnnasBaseInput(nextDraft.annasBaseInput);
    if (nextDraft.customMirrorsText !== customMirrorsText) {
      setCustomMirrorsText(nextDraft.customMirrorsText);
    }
    if (nextDraft.ipfsGatewaysText !== ipfsGatewaysText) {
      setIpfsGatewaysText(nextDraft.ipfsGatewaysText);
    }
    if (nextDraft.speedFloorInput !== speedFloorInput) setSpeedFloorInput(nextDraft.speedFloorInput);
  }, [savedDrafts]);

  /**
   * Credential-bearing writes (API key, private mirror / gateway templates) go through the
   * origin-pinned writer. Resolves `true` ONLY after the engine confirmed the save.
   */
  const applySecretPatch = async (patch: SettingsPatch, message = 'API key saved'): Promise<boolean> => {
    try {
      await onUpdateSecret(patch, {
        engineOrigin: pairedBinding.origin,
        sessionToken: pairedBinding.sessionToken,
        writeOnlySecrets: capabilities.features?.writeOnlySecrets === true,
        capabilityOrigin: capabilityBinding.origin,
        capabilitySessionToken: capabilityBinding.sessionToken,
      });
      setSaveError(null);
      setSaveFeedback(message);
      setTimeout(() => setSaveFeedback(null), 2200);
      return true;
    } catch (err) {
      setSaveFeedback(null);
      setSaveError(err instanceof Error ? err.message : 'Failed to save secret');
      return false;
    }
  };

  const splitLines = (text: string) =>
    text
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);

  const applyPatch = async (patch: SettingsPatch, message = 'Settings saved') => {
    try {
      await onUpdate(patch);
      setSaveError(null);
      setSaveFeedback(message);
      setTimeout(() => setSaveFeedback(null), 2200);
    } catch (err) {
      setSaveFeedback(null);
      setSaveError(err instanceof Error ? err.message : 'Failed to save setting');
    }
  };

  return (
    <section aria-labelledby="settings-heading">
      <div className="view-header">
        <div>
          <h1 id="settings-heading" className="view-title">
            Settings &amp; Speed Presets
          </h1>
          <p className="view-subtitle">
            Tune multi-segment acceleration, fast-source routing, custom mirrors, speed-floor switching, and Safety Gate policy.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          {saveFeedback && <span className="badge badge-ok">{saveFeedback}</span>}
          {saveError && <span className="badge badge-danger">{saveError}</span>}
        </div>
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
                Saves into video/, archive/, ebook/, etc. inside your download folder.
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
            <Globe size={16} aria-hidden="true" />
            Book Sources &amp; Auto-Routing
          </h2>

          <div className="field" style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
              <label htmlFor="set-annas-key" className="field-label">
                Anna&apos;s Archive Fast Download API Key (write-only)
              </label>
              <span className={`badge ${settings.hasAnnasArchiveApiKey ? 'badge-ok' : ''}`}>
                {settings.hasAnnasArchiveApiKey ? 'Saved in encrypted vault' : 'Not configured'}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <input
                id="set-annas-key"
                type={showApiKey ? 'text' : 'password'}
                className="input mono"
                style={{ flex: '1 1 180px', minWidth: 0 }}
                value={apiKeyInput}
                disabled={!supportsWriteOnlySecrets}
                onChange={(e) => setApiKeyInput(e.target.value)}
                placeholder={
                  !supportsWriteOnlySecrets
                    ? 'Upgrade/restart local Companion to enable encrypted key vault'
                    : settings.hasAnnasArchiveApiKey
                      ? 'Enter a new key to replace saved key'
                      : 'Paste secret API key (write-only)'
                }
                autoComplete="off"
              />
              <button
                type="button"
                className="btn btn-icon"
                disabled={!supportsWriteOnlySecrets}
                aria-label={showApiKey ? 'Hide API key input' : 'Show API key input'}
                onClick={() => setShowApiKey((v) => !v)}
              >
                {showApiKey ? <EyeOff size={15} aria-hidden="true" /> : <Eye size={15} aria-hidden="true" />}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={!supportsWriteOnlySecrets || !apiKeyInput.trim()}
                title={
                  supportsWriteOnlySecrets
                    ? undefined
                    : 'Disabled: current local Companion does not advertise encrypted writeOnlySecrets support'
                }
                onClick={async () => {
                  if (!supportsWriteOnlySecrets) return;
                  const key = apiKeyInput.trim();
                  if (!key) return;
                  const saved = await applySecretPatch(
                    { annasArchiveApiKey: key },
                    'Fast Download API key saved securely'
                  );
                  // Only clear the secret input after the engine confirmed the save
                  if (saved) setApiKeyInput('');
                }}
              >
                Save Key
              </button>
              {settings.hasAnnasArchiveApiKey && (
                <button
                  type="button"
                  className="btn"
                  disabled={!supportsWriteOnlySecrets}
                  onClick={async () => {
                    if (!supportsWriteOnlySecrets) return;
                    const cleared = await applySecretPatch(
                      { annasArchiveApiKey: '' },
                      'Saved Fast Download API key cleared'
                    );
                    if (cleared) setApiKeyInput('');
                  }}
                >
                  Clear Key
                </button>
              )}
            </div>
            {!supportsWriteOnlySecrets ? (
              <span className="field-help" style={{ color: 'var(--warn-text, var(--danger-text))' }}>
                Saving API keys is disabled because this Companion engine does not support encrypted write-only secrets. Restart <code className="mono">Launch-BoltGate.bat</code> to update.
              </span>
            ) : (
              <span className="field-help">
                Encrypted locally in Companion&apos;s <code className="mono">secrets.enc.json</code> (never persisted in plaintext <code className="mono">state.json</code> or returned to UI) and bound strictly to your configured HTTPS provider origin.
              </span>
            )}
          </div>

          <div className="field" style={{ marginBottom: 12 }}>
            <label htmlFor="set-annas-base" className="field-label">
              Anna&apos;s Archive Official HTTPS Provider Origin
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                id="set-annas-base"
                type="url"
                className="input mono"
                style={{ flex: 1, minWidth: 0 }}
                value={annasBaseInput}
                onChange={(e) => setAnnasBaseInput(e.target.value)}
                placeholder="https://annas-archive.org"
              />
              <button
                type="button"
                className="btn"
                onClick={() =>
                  void applyPatch({ annasArchiveBaseUrl: annasBaseInput.trim() }, 'Provider origin updated')
                }
              >
                Save
              </button>
            </div>
            <span className="field-help">
              Must use HTTPS on an approved Anna&apos;s Archive domain; pasted URLs from third-party hosts can never override this credential target.
            </span>
          </div>

          <div className="field" style={{ marginBottom: 12 }}>
            <label htmlFor="set-speed-floor" className="field-label">
              Minimum Speed Floor before Mirror Switch (KB/s — 0 disables)
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                id="set-speed-floor"
                type="number"
                min={0}
                step={50}
                className="input num"
                style={{ flex: 1 }}
                value={speedFloorInput}
                onChange={(e) => setSpeedFloorInput(e.target.value)}
              />
              <button
                type="button"
                className="btn"
                onClick={() =>
                  void applyPatch(
                    { minSpeedFloorKBps: Math.max(0, Number(speedFloorInput) || 0) },
                    'Speed floor updated'
                  )
                }
              >
                Apply
              </button>
            </div>
            <span className="field-help">
              Default <strong className="num">350 KB/s</strong>. Evicts throttled mirrors after a 5s rolling window and reassigns unfinished chunks to faster/standby mirrors.
            </span>
          </div>

          <div className="field" style={{ marginBottom: 12 }}>
            <label htmlFor="set-custom-mirrors" className="field-label">
              Custom External Mirror Templates (one URL per line, supports <code className="mono">{'{md5}'}</code>)
            </label>
            <textarea
              id="set-custom-mirrors"
              className="textarea"
              style={{ minHeight: 82 }}
              value={customMirrorsText}
              onChange={(e) => setCustomMirrorsText(e.target.value)}
              placeholder={'https://mirror-a.example.org/get/{md5}\nhttps://mirror-b.example.org/dl/{md5}'}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn btn-sm"
                disabled={!supportsWriteOnlySecrets}
                title={
                  supportsWriteOnlySecrets
                    ? undefined
                    : 'Disabled: private templates require encrypted writeOnlySecrets support'
                }
                onClick={() =>
                  void applySecretPatch(
                    {
                      customMirrorUrls: buildTemplatePatchEntries(
                        splitLines(customMirrorsText),
                        settings.customMirrorUrls,
                        settings.templateRefs?.customMirrorUrls
                      ),
                    },
                    'Custom mirror list saved'
                  )
                }
              >
                Save Custom Mirrors
              </button>
            </div>
          </div>

          <div className="field">
            <label htmlFor="set-ipfs-gateways" className="field-label">
              IPFS Gateways for Concurrent Race (supports <code className="mono">{'{cid}'}</code>)
            </label>
            <textarea
              id="set-ipfs-gateways"
              className="textarea"
              style={{ minHeight: 96 }}
              value={ipfsGatewaysText}
              onChange={(e) => setIpfsGatewaysText(e.target.value)}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                type="button"
                className="btn btn-sm"
                disabled={!supportsWriteOnlySecrets}
                onClick={() =>
                  void applySecretPatch(
                    { ipfsGateways: [...DEFAULT_PUBLIC_IPFS_GATEWAYS] },
                    'Reset default IPFS gateways'
                  )
                }
              >
                Reset Defaults
              </button>
              <button
                type="button"
                className="btn btn-sm"
                disabled={!supportsWriteOnlySecrets}
                title={
                  supportsWriteOnlySecrets
                    ? undefined
                    : 'Disabled: private templates require encrypted writeOnlySecrets support'
                }
                onClick={() =>
                  void applySecretPatch(
                    {
                      ipfsGateways: buildTemplatePatchEntries(
                        splitLines(ipfsGatewaysText),
                        settings.ipfsGateways,
                        settings.templateRefs?.ipfsGateways
                      ),
                    },
                    'IPFS gateways saved'
                  )
                }
              >
                Save Gateways
              </button>
            </div>
          </div>
        </div>

        <div className="card">
          <h2 style={{ margin: '0 0 12px', fontSize: 15, display: 'flex', alignItems: 'center', gap: 7 }}>
            <Shield size={16} aria-hidden="true" />
            Companion Bridge, P2P &amp; Policy
          </h2>

          <div className="install-hint-box" style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600, fontSize: 13 }}>
                <Terminal size={14} aria-hidden="true" />
                {capabilities.aria2Available
                  ? `aria2c v${capabilities.aria2Version} Detected`
                  : 'Pure Node.js Mode (aria2c not installed)'}
              </span>
              <span className={`badge ${capabilities.aria2Available ? 'badge-ok' : 'badge-warn'}`}>
                {capabilities.aria2Available ? 'P2P Ready' : 'HTTP/IPFS Ready'}
              </span>
            </div>

            {!capabilities.aria2Available && (
              <div style={{ fontSize: 12.5, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span>Optional for magnet / .torrent P2P ({capabilities.installHint.label}):</span>
                <code className="mono">{capabilities.installHint.command}</code>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => {
                    void navigator.clipboard.writeText(capabilities.installHint.command);
                    setCopiedCmd(true);
                    setTimeout(() => setCopiedCmd(false), 1800);
                  }}
                >
                  {copiedCmd ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
                  {copiedCmd ? 'Copied' : 'Copy'}
                </button>
              </div>
            )}

            <div>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => void onRefreshCapabilities()}
              >
                <RefreshCw size={13} aria-hidden="true" />
                Re-check aria2c
              </button>
            </div>
          </div>

          <div className="toggle-row" style={{ borderTop: 'none', paddingTop: 0 }}>
            <div>
              <span id="set-prefer-aria2-label" className="field-label" style={{ display: 'block' }}>
                Prefer aria2c for P2P &amp; multi-mirror queues
              </span>
              <span className="field-help">
                Uses aria2c for magnets/.torrents (and allows selecting aria2c in Safety Gate when installed).
              </span>
            </div>
            <button
              id="set-prefer-aria2"
              type="button"
              role="switch"
              aria-checked={settings.preferAria2}
              aria-labelledby="set-prefer-aria2-label"
              className="switch-btn"
              onClick={() => void applyPatch({ preferAria2: !settings.preferAria2 })}
            >
              <span className="switch-thumb" aria-hidden="true" />
            </button>
          </div>

          <div className="toggle-row">
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
