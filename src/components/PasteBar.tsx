import {
  AlertCircle,
  Check,
  ClipboardPaste,
  Copy,
  Layers,
  Search,
  Sparkles,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import { normalizeCapabilities } from '../../shared/compat';
import { parseSmartInput } from '../../shared/inputParser';
import type { CompanionCapabilities } from '../../shared/types';

interface PasteBarProps {
  defaultDest: string;
  capabilities: CompanionCapabilities;
  onInspect: (
    text: string,
    destinationDir?: string,
    mode?: 'auto' | 'separate' | 'mirrors'
  ) => Promise<void>;
  onInspectMirrors?: (text: string, destinationDir?: string) => Promise<void>;
  inputRef: React.RefObject<HTMLTextAreaElement | null>;
}

export function PasteBar({
  defaultDest,
  capabilities: rawCapabilities,
  onInspect,
  onInspectMirrors,
  inputRef,
}: PasteBarProps) {
  const capabilities = normalizeCapabilities(rawCapabilities);
  const [urlText, setUrlText] = useState('');
  const [quickMode, setQuickMode] = useState<'mirrors' | 'separate'>('mirrors');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedHint, setCopiedHint] = useState(false);

  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState('');
  const [bulkDest, setBulkDest] = useState('');
  const [bulkMode, setBulkMode] = useState<'separate' | 'mirrors'>('separate');
  const bulkTriggerRef = useRef<HTMLButtonElement | null>(null);
  const bulkTextareaRef = useRef<HTMLTextAreaElement | null>(null);

  const quickParsed = useMemo(() => parseSmartInput(urlText), [urlText]);
  const bulkParsed = useMemo(() => parseSmartInput(bulkText), [bulkText]);
  const lineCount = useMemo(() => urlText.split(/\r?\n/).length, [urlText]);

  useEffect(() => {
    if (!bulkOpen) return;
    bulkTextareaRef.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setBulkOpen(false);
        bulkTriggerRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [bulkOpen]);

  const submitQuickText = async () => {
    if (!urlText.trim()) {
      setErrorMsg('Paste a URL, MD5 hash, magnet link, IPFS URI, or mirror list first.');
      return;
    }
    setSubmitting(true);
    setErrorMsg(null);
    try {
      if (quickParsed.hasMultiMirrors && quickMode === 'mirrors' && onInspectMirrors) {
        await onInspectMirrors(urlText);
      } else {
        await onInspect(urlText, undefined, quickParsed.hasMultiMirrors ? quickMode : 'auto');
      }
      setUrlText('');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to inspect input');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await submitQuickText();
  };

  const handleTextareaKeyDown = (e: ReactKeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void submitQuickText();
    }
  };

  const handleBulkSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!bulkText.trim()) return;
    setSubmitting(true);
    setErrorMsg(null);
    try {
      const dest = bulkDest.trim() || undefined;
      if (bulkMode === 'mirrors' && bulkParsed.directUrls.length >= 2 && onInspectMirrors) {
        await onInspectMirrors(bulkText, dest);
      } else {
        await onInspect(bulkText, dest, 'separate');
      }
      setBulkText('');
      setBulkDest('');
      setBulkMode('separate');
      setBulkOpen(false);
      bulkTriggerRef.current?.focus();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to inspect links');
    } finally {
      setSubmitting(false);
    }
  };

  const hasP2PEntry = quickParsed.entries.some(
    (e) => e.kind === 'magnet' || e.kind === 'torrent_url'
  );
  const hasMd5Entry = quickParsed.entries.some(
    (e) => e.kind === 'annas_md5' || e.kind === 'raw_md5'
  );

  return (
    <>
      <header className="paste-header">
        <form className="paste-form" onSubmit={handleSubmit}>
          <div className="paste-input-wrap">
            <Search size={16} className="paste-icon" aria-hidden="true" />
            <label htmlFor="quick-paste-input" className="sr-only">
              Paste URL, Anna&apos;s Archive link or MD5 hash, multi-line mirrors, magnet, or .torrent link
            </label>
            <textarea
              id="quick-paste-input"
              ref={inputRef}
              rows={Math.min(5, Math.max(1, lineCount))}
              className="paste-input paste-textarea"
              value={urlText}
              onChange={(e) => {
                setUrlText(e.target.value);
                if (errorMsg) setErrorMsg(null);
              }}
              onKeyDown={handleTextareaKeyDown}
              placeholder="Paste URL, Anna’s Archive link or 32-char MD5, multi-line mirrors, magnet:?, .torrent, or ipfs://…"
            />
          </div>

          <div className="paste-actions">
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              <ClipboardPaste size={15} aria-hidden="true" />
              {submitting ? 'Resolving…' : 'Inspect & Resolve'}
            </button>
            <button
              ref={bulkTriggerRef}
              type="button"
              className="btn"
              onClick={() => setBulkOpen(true)}
            >
              <Layers size={15} aria-hidden="true" />
              Bulk Paste
            </button>
          </div>
        </form>

        {quickParsed.entries.length > 0 && (
          <div className="smart-detect-bar">
            <span className="badge badge-info">
              <Sparkles size={12} aria-hidden="true" />
              {quickParsed.summaryLabel}
            </span>

            {hasMd5Entry && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Companion will race Fast API, custom mirrors &amp; IPFS gateways automatically.
              </span>
            )}

            {quickParsed.hasMultiMirrors && (
              <div className="pill-tabs" role="radiogroup" aria-label="Multiple mirror handling">
                <button
                  type="button"
                  role="radio"
                  aria-checked={quickMode === 'mirrors'}
                  className={`pill-tab ${quickMode === 'mirrors' ? 'active' : ''}`}
                  onClick={() => setQuickMode('mirrors')}
                >
                  Combine Mirrors (Speed)
                </button>
                <button
                  type="button"
                  role="radio"
                  aria-checked={quickMode === 'separate'}
                  className={`pill-tab ${quickMode === 'separate' ? 'active' : ''}`}
                  onClick={() => setQuickMode('separate')}
                >
                  Separate Files
                </button>
              </div>
            )}

            {hasP2PEntry && (
              capabilities.aria2Available ? (
                <span className="badge badge-ok">
                  aria2c v{capabilities.aria2Version} Ready
                </span>
              ) : (
                <span className="badge badge-warn">
                  aria2c not found — install with{' '}
                  <code className="mono">{capabilities.installHint.command}</code>
                  <button
                    type="button"
                    className="btn btn-sm btn-icon"
                    style={{ minHeight: 24, minWidth: 24, padding: '2px 6px' }}
                    aria-label="Copy aria2c install command"
                    onClick={() => {
                      void navigator.clipboard.writeText(capabilities.installHint.command);
                      setCopiedHint(true);
                      setTimeout(() => setCopiedHint(false), 1800);
                    }}
                  >
                    {copiedHint ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                  </button>
                </span>
              )
            )}
          </div>
        )}

        {errorMsg && (
          <div className="paste-feedback" role="alert">
            <AlertCircle size={14} aria-hidden="true" />
            <span>{errorMsg}</span>
          </div>
        )}
      </header>

      {bulkOpen && (
        <div
          className="backdrop"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setBulkOpen(false);
              bulkTriggerRef.current?.focus();
            }
          }}
        >
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="bulk-modal-title"
          >
            <div className="modal-header">
              <div>
                <h2 id="bulk-modal-title" style={{ margin: 0, fontSize: 16 }}>
                  Bulk Paste Links, MD5 Hashes &amp; Mirrors
                </h2>
                <div style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
                  Supports direct URLs, Anna&apos;s Archive /md5/ links, raw 32-char MD5 hashes, magnets, .torrent links, and IPFS URIs.
                </div>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-icon"
                aria-label="Close bulk paste dialog"
                onClick={() => {
                  setBulkOpen(false);
                  bulkTriggerRef.current?.focus();
                }}
              >
                <X size={16} aria-hidden="true" />
              </button>
            </div>

            <form onSubmit={handleBulkSubmit} style={{ display: 'contents' }}>
              <div className="modal-body">
                <div className="field">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label htmlFor="bulk-urls-textarea" className="field-label">
                      Sources or Text
                    </label>
                    <span className="badge badge-info num">
                      {bulkParsed.entries.length} source{bulkParsed.entries.length === 1 ? '' : 's'} detected
                    </span>
                  </div>
                  <textarea
                    id="bulk-urls-textarea"
                    ref={bulkTextareaRef}
                    className="textarea"
                    value={bulkText}
                    onChange={(e) => setBulkText(e.target.value)}
                    placeholder={
                      'https://annas-archive.org/md5/0123456789abcdef0123456789abcdef\nhttps://mirror1.example.com/book.epub\nhttps://mirror2.example.com/book.epub'
                    }
                  />
                </div>

                {bulkParsed.directUrls.length >= 2 && onInspectMirrors && (
                  <div className="field">
                    <span id="bulk-mode-label" className="field-label">
                      How should these {bulkParsed.directUrls.length} direct URLs download?
                    </span>
                    <div
                      className="pill-tabs"
                      role="radiogroup"
                      aria-labelledby="bulk-mode-label"
                      style={{ width: '100%' }}
                    >
                      <button
                        type="button"
                        role="radio"
                        aria-checked={bulkMode === 'separate'}
                        className={`pill-tab ${bulkMode === 'separate' ? 'active' : ''}`}
                        style={{ flex: 1 }}
                        onClick={() => setBulkMode('separate')}
                      >
                        Separate Files (Queue Each)
                      </button>
                      <button
                        type="button"
                        role="radio"
                        aria-checked={bulkMode === 'mirrors'}
                        className={`pill-tab ${bulkMode === 'mirrors' ? 'active' : ''}`}
                        style={{ flex: 1 }}
                        onClick={() => setBulkMode('mirrors')}
                      >
                        Same File — Swarm Mirrors for Speed
                      </button>
                    </div>
                    <span className="field-help">
                      {bulkMode === 'mirrors'
                        ? 'Verifies matching file sizes across mirrors and swarms parallel byte ranges across all healthy hosts with live speed-floor switching.'
                        : 'Inspects and downloads each URL as its own file using polite per-host queue limits.'}
                    </span>
                  </div>
                )}

                <div className="field">
                  <label htmlFor="bulk-dest-input" className="field-label">
                    Destination Folder Override (optional)
                  </label>
                  <input
                    id="bulk-dest-input"
                    type="text"
                    className="input"
                    value={bulkDest}
                    onChange={(e) => setBulkDest(e.target.value)}
                    placeholder={`Default: ${defaultDest}`}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    setBulkOpen(false);
                    bulkTriggerRef.current?.focus();
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={submitting || bulkParsed.entries.length === 0}
                >
                  {bulkMode === 'mirrors' && bulkParsed.directUrls.length >= 2
                    ? `Swarm ${bulkParsed.directUrls.length} Mirrors`
                    : `Inspect ${bulkParsed.entries.length || ''} Source${bulkParsed.entries.length === 1 ? '' : 's'}`}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
