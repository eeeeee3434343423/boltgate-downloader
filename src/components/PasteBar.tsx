import { AlertCircle, ClipboardPaste, Layers, Search, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';

interface PasteBarProps {
  defaultDest: string;
  onInspect: (text: string, destinationDir?: string) => Promise<void>;
  inputRef: React.RefObject<HTMLInputElement | null>;
}

export function PasteBar({ defaultDest, onInspect, inputRef }: PasteBarProps) {
  const [urlText, setUrlText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState('');
  const [bulkDest, setBulkDest] = useState('');
  const bulkTriggerRef = useRef<HTMLButtonElement | null>(null);
  const bulkTextareaRef = useRef<HTMLTextAreaElement | null>(null);

  const detectedBulkCount = useMemo(() => {
    const matches = bulkText.match(/https?:\/\/[^\s<>"'`]+/gi) ?? [];
    return new Set(matches.map((m) => m.trim())).size;
  }, [bulkText]);

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

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!urlText.trim()) {
      setErrorMsg('Paste one or more http:// or https:// links first.');
      return;
    }
    setSubmitting(true);
    setErrorMsg(null);
    try {
      await onInspect(urlText);
      setUrlText('');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to inspect URL');
    } finally {
      setSubmitting(false);
    }
  };

  const handleBulkSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!bulkText.trim()) return;
    setSubmitting(true);
    setErrorMsg(null);
    try {
      await onInspect(bulkText, bulkDest.trim() || undefined);
      setBulkText('');
      setBulkDest('');
      setBulkOpen(false);
      bulkTriggerRef.current?.focus();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to inspect links');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <header className="paste-header">
        <form className="paste-form" onSubmit={handleSubmit}>
          <div className="paste-input-wrap">
            <Search size={16} className="paste-icon" aria-hidden="true" />
            <label htmlFor="quick-paste-input" className="sr-only">
              Paste download URL or links to inspect
            </label>
            <input
              id="quick-paste-input"
              ref={inputRef}
              type="text"
              className="paste-input"
              value={urlText}
              onChange={(e) => {
                setUrlText(e.target.value);
                if (errorMsg) setErrorMsg(null);
              }}
              placeholder="Paste a link (or Ctrl+V anywhere) to inspect before downloading…"
            />
          </div>

          <div className="paste-actions">
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              <ClipboardPaste size={15} aria-hidden="true" />
              {submitting ? 'Probing…' : 'Inspect & Check'}
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
                  Bulk Paste Links for Safety Inspection
                </h2>
                <div style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
                  Paste any text, list of URLs, or release notes — BoltGate extracts valid links and checks every one before downloading.
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
                      Links or Text
                    </label>
                    <span className="badge badge-info num">{detectedBulkCount} URLs detected</span>
                  </div>
                  <textarea
                    id="bulk-urls-textarea"
                    ref={bulkTextareaRef}
                    className="textarea"
                    value={bulkText}
                    onChange={(e) => setBulkText(e.target.value)}
                    placeholder={'https://example.com/archive-part1.zip\nhttps://example.com/archive-part2.zip'}
                  />
                </div>

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
                  disabled={submitting || detectedBulkCount === 0}
                >
                  Inspect {detectedBulkCount || ''} Link{detectedBulkCount === 1 ? '' : 's'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
