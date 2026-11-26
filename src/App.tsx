import { Menu, RefreshCw, ShieldCheck, Terminal, Zap } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AppStateSnapshot, DownloadItem, TrustRule } from '../shared/types';
import { api } from './api';
import { CompletedView } from './components/CompletedView';
import { DownloadsView } from './components/DownloadsView';
import { InspectDrawer } from './components/InspectDrawer';
import { PasteBar } from './components/PasteBar';
import { SafetyGateView } from './components/SafetyGateView';
import { SettingsView } from './components/SettingsView';
import { Sidebar, type NavTab } from './components/Sidebar';
import { Toast, type ToastNotice } from './components/Toast';
import { TrustListView } from './components/TrustListView';

export function App() {
  const [state, setState] = useState<AppStateSnapshot | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const [activeTab, setActiveTab] = useState<NavTab>('gate');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [drawerItemId, setDrawerItemId] = useState<string | null>(null);
  const [toast, setToast] = useState<ToastNotice | null>(null);
  const [engineUrlInput, setEngineUrlInput] = useState(() => api.getEngineBaseUrl() || 'http://127.0.0.1:3847');
  const [connectAttempt, setConnectAttempt] = useState(0);

  const pasteInputRef = useRef<HTMLInputElement | null>(null);
  const toastTimerRef = useRef<number | null>(null);

  const showToast = useCallback(
    (message: string, onUndo?: () => Promise<void> | void, tone: 'info' | 'error' = 'info') => {
      if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
      const id = String(Date.now());
      setToast({ id, message, onUndo, tone });
      toastTimerRef.current = window.setTimeout(() => {
        setToast((curr) => (curr?.id === id ? null : curr));
      }, 10_000);
    },
    []
  );

  // Sync theme attribute to <html>
  useEffect(() => {
    const theme = state?.settings.theme ?? 'light';
    document.documentElement.setAttribute('data-theme', theme);
  }, [state?.settings.theme]);

  // Initial load + SSE realtime subscription
  useEffect(() => {
    let alive = true;
    setLoadError(null);
    api
      .getState()
      .then((snap) => {
        if (!alive) return;
        setState(snap);
        setLoadError(null);
        if (snap.stats.pendingReviewCount === 0 && snap.stats.activeCount > 0) {
          setActiveTab('downloads');
        }
      })
      .catch((err) => {
        if (!alive) return;
        setLoadError(err instanceof Error ? err.message : 'Failed to connect to BoltGate backend');
      });

    const disconnect = api.connectEvents(
      (ev) => {
        setLoadError(null);
        setState((prev) => {
          if (ev.type === 'snapshot') return ev.data;
          if (!prev) return prev;

          if (ev.type === 'telemetry') {
            const updates = new Map(ev.data.downloads.map((d) => [d.id, d]));
            return {
              ...prev,
              downloads: prev.downloads.map((d) => updates.get(d.id) ?? d),
              speedHistory: ev.data.speedHistory,
              stats: ev.data.stats,
            };
          }

          if (ev.type === 'download_updated') {
            const exists = prev.downloads.some((d) => d.id === ev.data.id);
            const nextDownloads = exists
              ? prev.downloads.map((d) => (d.id === ev.data.id ? ev.data : d))
              : [ev.data, ...prev.downloads];
            return {
              ...prev,
              downloads: nextDownloads,
              stats: recomputeStats(nextDownloads),
            };
          }

          if (ev.type === 'download_removed') {
            const nextDownloads = prev.downloads.filter((d) => d.id !== ev.data.id);
            return {
              ...prev,
              downloads: nextDownloads,
              stats: recomputeStats(nextDownloads),
            };
          }

          if (ev.type === 'settings_updated') {
            return {
              ...prev,
              settings: ev.data.settings,
              diskSpace: ev.data.diskSpace,
            };
          }

          if (ev.type === 'trust_updated') {
            return {
              ...prev,
              trustRules: ev.data,
            };
          }

          return prev;
        });
      },
      (connected) => setSseConnected(connected)
    );

    return () => {
      alive = false;
      disconnect();
    };
  }, [connectAttempt]);

  // Auto-retry every 3s while disconnected so launching Launch-BoltGate.bat connects automatically
  useEffect(() => {
    if (!loadError) return;
    const timer = window.setInterval(() => {
      setConnectAttempt((n) => n + 1);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [loadError]);

  // Global paste listener (when user presses Ctrl+V outside an input/textarea)
  const handleInspect = useCallback(
    async (text: string, destinationDir?: string) => {
      const res = await api.inspectLinks(text, destinationDir);
      if (res.items.length > 0) {
        setActiveTab('gate');
      }
      if (res.rejectedTokens.length > 0) {
        showToast(
          `Inspected ${res.items.length} link(s); skipped ${res.rejectedTokens.length} unsupported scheme(s).`
        );
      }
    },
    [showToast]
  );

  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable)
      ) {
        return;
      }
      const text = e.clipboardData?.getData('text/plain') ?? '';
      if (/https?:\/\//i.test(text)) {
        e.preventDefault();
        void handleInspect(text).catch((err) => {
          showToast(err instanceof Error ? err.message : 'Failed to inspect pasted link', undefined, 'error');
        });
      }
    };
    window.addEventListener('paste', onPaste);
    return () => window.removeEventListener('paste', onPaste);
  }, [handleInspect, showToast]);

  const gateItems = useMemo(
    () =>
      (state?.downloads ?? []).filter(
        (d) => d.status === 'probing' || d.status === 'pending_review'
      ),
    [state?.downloads]
  );

  const activeDownloads = useMemo(
    () =>
      (state?.downloads ?? []).filter((d) =>
        ['queued', 'downloading', 'paused', 'verifying', 'failed'].includes(d.status)
      ),
    [state?.downloads]
  );

  const completedDownloads = useMemo(
    () => (state?.downloads ?? []).filter((d) => d.status === 'completed'),
    [state?.downloads]
  );

  const drawerItem = useMemo(
    () => (state?.downloads ?? []).find((d) => d.id === drawerItemId) ?? null,
    [state?.downloads, drawerItemId]
  );

  if (loadError) {
    const remote = api.isRemoteHosted();
    return (
      <div className="workspace-content" style={{ maxWidth: 680, marginTop: 48 }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="brand-icon" aria-hidden="true">
              <Zap size={18} />
            </div>
            <div>
              <h1 style={{ margin: 0, fontSize: 19 }}>
                {remote ? 'Connect Your Local BoltGate Engine' : 'Cannot Reach BoltGate Engine'}
              </h1>
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                {remote
                  ? 'GitHub Pages hosts the BoltGate UI. Your PC runs the multi-stream engine locally to bypass browser CORS limits and save directly to disk.'
                  : loadError}
              </div>
            </div>
          </div>

          <form
            style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}
            onSubmit={(e) => {
              e.preventDefault();
              api.setEngineBaseUrl(engineUrlInput);
              setConnectAttempt((n) => n + 1);
            }}
          >
            <div className="field" style={{ flex: '1 1 280px' }}>
              <label htmlFor="engine-url-in" className="field-label">
                Local Engine Address
              </label>
              <input
                id="engine-url-in"
                type="url"
                className="input mono"
                value={engineUrlInput}
                onChange={(e) => setEngineUrlInput(e.target.value)}
              />
            </div>
            <button type="submit" className="btn btn-primary">
              <RefreshCw size={15} aria-hidden="true" />
              Connect Now
            </button>
          </form>

          <div
            className="signal-details-list"
            style={{ marginTop: 0, gap: 6 }}
          >
            <div style={{ fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Terminal size={14} aria-hidden="true" />
              Quick Start (auto-connects within 3 seconds once running)
            </div>
            <div style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
              1. Run <code className="mono">Launch-BoltGate.bat</code> (or <code className="mono">npm start</code> inside the repo).
            </div>
            <div style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
              2. Need the local engine? Download or clone{' '}
              <a
                href="https://github.com/eeeeee3434343423/boltgate-downloader"
                target="_blank"
                rel="noreferrer"
                style={{ color: 'var(--accent-text)', fontWeight: 600 }}
              >
                github.com/eeeeee3434343423/boltgate-downloader
              </a>
              .
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--text-muted)' }}>
            <ShieldCheck size={14} aria-hidden="true" />
            <span>
              Multi-segment acceleration, EPUB/PDF/MOBI anti-corruption checks, and direct-to-disk saving stay 100% on your machine.
            </span>
          </div>
        </div>
      </div>
    );
  }

  if (!state) {
    return (
      <div className="app-shell">
        <aside className="sidebar" aria-hidden="true">
          <div className="skeleton-line" style={{ height: 34, width: '75%' }} />
          <div className="skeleton-line" style={{ height: 36 }} />
          <div className="skeleton-line" style={{ height: 36 }} />
          <div className="skeleton-line" style={{ height: 36 }} />
        </aside>
        <main className="main-column">
          <div className="paste-header">
            <div className="skeleton-line" style={{ height: 40, maxWidth: 1120, margin: '0 auto' }} />
          </div>
          <div className="workspace-content">
            <div className="card" style={{ height: 180 }} />
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        stats={state.stats}
        speedHistory={state.speedHistory}
        diskSpace={state.diskSpace}
        settings={state.settings}
        sseConnected={sseConnected}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        onToggleTheme={() =>
          void api.updateSettings({ theme: state.settings.theme === 'dark' ? 'light' : 'dark' })
        }
      />

      <div className="main-column">
        <div className="mobile-topbar">
          <button
            type="button"
            className="btn btn-sm"
            aria-label="Open navigation menu"
            onClick={() => setMobileMenuOpen(true)}
          >
            <Menu size={16} aria-hidden="true" />
            Menu
          </button>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 700 }}>
            <Zap size={16} color="var(--accent)" aria-hidden="true" />
            BoltGate
          </span>
          <span className="badge num">
            {state.stats.pendingReviewCount > 0
              ? `${state.stats.pendingReviewCount} review`
              : `${state.stats.activeCount} active`}
          </span>
        </div>

        <PasteBar
          defaultDest={state.settings.downloadDir}
          onInspect={handleInspect}
          inputRef={pasteInputRef}
        />

        <main className="workspace-content">
          {activeTab === 'gate' && (
            <SafetyGateView
              items={gateItems}
              onApprove={async (id, opts) => {
                await api.approveDownload(id, opts);
                setActiveTab('downloads');
              }}
              onApproveBatch={async (ids) => {
                await api.approveBatch(ids, false);
                setActiveTab('downloads');
              }}
              onReject={async (id, blockDomain) => {
                await api.rejectDownload(id, blockDomain);
                showToast(
                  blockDomain ? 'Link rejected and domain added to Blocked list.' : 'Link rejected.'
                );
              }}
              onReprobe={async (id) => {
                await api.reprobeDownload(id);
              }}
              onInspectDrawer={(item) => setDrawerItemId(item.id)}
              onRunBenchmark={async () => {
                const engineOrigin = api.getEngineBaseUrl() || window.location.origin;
                const benchUrl = `${engineOrigin}/api/local-benchmark?sizeMB=20`;
                await handleInspect(benchUrl);
              }}
              onFocusPaste={() => pasteInputRef.current?.focus()}
            />
          )}

          {activeTab === 'downloads' && (
            <DownloadsView
              items={activeDownloads}
              onPause={async (id) => {
                await api.pauseDownload(id);
              }}
              onResume={async (id, startNow) => {
                await api.resumeDownload(id, startNow);
              }}
              onPriority={async (id, action) => {
                await api.reorderPriority(id, action);
              }}
              onRemove={async (id, deleteFile) => {
                const item = state.downloads.find((d) => d.id === id);
                await api.removeDownload(id, deleteFile);
                showToast(`Removed "${item?.filename ?? 'download'}"`, async () => {
                  await api.restoreDownload(id);
                });
              }}
              onBulkAction={async (action) => {
                await api.bulkAction(action);
              }}
              onInspectDrawer={(item) => setDrawerItemId(item.id)}
              onGoToGate={() => setActiveTab('gate')}
            />
          )}

          {activeTab === 'completed' && (
            <CompletedView
              items={completedDownloads}
              onOpenFolder={async (id) => {
                await api.openInFolder(id);
              }}
              onOpenFile={async (id) => {
                try {
                  await api.openFile(id);
                } catch (err) {
                  showToast(err instanceof Error ? err.message : 'Cannot open file', undefined, 'error');
                }
              }}
              onVerifyHash={(id, expected) => api.verifyHash(id, expected)}
              onRedownload={async (url) => {
                await handleInspect(url);
              }}
              onRemove={async (id, deleteFile) => {
                const item = state.downloads.find((d) => d.id === id);
                await api.removeDownload(id, deleteFile);
                showToast(`Removed "${item?.filename ?? 'file'}" from list`, async () => {
                  await api.restoreDownload(id);
                });
              }}
              onClearCompleted={async () => {
                const res = await api.bulkAction('clearCompleted');
                if (res.undoToken) {
                  const token = res.undoToken;
                  showToast(`Cleared ${res.count} completed item(s)`, async () => {
                    await api.restoreBatch(token);
                  });
                }
              }}
              onInspectDrawer={(item) => setDrawerItemId(item.id)}
            />
          )}

          {activeTab === 'trust' && (
            <TrustListView
              rules={state.trustRules}
              onUpsert={async (domain, status, note) => {
                await api.upsertTrustRule(domain, status, note);
              }}
              onDelete={async (rule: TrustRule) => {
                await api.deleteTrustRule(rule.domain);
                showToast(`Removed rule for ${rule.domain}`, async () => {
                  await api.upsertTrustRule(rule.domain, rule.status, rule.note);
                });
              }}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              settings={state.settings}
              diskSpace={state.diskSpace}
              onUpdate={async (patch) => {
                await api.updateSettings(patch);
              }}
            />
          )}
        </main>
      </div>

      <InspectDrawer item={drawerItem} onClose={() => setDrawerItemId(null)} />
      <Toast notice={toast} onDismiss={() => setToast(null)} />
    </div>
  );
}

function recomputeStats(downloads: DownloadItem[]) {
  let pendingReviewCount = 0;
  let probingCount = 0;
  let activeCount = 0;
  let queuedCount = 0;
  let pausedCount = 0;
  let failedCount = 0;
  let completedCount = 0;
  let totalSpeedBps = 0;
  let activeStreamsCount = 0;
  let totalDownloadedBytes = 0;

  for (const d of downloads) {
    totalDownloadedBytes += d.downloadedBytes;
    switch (d.status) {
      case 'pending_review':
        pendingReviewCount++;
        break;
      case 'probing':
        probingCount++;
        break;
      case 'downloading':
      case 'verifying':
        activeCount++;
        totalSpeedBps += d.speedBps;
        activeStreamsCount += d.segments.filter((s) => s.status === 'active').length;
        break;
      case 'queued':
        queuedCount++;
        break;
      case 'paused':
        pausedCount++;
        break;
      case 'failed':
        failedCount++;
        break;
      case 'completed':
        completedCount++;
        break;
    }
  }

  return {
    pendingReviewCount,
    probingCount,
    activeCount,
    queuedCount,
    pausedCount,
    failedCount,
    completedCount,
    totalSpeedBps,
    activeStreamsCount,
    totalDownloadedBytes,
  };
}
