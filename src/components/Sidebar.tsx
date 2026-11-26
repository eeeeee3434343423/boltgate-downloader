import {
  CheckCircle2,
  Download,
  HardDrive,
  Moon,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sun,
  X,
  Zap,
} from 'lucide-react';
import type { AppSettings, AppStats, DiskSpaceInfo } from '../../shared/types';
import { formatBytes, formatSpeed } from '../utils/format';

export type NavTab = 'gate' | 'downloads' | 'completed' | 'trust' | 'settings';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  stats: AppStats;
  speedHistory: number[];
  diskSpace: DiskSpaceInfo;
  settings: AppSettings;
  sseConnected: boolean;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onToggleTheme: () => void;
}

export function Sidebar({
  activeTab,
  onSelectTab,
  stats,
  speedHistory,
  diskSpace,
  settings,
  sseConnected,
  mobileOpen,
  onCloseMobile,
  onToggleTheme,
}: SidebarProps) {
  const gateCount = stats.pendingReviewCount + stats.probingCount;
  const activeDownloadsCount =
    stats.activeCount + stats.queuedCount + stats.pausedCount + stats.failedCount;

  const navItems: Array<{
    id: NavTab;
    label: string;
    icon: typeof ShieldAlert;
    count?: number;
    badgeTone?: 'attention' | 'active-flow';
  }> = [
    {
      id: 'gate',
      label: 'Safety Gate',
      icon: ShieldAlert,
      count: gateCount,
      badgeTone: gateCount > 0 ? 'attention' : undefined,
    },
    {
      id: 'downloads',
      label: 'Downloads',
      icon: Download,
      count: activeDownloadsCount,
      badgeTone: stats.activeCount > 0 ? 'active-flow' : undefined,
    },
    {
      id: 'completed',
      label: 'Completed',
      icon: CheckCircle2,
      count: stats.completedCount,
    },
    {
      id: 'trust',
      label: 'Trust List',
      icon: ShieldCheck,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
    },
  ];

  const maxSpeed = Math.max(1024, ...speedHistory);
  const sparkPoints = speedHistory
    .map((val, idx) => {
      const x = (idx / Math.max(1, speedHistory.length - 1)) * 220;
      const y = 30 - (val / maxSpeed) * 26;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  const usedPct =
    diskSpace.totalBytes > 0
      ? Math.min(100, Math.round(((diskSpace.totalBytes - diskSpace.freeBytes) / diskSpace.totalBytes) * 100))
      : 0;

  return (
    <>
      {mobileOpen && (
        <div
          className="sidebar-scrim"
          aria-hidden="true"
          onClick={onCloseMobile}
        />
      )}
      <aside className={`sidebar ${mobileOpen ? 'open' : ''}`} aria-label="Primary navigation">
        <div className="sidebar-brand">
          <div className="brand-lockup">
            <div className="brand-icon" aria-hidden="true">
              <Zap size={18} />
            </div>
            <div>
              <div className="brand-title">BoltGate</div>
              <div className="brand-sub">Safe-First Accelerator</div>
            </div>
          </div>
          {mobileOpen && (
            <button
              type="button"
              className="btn btn-sm btn-icon"
              aria-label="Close navigation menu"
              onClick={onCloseMobile}
            >
              <X size={16} aria-hidden="true" />
            </button>
          )}
        </div>

        <nav className="nav-list">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`nav-btn ${isActive ? 'active' : ''}`}
                aria-current={isActive ? 'page' : undefined}
                onClick={() => {
                  onSelectTab(item.id);
                  onCloseMobile();
                }}
              >
                <span className="nav-btn-left">
                  <Icon size={17} aria-hidden="true" />
                  <span>{item.label}</span>
                </span>
                {item.count !== undefined && item.count > 0 && (
                  <span className={`nav-badge num ${item.badgeTone ?? ''}`}>{item.count}</span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-telemetry">
          <div className="telemetry-card">
            <div className="telemetry-row">
              <span className="telemetry-label">Throughput</span>
              <span className="num" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                {stats.activeStreamsCount} streams
              </span>
            </div>
            <div className="telemetry-speed num">{formatSpeed(stats.totalSpeedBps)}</div>
            <svg
              className="sparkline-svg"
              viewBox="0 0 220 32"
              preserveAspectRatio="none"
              aria-hidden="true"
            >
              <polyline
                fill="none"
                stroke="var(--accent)"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                points={sparkPoints}
              />
            </svg>
            <div className="telemetry-row" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              <span>Cap</span>
              <span className="num">
                {settings.speedLimitKBps === 0
                  ? 'Unlimited'
                  : `${(settings.speedLimitKBps / 1024).toFixed(1)} MB/s`}
              </span>
            </div>
          </div>

          <div className="telemetry-card">
            <div className="telemetry-row">
              <span className="telemetry-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <HardDrive size={12} aria-hidden="true" />
                Storage Free
              </span>
              <span className="num" style={{ fontSize: 12.5, fontWeight: 600 }}>
                {diskSpace.freeBytes > 0 ? formatBytes(diskSpace.freeBytes) : '—'}
              </span>
            </div>
            <div className="disk-bar-track" aria-hidden="true">
              <div className="disk-bar-fill" style={{ width: `${usedPct}%` }} />
            </div>
          </div>

          <div className="sidebar-footer">
            <span className="connection-pill">
              <span className={sseConnected ? 'dot-live' : 'dot-offline'} aria-hidden="true" />
              {sseConnected ? 'Engine Ready' : 'Reconnecting…'}
            </span>
            <button
              type="button"
              className="btn btn-sm"
              onClick={onToggleTheme}
              aria-label={`Switch to ${settings.theme === 'dark' ? 'light' : 'dark'} theme`}
            >
              {settings.theme === 'dark' ? (
                <>
                  <Sun size={14} aria-hidden="true" /> Light
                </>
              ) : (
                <>
                  <Moon size={14} aria-hidden="true" /> Dark
                </>
              )}
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
