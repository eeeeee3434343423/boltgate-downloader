import type { FileCategory, RiskLevel } from '../../shared/types';

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return 'Unknown size';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  const decimals = idx === 0 ? 0 : val >= 100 ? 0 : val >= 10 ? 1 : 2;
  return `${val.toFixed(decimals)} ${units[idx]}`;
}

export function formatSpeed(bps: number | null | undefined): string {
  if (!bps || !Number.isFinite(bps) || bps <= 0) return '0 KB/s';
  if (bps < 1024) return `${Math.round(bps)} B/s`;
  const kbps = bps / 1024;
  if (kbps < 1024) return `${kbps >= 100 ? Math.round(kbps) : kbps.toFixed(1)} KB/s`;
  const mbps = kbps / 1024;
  return `${mbps >= 100 ? Math.round(mbps) : mbps.toFixed(1)} MB/s`;
}

export function formatEta(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return '—';
  }
  if (seconds === 0) return 'Done';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function formatRelativeTime(timestamp?: number): string {
  if (!timestamp) return '—';
  const diffSec = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (diffSec < 10) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return new Date(timestamp).toLocaleDateString();
}

export function categoryLabel(category: FileCategory): string {
  switch (category) {
    case 'ebook':
      return 'Ebook';
    case 'video':
      return 'Video';
    case 'audio':
      return 'Audio';
    case 'archive':
      return 'Archive';
    case 'software':
      return 'Software';
    case 'document':
      return 'Document';
    case 'image':
      return 'Image';
    case 'disk':
      return 'Disk Image';
    default:
      return 'Other';
  }
}

export function riskMeta(risk: RiskLevel): {
  label: string;
  tone: 'ok' | 'warn' | 'danger' | 'error';
} {
  switch (risk) {
    case 'safe':
      return { label: 'Low Risk', tone: 'ok' };
    case 'caution':
      return { label: 'Caution', tone: 'warn' };
    case 'high_risk':
      return { label: 'High Risk', tone: 'danger' };
    case 'error':
      return { label: 'Probe Error', tone: 'error' };
  }
}
