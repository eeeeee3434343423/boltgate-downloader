import { RotateCcw, X } from 'lucide-react';

export interface ToastNotice {
  id: string;
  message: string;
  onUndo?: () => Promise<void> | void;
  tone?: 'info' | 'error';
}

interface ToastProps {
  notice: ToastNotice | null;
  onDismiss: () => void;
}

export function Toast({ notice, onDismiss }: ToastProps) {
  if (!notice) return null;

  return (
    <div className="toast-container" role="status" aria-live="polite">
      <div className="toast">
        <span>{notice.message}</span>
        {notice.onUndo && (
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => {
              void notice.onUndo?.();
              onDismiss();
            }}
          >
            <RotateCcw size={14} aria-hidden="true" />
            Undo
          </button>
        )}
        <button
          type="button"
          className="btn btn-sm btn-icon"
          aria-label="Dismiss notification"
          onClick={onDismiss}
          style={{
            background: 'transparent',
            borderColor: 'rgba(255,255,255,0.28)',
            color: '#f8fafc',
          }}
        >
          <X size={15} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}
