import type { Target } from '../types';
import { ShieldCheck, ShieldAlert, FileSignature } from 'lucide-react';

interface ScopeBannerProps {
  target: Target;
  onOpenRoEModal: () => void;
}

export const ScopeBanner = ({ target, onOpenRoEModal }: ScopeBannerProps) => {
  const isAuthorized = !!target.authorizationRecord;

  return (
    <div className={`p-4 rounded-xl border flex items-center justify-between ${
      isAuthorized 
        ? 'bg-emerald-950/30 border-emerald-800/50 text-emerald-200' 
        : 'bg-amber-950/30 border-amber-800/50 text-amber-200'
    }`}>
      <div className="flex items-center gap-3">
        {isAuthorized ? (
          <ShieldCheck className="w-6 h-6 text-emerald-400" />
        ) : (
          <ShieldAlert className="w-6 h-6 text-amber-400" />
        )}
        <div>
          <div className="font-semibold flex items-center gap-2">
            Target Authorization Status: 
            <span className={isAuthorized ? 'text-emerald-400' : 'text-amber-400'}>
              {isAuthorized ? 'AUTHORIZED & SIGNED' : 'UNAUTHORIZED (ACTIVE SCANS LOCKED)'}
            </span>
          </div>
          <div className="text-xs opacity-80 mt-0.5">
            {isAuthorized 
              ? `Signed by ${target.authorizationRecord?.acknowledgedBy} on ${new Date(target.authorizationRecord?.signedAt || '').toLocaleDateString()}`
              : 'Legal Rules of Engagement (RoE) signature required before running active DAST/Nuclei scans.'
            }
          </div>
        </div>
      </div>

      {!isAuthorized && (
        <button
          onClick={onOpenRoEModal}
          className="flex items-center gap-2 bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs px-3.5 py-2 rounded-lg transition"
        >
          <FileSignature className="w-4 h-4" />
          Sign Rules of Engagement
        </button>
      )}
    </div>
  );
};
