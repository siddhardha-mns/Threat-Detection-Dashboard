import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="h-10 border-t border-slate-800/80 bg-slate-950 px-6 flex items-center justify-between text-[11px] text-slate-500 shrink-0">
      <div className="flex items-center gap-3">
        <span>Team:</span>
        <span className="text-slate-400">Member A (ML)</span>
        <span className="text-slate-700" aria-hidden="true">·</span>
        <span className="text-slate-400">Member B (NLP & Risk)</span>
        <span className="text-slate-700" aria-hidden="true">·</span>
        <span className="text-slate-400">Member C (Dashboard & Integration)</span>
      </div>

      <div className="flex items-center gap-3 font-mono">
        <span>Dataset: NSL-KDD</span>
        <span className="text-slate-700" aria-hidden="true">·</span>
        <span>Version 1.0.4</span>
      </div>
    </footer>
  );
};
