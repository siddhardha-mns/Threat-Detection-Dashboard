import React, { useState } from 'react';
import { X, Copy, Check, Download, FileCode2, Terminal } from 'lucide-react';
import { PYTHON_SCRIPTS, PythonScript } from '../data/pythonExports';

interface PythonScriptsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const PythonScriptsModal: React.FC<PythonScriptsModalProps> = ({ isOpen, onClose }) => {
  const [selectedScript, setSelectedScript] = useState<PythonScript>(PYTHON_SCRIPTS[0]);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(selectedScript.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([selectedScript.code], { type: 'text/x-python' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedScript.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-5xl w-full h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <FileCode2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                <span>Python Pipeline & ML Scripts</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                  {PYTHON_SCRIPTS.length} Modules Ready
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Direct implementation files specified in the 5-Day project architecture
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy Code'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .py</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body: Split view of script list & code display */}
        <div className="flex-1 flex overflow-hidden">
          {/* File Selector Sidebar */}
          <div className="w-72 border-r border-slate-800 bg-slate-950/60 p-3 overflow-y-auto space-y-1">
            <p className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
              Project Architecture Files
            </p>
            {PYTHON_SCRIPTS.map((script) => {
              const isSelected = selectedScript.filename === script.filename;
              return (
                <button
                  key={script.filename}
                  onClick={() => setSelectedScript(script)}
                  className={`w-full text-left p-2.5 rounded-lg text-xs transition-colors flex flex-col gap-1 border ${
                    isSelected
                      ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-medium">{script.filename}</span>
                    <span className="text-[10px] text-slate-500">{script.owner.split(' ')[0]}</span>
                  </div>
                  <span className="text-[11px] text-slate-500 line-clamp-1">{script.description}</span>
                </button>
              );
            })}
          </div>

          {/* Code Viewer */}
          <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden">
            <div className="px-5 py-2.5 border-b border-slate-800/80 bg-slate-900/50 flex items-center justify-between text-xs text-slate-400 font-mono">
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-slate-200 font-semibold">{selectedScript.module}</span>
                <span className="text-slate-600">·</span>
                <span className="text-slate-400">{selectedScript.owner}</span>
              </div>
              <span>Python 3.10+ / scikit-learn</span>
            </div>

            <div className="flex-1 p-4 overflow-auto font-mono text-xs text-slate-300 leading-relaxed bg-[#060a12]">
              <pre className="selection:bg-emerald-500/30 selection:text-emerald-200">
                <code>{selectedScript.code}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
