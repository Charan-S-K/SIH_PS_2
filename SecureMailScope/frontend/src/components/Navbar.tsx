import React from 'react';
import { Shield, Activity, Terminal } from 'lucide-react';

export const Navbar: React.FC = () => {
  return (
    <header className="border-b border-slate-800 bg-[#0e1626]/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Shield className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg text-slate-100 tracking-tight">SecureMailScope</span>
              <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
                SIH26159
              </span>
            </div>
            <p className="text-xs text-slate-400">AI-Assisted Cryptographic Security Posture Assessment</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="hidden md:flex items-center space-x-2 text-xs text-slate-400 bg-slate-900 px-3 py-1.5 rounded-md border border-slate-800">
            <Terminal className="h-3.5 w-3.5 text-blue-400" />
            <span>Passive Forensic Pipeline</span>
          </div>
          <div className="flex items-center space-x-1.5 text-xs font-medium text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-3 py-1.5 rounded-full">
            <Activity className="h-3.5 w-3.5 animate-pulse" />
            <span>Stage 01 PCAP Upload & Jobs</span>
          </div>
        </div>
      </div>
    </header>
  );
};
