import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Upload,
  Server,
  Lock,
  ShieldAlert,
  Brain,
  ListOrdered,
  Terminal,
  Activity
} from 'lucide-react';

export interface NavbarProps {
  activeTab?: string;
  onTabChange?: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab = 'dashboard', onTabChange }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'ingestion', label: 'PCAPs & Jobs', icon: Upload },
    { id: 'protocols', label: 'Protocols & Streams', icon: Server },
    { id: 'tls', label: 'TLS & Certificates', icon: Lock },
    { id: 'findings', label: 'Findings & Evidence', icon: ShieldAlert },
    { id: 'posture', label: 'Security Posture', icon: Shield },
    { id: 'ml', label: 'ML & Anomaly AI', icon: Brain },
    { id: 'remediation', label: 'Prioritization & Fixes', icon: ListOrdered },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0e1626]/90 backdrop-blur sticky top-0 z-50 shadow-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Top Header Row */}
        <div className="h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 border border-blue-500/40 flex items-center justify-center text-white shadow-lg shadow-blue-600/20">
              <Shield className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg text-white tracking-tight">SecureMailScope</span>
                <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full bg-blue-950 text-blue-400 border border-blue-800">
                  SIH26159
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Cryptographic Posture & Passive Forensics Platform</p>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="hidden md:flex items-center space-x-2 text-xs text-slate-400 bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-800">
              <Terminal className="h-3.5 w-3.5 text-blue-400" />
              <span>Stage 20 Security Dashboard</span>
            </div>
            <div className="flex items-center space-x-1.5 text-xs font-semibold text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-3 py-1.5 rounded-full shadow-inner">
              <Activity className="h-3.5 w-3.5 animate-pulse text-emerald-400" />
              <span>Live Engine Ready</span>
            </div>
          </div>
        </div>

        {/* Tab Navigation Row */}
        {onTabChange && (
          <div className="flex items-center space-x-1 overflow-x-auto py-2 border-t border-slate-800/60 scrollbar-none">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        )}

      </div>
    </header>
  );
};
