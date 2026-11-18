"use client";

import "./globals.css";
import Link from "next/navigation";
import { usePathname } from "next/navigation";
import { 
  Shield, 
  Target, 
  Play, 
  AlertTriangle, 
  FileText, 
  Lock, 
  FlaskConical, 
  Activity,
  CheckCircle,
  LogOut
} from "lucide-react";
import { useState, useEffect } from "react";
import { api } from "@/lib/api";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [user, setUser] = useState<any>(null);
  const [loginModalOpen, setLoginModalOpen] = useState(false);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("Admin@12345");
  const [loginError, setLoginError] = useState("");

  useEffect(() => {
    // Attempt auto-login or load stored token
    const token = localStorage.getItem("sec_auth_token");
    if (token) {
      api.auth.getMe().then(setUser).catch(() => {
        // Stored token expired, auto login as default admin for smooth zero-friction dev
        performAutoLogin();
      });
    } else {
      performAutoLogin();
    }
  }, []);

  const performAutoLogin = async () => {
    try {
      const res = await api.auth.login({ username: "admin", password: "Admin@12345" });
      localStorage.setItem("sec_auth_token", res.access_token);
      setUser(res.user);
    } catch (_) {
      // Manual login needed
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    try {
      const res = await api.auth.login({ username, password });
      localStorage.setItem("sec_auth_token", res.access_token);
      setUser(res.user);
      setLoginModalOpen(false);
    } catch (err: any) {
      setLoginError(err.message || "Invalid credentials");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("sec_auth_token");
    setUser(null);
  };

  const navItems = [
    { name: "Dashboard", href: "/", icon: Activity },
    { name: "Target Registry", href: "/targets", icon: Target },
    { name: "Scan Console", href: "/scans", icon: Play },
    { name: "Findings & Evidence", href: "/findings", icon: AlertTriangle },
    { name: "Audit Trail", href: "/audit", icon: Lock },
    { name: "Safe Lab", href: "/lab", icon: FlaskConical },
    { name: "Reports", href: "/reports", icon: FileText },
  ];

  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col bg-[#070b14] text-slate-100 antialiased selection:bg-cyan-500 selection:text-black">
        {/* Prominent Authorized Target Only Indicator Banner */}
        <header className="bg-gradient-to-r from-emerald-950 via-teal-950 to-slate-900 border-b border-emerald-700/40 text-emerald-300 px-4 py-2 text-xs font-mono flex items-center justify-between shadow-lg">
          <div className="flex items-center space-x-2">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500 text-slate-950 uppercase tracking-wider">
              Enforced Policy
            </span>
            <span className="font-semibold text-emerald-200">
              AUTHORIZED TARGET ONLY MODE
            </span>
            <span className="text-emerald-400/60 hidden md:inline">
              — Strictly gated to pre-registered targets with verified written consent.
            </span>
          </div>
          <div className="flex items-center space-x-4 text-[11px]">
            <span className="inline-flex items-center text-emerald-400">
              <CheckCircle className="w-3.5 h-3.5 mr-1 text-emerald-400" />
              Pre-Flight Gate: Active
            </span>
            {user ? (
              <div className="flex items-center space-x-2 border-l border-emerald-700/50 pl-4">
                <span className="text-slate-300">Operator:</span>
                <span className="text-cyan-300 font-bold">{user.username} ({user.role})</span>
                <button
                  onClick={handleLogout}
                  className="text-slate-400 hover:text-rose-400 ml-1 p-1 transition"
                  title="Log out"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setLoginModalOpen(true)}
                className="text-cyan-400 hover:text-cyan-300 font-bold underline"
              >
                Operator Login
              </button>
            )}
          </div>
        </header>

        {/* Main Navigation Bar */}
        <nav className="bg-[#0b1222]/90 backdrop-blur border-b border-slate-800/80 sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center space-x-8">
            <a href="/" className="flex items-center space-x-2.5 text-slate-100 hover:opacity-90 transition">
              <div className="bg-gradient-to-tr from-cyan-600 to-emerald-500 p-2 rounded-lg shadow-md shadow-cyan-500/10">
                <Shield className="w-5 h-5 text-slate-950 font-extrabold" />
              </div>
              <div>
                <span className="font-bold text-base tracking-tight font-mono text-slate-100">
                  DEFENSE<span className="text-cyan-400">AUDIT</span>
                </span>
                <span className="text-[10px] block font-mono text-cyan-400/80 -mt-1 tracking-wider uppercase">
                  Vulnerability Platform
                </span>
              </div>
            </a>

            <div className="hidden lg:flex items-center space-x-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.href;
                return (
                  <a
                    key={item.href}
                    href={item.href}
                    className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-medium font-mono transition-all ${
                      isActive
                        ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm"
                        : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                    }`}
                  >
                    <Icon className={`w-3.5 h-3.5 ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
                    <span>{item.name}</span>
                  </a>
                );
              })}
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span className="hidden sm:inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-mono bg-slate-800 border border-slate-700 text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse" />
              Safe Non-Destructive Engine
            </span>
          </div>
        </nav>

        {/* Main Content View */}
        <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8">
          {children}
        </main>

        {/* Login Modal */}
        {loginModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
            <div className="bg-[#0f172a] border border-slate-700 rounded-xl p-6 max-w-md w-full shadow-2xl">
              <h3 className="text-lg font-bold text-slate-100 mb-2 font-mono flex items-center">
                <Lock className="w-4 h-4 mr-2 text-cyan-400" /> Operator Authentication
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                Access authorized security auditing capabilities. Default admin: <code className="text-cyan-300">admin</code> / <code className="text-cyan-300">Admin@12345</code>
              </p>

              {loginError && (
                <div className="bg-rose-950/50 border border-rose-700/50 text-rose-300 text-xs p-2.5 rounded-md mb-4">
                  {loginError}
                </div>
              )}

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>
                <div className="flex justify-end space-x-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setLoginModalOpen(false)}
                    className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 py-1.5 rounded text-xs transition"
                  >
                    Sign In
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Global Footer */}
        <footer className="border-t border-slate-800/60 bg-[#070b14] py-6 px-8 text-center text-xs text-slate-500 font-mono">
          DefenseAudit Platform — Authorized Defensive Vulnerability Analysis & Compliance Engine.<br/>
          Strictly prohibited from weaponized exploitation, credential theft, or unauthorized target scanning.
        </footer>
      </body>
    </html>
  );
}
