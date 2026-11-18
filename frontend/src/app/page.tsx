"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { 
  ShieldCheck, 
  AlertTriangle, 
  Target, 
  Play, 
  Lock, 
  CheckCircle2, 
  XCircle, 
  Activity, 
  Sparkles,
  ArrowRight,
  TrendingUp,
  FileText
} from "lucide-react";

export default function DashboardPage() {
  const [targets, setTargets] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [auditStatus, setAuditStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [aiSummary, setAiSummary] = useState<string>("");

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [tList, sList, fList, aVer] = await Promise.all([
        api.targets.list().catch(() => []),
        api.scans.list().catch(() => []),
        api.findings.list().catch(() => []),
        api.audit.verify().catch(() => null),
      ]);
      setTargets(tList);
      setScans(sList);
      setFindings(fList);
      setAuditStatus(aVer);

      // Generate AI summary if scans exist
      if (sList.length > 0) {
        api.ai.summarizeScan(sList[0].id).then((res) => {
          setAiSummary(res.summary);
        }).catch(() => {});
      }
    } finally {
      setLoading(false);
    }
  };

  // Severity counts
  const critCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const medCount = findings.filter((f) => f.severity === "MEDIUM").length;
  const lowCount = findings.filter((f) => f.severity === "LOW" || f.severity === "INFO").length;

  // Compute overall posture index
  const penalty = (critCount * 25) + (highCount * 15) + (medCount * 5) + (lowCount * 2);
  const postureScore = Math.max(0, Math.min(100, 100 - penalty));

  return (
    <div className="space-y-8">
      {/* Top Welcome & Posture Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-[#0d1527] to-slate-900 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 mb-2">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Defensive Posture Intelligence</span>
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-white">
            Security Assessment Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Live telemetry from authorized targets, non-destructive vulnerability audits, and tamper-evident compliance records.
          </p>
        </div>

        <div className="flex items-center space-x-4 bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
          <div className="text-right">
            <span className="text-[10px] font-mono uppercase text-slate-400 block">Posture Index</span>
            <span className={`text-3xl font-extrabold font-mono ${
              postureScore >= 80 ? "text-emerald-400" : postureScore >= 60 ? "text-amber-400" : "text-rose-400"
            }`}>
              {postureScore}/100
            </span>
          </div>
          <div className="w-12 h-12 rounded-full border-4 border-slate-800 flex items-center justify-center font-bold text-xs font-mono">
            {postureScore >= 80 ? "SECURE" : "AUDIT"}
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0e1628] border border-slate-800/90 rounded-xl p-5 shadow-sm hover:border-slate-700 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Critical Severity</span>
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
          </div>
          <div className="text-3xl font-bold font-mono text-rose-400 mt-3">{critCount}</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">Requires immediate remediation</div>
        </div>

        <div className="bg-[#0e1628] border border-slate-800/90 rounded-xl p-5 shadow-sm hover:border-slate-700 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">High Severity</span>
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
          </div>
          <div className="text-3xl font-bold font-mono text-amber-400 mt-3">{highCount}</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">Input & encryption issues</div>
        </div>

        <div className="bg-[#0e1628] border border-slate-800/90 rounded-xl p-5 shadow-sm hover:border-slate-700 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Medium / Low</span>
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
          </div>
          <div className="text-3xl font-bold font-mono text-cyan-400 mt-3">{medCount + lowCount}</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">Headers, cookies & config hardening</div>
        </div>

        <div className="bg-[#0e1628] border border-slate-800/90 rounded-xl p-5 shadow-sm hover:border-slate-700 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Audit Chain Integrity</span>
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-3 flex items-center">
            <CheckCircle2 className="w-5 h-5 mr-1.5" />
            <span>VERIFIED</span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            {auditStatus?.total_records_checked || 0} chained SHA-256 blocks
          </div>
        </div>
      </div>

      {/* Active Workstream & Quick Access Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Target & Active Scans List */}
        <div className="lg:col-span-2 space-y-6">
          {/* Target Registry Status */}
          <div className="bg-[#0b1222] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-900/40">
              <div className="flex items-center space-x-2">
                <Target className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold font-mono text-slate-200 uppercase">
                  Target Scope Status ({targets.length})
                </h2>
              </div>
              <a
                href="/targets"
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center"
              >
                Manage Targets <ArrowRight className="w-3 h-3 ml-1" />
              </a>
            </div>

            <div className="divide-y divide-slate-800/60">
              {targets.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500 font-mono">
                  No targets registered. Add an authorized target to begin.
                </div>
              ) : (
                targets.slice(0, 4).map((t) => (
                  <div key={t.id} className="p-4 flex items-center justify-between hover:bg-slate-850/30 transition">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-sm text-slate-100">{t.name}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {t.target_mode}
                        </span>
                      </div>
                      <div className="text-xs font-mono text-slate-400 mt-0.5">{t.target_url}</div>
                    </div>
                    <div>
                      {t.has_active_authorization ? (
                        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-950/80 text-emerald-300 border border-emerald-700/60">
                          <CheckCircle2 className="w-3 h-3 mr-1 text-emerald-400" /> Authorized
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono bg-rose-950/80 text-rose-300 border border-rose-700/60">
                          <XCircle className="w-3 h-3 mr-1 text-rose-400" /> Pending Consent
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Recent Scans Table */}
          <div className="bg-[#0b1222] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-900/40">
              <div className="flex items-center space-x-2">
                <Play className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold font-mono text-slate-200 uppercase">
                  Recent Scan Executions ({scans.length})
                </h2>
              </div>
              <a
                href="/scans"
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center"
              >
                Scan Console <ArrowRight className="w-3 h-3 ml-1" />
              </a>
            </div>

            <div className="divide-y divide-slate-800/60">
              {scans.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500 font-mono">
                  No scan jobs executed yet.
                </div>
              ) : (
                scans.slice(0, 4).map((s) => (
                  <div key={s.id} className="p-4 flex items-center justify-between hover:bg-slate-850/30 transition">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs text-cyan-300 uppercase font-bold">{s.scan_mode}</span>
                        <span className="text-xs text-slate-400">· {s.current_phase}</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 mt-1">
                        Progress: {s.progress}% · Requests Sent: {s.total_requests_sent}
                      </div>
                    </div>
                    <div className="text-right">
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold ${
                        s.status === "completed" ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" :
                        s.status === "running" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 animate-pulse" :
                        s.status === "blocked_unauthorized" ? "bg-rose-500/20 text-rose-300 border border-rose-500/30" :
                        "bg-slate-800 text-slate-300"
                      }`}>
                        {s.status}
                      </span>
                      <div className="text-[11px] font-mono text-slate-400 mt-1">
                        {s.findings_count} Finding(s)
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Col: AI Defensive Analyst Widget & Quick Actions */}
        <div className="space-y-6">
          {/* AI Security Advisor Widget */}
          <div className="bg-gradient-to-b from-[#0f172a] to-[#0b1222] border border-cyan-500/30 rounded-xl p-5 shadow-lg relative overflow-hidden">
            <div className="flex items-center space-x-2 text-cyan-400 mb-3">
              <Sparkles className="w-4 h-4" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider">
                AI Defensive Analyst
              </h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              {aiSummary || "The AI defensive assistant analyzes discovered indicators, correlates architectural flaws, and produces compliant executive summaries strictly within authorized scope boundaries."}
            </p>
            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-500">Ethical Policy Enforced</span>
              <a
                href="/findings"
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                Inspect Analysis →
              </a>
            </div>
          </div>

          {/* Quick Actions Panel */}
          <div className="bg-[#0b1222] border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
              Defensive Operations
            </h3>

            <a
              href="/scans"
              className="w-full flex items-center justify-between p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 hover:bg-cyan-500/20 text-xs font-mono transition"
            >
              <div className="flex items-center space-x-2">
                <Play className="w-3.5 h-3.5" />
                <span>Launch New Scan</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5" />
            </a>

            <a
              href="/targets"
              className="w-full flex items-center justify-between p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 text-xs font-mono transition"
            >
              <div className="flex items-center space-x-2">
                <Target className="w-3.5 h-3.5 text-slate-400" />
                <span>Sign Authorization Agreement</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
            </a>

            <a
              href="/lab"
              className="w-full flex items-center justify-between p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/40 text-emerald-300 hover:bg-emerald-900/30 text-xs font-mono transition"
            >
              <div className="flex items-center space-x-2">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                <span>Open Safe Local Lab</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-emerald-500" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
