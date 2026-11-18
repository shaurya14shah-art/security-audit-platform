"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { 
  Play, 
  AlertOctagon, 
  CheckCircle2, 
  Clock, 
  XCircle, 
  ShieldAlert, 
  RefreshCw,
  Sliders,
  ExternalLink
} from "lucide-react";

export default function ScansPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [launchModalOpen, setLaunchModalOpen] = useState(false);

  // Scan Launch Form
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [scanMode, setScanMode] = useState("passive");
  const [rateLimit, setRateLimit] = useState(5.0);
  const [maxRequests, setMaxRequests] = useState(100);
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    loadData();
    const interval = setInterval(loadScansOnly, 3000); // Live poll scan updates every 3s
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [sList, tList] = await Promise.all([
        api.scans.list(),
        api.targets.list(),
      ]);
      setScans(sList);
      setTargets(tList);
      const authorizedTargets = tList.filter((t) => t.has_active_authorization);
      if (authorizedTargets.length > 0 && !selectedTargetId) {
        setSelectedTargetId(authorizedTargets[0].id);
      }
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const loadScansOnly = async () => {
    try {
      const sList = await api.scans.list();
      setScans(sList);
    } catch (_) {}
  };

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    try {
      await api.scans.launch({
        target_id: selectedTargetId,
        scan_mode: scanMode,
        rate_limit_per_second: rateLimit,
        max_requests: maxRequests,
      });
      setLaunchModalOpen(false);
      loadScansOnly();
    } catch (e: any) {
      setErrorMsg(e.message);
    }
  };

  const handleKillSwitch = async (scanId: string) => {
    if (!confirm("EMERGENCY KILL SWITCH: Immediately terminate active network operations for this scan job?")) return;
    try {
      await api.scans.cancel(scanId);
      loadScansOnly();
    } catch (e: any) {
      alert(e.message);
    }
  };

  const authorizedTargets = targets.filter((t) => t.has_active_authorization);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center">
            <Play className="w-5 h-5 mr-2 text-cyan-400" />
            Scan Orchestration Console
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Dispatch authorized passive analyses and safe active checks. Equipped with an emergency kill-switch.
          </p>
        </div>

        <button
          onClick={() => setLaunchModalOpen(true)}
          className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 px-4 py-2 rounded-lg text-xs font-mono font-bold flex items-center transition shadow-md shadow-cyan-500/10"
        >
          <Play className="w-3.5 h-3.5 mr-1.5 fill-current" />
          Launch Scan Job
        </button>
      </div>

      {errorMsg && (
        <div className="bg-rose-950/60 border border-rose-700/60 text-rose-300 p-3 rounded-lg text-xs font-mono">
          {errorMsg}
        </div>
      )}

      {/* Scans Table */}
      <div className="bg-[#0b1222] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-6 py-3.5 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>Active & Historical Scan Jobs ({scans.length})</span>
          <button onClick={loadScansOnly} className="flex items-center text-cyan-400 hover:text-cyan-300">
            <RefreshCw className="w-3 h-3 mr-1" /> Refresh
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/30 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="px-6 py-3.5">Scan Job / Mode</th>
                <th className="px-6 py-3.5">Phase & Progress</th>
                <th className="px-6 py-3.5">Telemetry</th>
                <th className="px-6 py-3.5">Findings</th>
                <th className="px-6 py-3.5 text-right">Controls</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                    No scans registered. Click 'Launch Scan Job' to test an authorized target.
                  </td>
                </tr>
              ) : (
                scans.map((s) => {
                  const isRunning = s.status === "running" || s.status === "pending";
                  return (
                    <tr key={s.id} className="hover:bg-slate-850/40 transition">
                      <td className="px-6 py-4">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-slate-100 uppercase">{s.scan_mode}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            s.status === "completed" ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" :
                            s.status === "running" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 animate-pulse" :
                            s.status === "cancelled" ? "bg-amber-500/20 text-amber-300 border border-amber-500/30" :
                            s.status === "blocked_unauthorized" ? "bg-rose-500/20 text-rose-300 border border-rose-500/30" :
                            "bg-slate-800 text-slate-300"
                          }`}>
                            {s.status}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono mt-1">
                          ID: {s.id.slice(0, 8)} · Started: {s.created_at ? s.created_at.slice(0, 19).replace("T", " ") : "N/A"}
                        </div>
                        {s.cancellation_reason && (
                          <div className="text-[10px] text-rose-400/80 mt-0.5">
                            Reason: {s.cancellation_reason}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 w-1/3">
                        <div className="flex items-center justify-between text-[11px] mb-1">
                          <span className="text-slate-300">{s.current_phase}</span>
                          <span className="text-cyan-400 font-bold">{s.progress}%</span>
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full transition-all duration-300 ${
                              s.status === "completed" ? "bg-emerald-400" :
                              s.status === "cancelled" ? "bg-amber-400" :
                              s.status === "blocked_unauthorized" ? "bg-rose-500" :
                              "bg-cyan-400"
                            }`}
                            style={{ width: `${s.progress}%` }}
                          />
                        </div>
                      </td>
                      <td className="px-6 py-4 text-slate-400 text-[11px]">
                        <div>Requests: {s.total_requests_sent}</div>
                        <div>Duration: {s.completed_at ? "Finished" : isRunning ? "In flight" : "Queued"}</div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-slate-800 text-cyan-300">
                          {s.findings_count} Issue(s)
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right space-x-2">
                        {isRunning ? (
                          <button
                            onClick={() => handleKillSwitch(s.id)}
                            className="bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-600/50 px-2.5 py-1 rounded text-xs font-bold transition flex items-center ml-auto"
                            title="Emergency Kill Switch"
                          >
                            <AlertOctagon className="w-3.5 h-3.5 mr-1" />
                            KILL SWITCH
                          </button>
                        ) : (
                          <a
                            href={`/findings?scan_id=${s.id}`}
                            className="text-cyan-400 hover:text-cyan-300 text-xs hover:underline inline-flex items-center"
                          >
                            View Findings <ExternalLink className="w-3 h-3 ml-1" />
                          </a>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Launch Scan Modal */}
      {launchModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#0f172a] border border-cyan-500/40 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <h3 className="text-base font-bold font-mono text-white flex items-center">
              <Play className="w-4 h-4 mr-2 text-cyan-400 fill-current" />
              Configure & Launch Scan Job
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              The Scope Gatekeeper will verify that the chosen target possesses an active authorization record before starting.
            </p>

            <form onSubmit={handleLaunchScan} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Target Asset</label>
                {authorizedTargets.length === 0 ? (
                  <div className="p-3 bg-rose-950/40 border border-rose-700/50 rounded text-rose-300 text-xs">
                    No authorized targets available. Please register and sign authorization for a target first.
                  </div>
                ) : (
                  <select
                    value={selectedTargetId}
                    onChange={(e) => setSelectedTargetId(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                    required
                  >
                    {authorizedTargets.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name} ({t.target_url}) — Mode: {t.target_mode}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Scan Mode</label>
                <select
                  value={scanMode}
                  onChange={(e) => setScanMode(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="passive">Passive Analysis (Headers, Cookies, TLS, Metadata)</option>
                  <option value="safe_active">Safe Active Testing (HTTP Methods, CORS, Safe Input Boundaries)</option>
                  <option value="lab_simulation">Local Lab Simulation (OWASP Top 10 Toy App Checks)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Rate Limit (req/sec)</label>
                  <input
                    type="number"
                    step="0.5"
                    min="0.5"
                    max="15"
                    value={rateLimit}
                    onChange={(e) => setRateLimit(parseFloat(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Max Requests</label>
                  <input
                    type="number"
                    min="10"
                    max="300"
                    value={maxRequests}
                    onChange={(e) => setMaxRequests(parseInt(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="p-3 bg-slate-900 border border-slate-800 rounded text-[11px] text-slate-400 space-y-1">
                <div className="text-slate-300 font-bold">Safety Guarantees:</div>
                <div>• Zero destructive payloads or credential stuffing</div>
                <div>• Emergency kill-switch available at all times</div>
                <div>• Every request logged to tamper-evident audit trail</div>
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setLaunchModalOpen(false)}
                  className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={authorizedTargets.length === 0}
                  className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold px-4 py-1.5 rounded transition shadow-md shadow-cyan-500/10"
                >
                  Confirm & Dispatch Scan
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
