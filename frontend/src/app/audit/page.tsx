"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { AuditLog, AuditVerification } from "@/types";
import { 
  ShieldCheck, 
  ShieldAlert, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  Hash, 
  Clock, 
  User, 
  Activity, 
  Link2, 
  ChevronRight,
  Filter,
  FileCheck
} from "lucide-react";

export default function AuditTrailPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [actionFilter, setActionFilter] = useState<string>("ALL");

  useEffect(() => {
    loadAuditData();
  }, []);

  const loadAuditData = async () => {
    setLoading(true);
    try {
      const [logsData, verifyData] = await Promise.all([
        api.audit.list().catch(() => []),
        api.audit.verify().catch(() => null),
      ]);
      setLogs(logsData);
      setVerification(verifyData);
      if (logsData.length > 0) {
        setSelectedLog(logsData[0]);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const result = await api.audit.verify();
      setVerification(result);
    } catch (err: any) {
      alert("Error verifying hash chain: " + err.message);
    } finally {
      setVerifying(false);
    }
  };

  const actionTypes = [
    "ALL",
    "TARGET_REGISTERED",
    "AUTHORIZATION_GRANTED",
    "AUTHORIZATION_REVOKED",
    "SCAN_DISPATCHED",
    "SCAN_CANCELLED",
    "SCAN_BLOCKED_UNAUTHORIZED",
    "FINDING_STATUS_CHANGED",
    "REPORT_GENERATED"
  ];

  const filteredLogs = logs.filter((log) => {
    if (actionFilter === "ALL") return true;
    return log.action === actionFilter;
  });

  const getActionBadgeColor = (action: string) => {
    if (action.includes("BLOCKED") || action.includes("CANCELLED") || action.includes("REVOKED")) {
      return "bg-rose-500/10 text-rose-400 border-rose-500/20";
    }
    if (action.includes("AUTHORIZATION") || action.includes("REPORT")) {
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    }
    if (action.includes("SCAN")) {
      return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
    }
    return "bg-slate-500/10 text-slate-300 border-slate-500/20";
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-[#0a1526] to-slate-900 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 mb-2">
            <Link2 className="w-3.5 h-3.5" />
            <span>Cryptographic Proof of Compliance</span>
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-white">
            Tamper-Evident Audit Trail
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Immutable SHA-256 hash-chained log preserving all target registrations, authorization agreements, scan executions, and emergency kills.
          </p>
        </div>

        <button
          onClick={handleVerifyChain}
          disabled={verifying}
          className="flex items-center space-x-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-semibold px-4 py-2.5 rounded-xl shadow-lg shadow-cyan-900/30 transition disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${verifying ? "animate-spin" : ""}`} />
          <span>{verifying ? "Verifying Math..." : "Verify Hash Chain"}</span>
        </button>
      </div>

      {/* Verification Status Banner */}
      {verification && (
        <div className={`p-5 rounded-2xl border shadow-lg ${
          verification.is_valid
            ? "bg-emerald-950/20 border-emerald-500/30 text-emerald-300"
            : "bg-rose-950/20 border-rose-500/30 text-rose-300"
        }`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              {verification.is_valid ? (
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                  <ShieldCheck className="w-6 h-6" />
                </div>
              ) : (
                <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
                  <ShieldAlert className="w-6 h-6" />
                </div>
              )}
              <div>
                <h3 className="text-sm font-bold font-mono uppercase tracking-wider">
                  {verification.is_valid ? "Cryptographic Chain Integrity Verified" : "Integrity Failure Detected"}
                </h3>
                <p className="text-xs opacity-80 mt-0.5">
                  {verification.is_valid
                    ? `All ${verification.total_records_checked} sequential records validated against root genesis zero block.`
                    : `Hash mismatch at sequence index #${verification.broken_sequence_index}: ${verification.error_message}`}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Blocks Verified</span>
                <span className="text-white font-bold">{verification.total_records_checked}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Genesis Block</span>
                <span className="text-cyan-400 font-mono text-[11px] truncate block w-28" title={verification.root_genesis_hash}>
                  {verification.root_genesis_hash.slice(0, 10)}...
                </span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Latest Leaf</span>
                <span className="text-emerald-400 font-mono text-[11px] truncate block w-28" title={verification.latest_leaf_hash}>
                  {verification.latest_leaf_hash ? `${verification.latest_leaf_hash.slice(0, 10)}...` : "Genesis"}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter and Content Grid */}
      <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Filter Action:</span>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
          >
            {actionTypes.map((act) => (
              <option key={act} value={act}>{act}</option>
            ))}
          </select>
        </div>
        <div className="text-xs font-mono text-slate-500">
          Showing {filteredLogs.length} of {logs.length} logged operations
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Chain Sequence List */}
        <div className="lg:col-span-2 space-y-3 max-h-[750px] overflow-y-auto pr-1">
          {filteredLogs.length === 0 ? (
            <div className="bg-[#0e1628] border border-slate-800 rounded-xl p-8 text-center text-slate-400 font-mono text-xs">
              No audit records found matching the selected filter.
            </div>
          ) : (
            filteredLogs.map((log, idx) => {
              const isSelected = selectedLog?.id === log.id;
              let details: any = {};
              try {
                details = typeof log.details_json === "string" ? JSON.parse(log.details_json) : log.details_json;
              } catch (_) {}

              return (
                <div
                  key={log.id || idx}
                  onClick={() => setSelectedLog(log)}
                  className={`p-4 rounded-xl border transition cursor-pointer relative ${
                    isSelected
                      ? "bg-slate-900/90 border-cyan-500/60 shadow-lg shadow-cyan-950/20"
                      : "bg-[#0e1628]/80 border-slate-800/80 hover:border-slate-700 hover:bg-[#0e1628]"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center space-x-3">
                      <span className="font-mono text-xs font-extrabold px-2 py-1 rounded bg-slate-950 border border-slate-800 text-slate-300">
                        #{log.sequence_number}
                      </span>
                      <div>
                        <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${getActionBadgeColor(log.action)}`}>
                          {log.action}
                        </span>
                        <div className="flex items-center space-x-3 text-[11px] text-slate-400 font-mono mt-1">
                          <span className="flex items-center space-x-1">
                            <Clock className="w-3 h-3 text-slate-500" />
                            <span>{new Date(log.timestamp).toLocaleString()}</span>
                          </span>
                          {log.client_ip && (
                            <span>IP: {log.client_ip}</span>
                          )}
                        </div>
                      </div>
                    </div>
                    <ChevronRight className={`w-4 h-4 transition ${isSelected ? "text-cyan-400 translate-x-1" : "text-slate-600"}`} />
                  </div>

                  {/* Hash connector preview */}
                  <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-500">
                    <div className="truncate max-w-[45%]">
                      <span className="text-slate-600">PREV:</span> {log.previous_entry_hash.slice(0, 12)}...
                    </div>
                    <div className="text-cyan-500/80">➔</div>
                    <div className="truncate max-w-[45%] text-right text-slate-400">
                      <span className="text-slate-600">HASH:</span> {log.entry_hash.slice(0, 12)}...
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right: Detailed Block Inspector */}
        <div className="bg-[#0e1628] border border-slate-800 rounded-2xl p-5 shadow-lg h-fit sticky top-24">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div className="flex items-center space-x-2">
              <Hash className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold font-mono text-white">Block Details</h3>
            </div>
            {selectedLog && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Seq #{selectedLog.sequence_number}
              </span>
            )}
          </div>

          {selectedLog ? (
            <div className="space-y-4 font-mono text-xs">
              <div>
                <span className="text-[10px] text-slate-500 uppercase block mb-1">Action</span>
                <span className={`inline-block px-2 py-1 rounded text-xs font-semibold border ${getActionBadgeColor(selectedLog.action)}`}>
                  {selectedLog.action}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Resource Type</span>
                  <span className="text-slate-200">{selectedLog.resource_type}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Client IP</span>
                  <span className="text-slate-200">{selectedLog.client_ip || "127.0.0.1"}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-[10px] text-slate-500 uppercase block">Timestamp</span>
                  <span className="text-slate-300">{new Date(selectedLog.timestamp).toISOString()}</span>
                </div>
              </div>

              {/* Cryptographic Hashes */}
              <div className="space-y-2 bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Previous Entry Hash (H_prev)</span>
                  <p className="text-[10px] text-slate-400 break-all bg-slate-900 p-1.5 rounded border border-slate-800/80 mt-1">
                    {selectedLog.previous_entry_hash}
                  </p>
                </div>
                <div>
                  <span className="text-[10px] text-cyan-400 uppercase block font-bold">This Block Entry Hash (H_cur)</span>
                  <p className="text-[10px] text-cyan-300 break-all bg-cyan-950/20 p-1.5 rounded border border-cyan-500/30 mt-1">
                    {selectedLog.entry_hash}
                  </p>
                </div>
              </div>

              {/* Parsed Details */}
              <div>
                <span className="text-[10px] text-slate-500 uppercase block mb-1">Payload Details</span>
                <pre className="text-[11px] bg-slate-950 p-3 rounded-xl border border-slate-800 overflow-x-auto text-emerald-400 font-mono max-h-56">
                  {JSON.stringify(
                    typeof selectedLog.details_json === "string"
                      ? JSON.parse(selectedLog.details_json)
                      : selectedLog.details_json,
                    null,
                    2
                  )}
                </pre>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500 font-mono text-center py-8">
              Select a block from the chain to inspect cryptographic proofs.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
