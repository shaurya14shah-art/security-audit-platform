"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { 
  AlertTriangle, 
  Search, 
  Filter, 
  Sparkles, 
  CheckCircle2, 
  Clock, 
  FileCode, 
  ChevronRight,
  ShieldAlert,
  ArrowRight
} from "lucide-react";

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);

  // AI analysis state
  const [aiAnalysis, setAiAnalysis] = useState<string>("");
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => {
    loadFindings();
  }, [severityFilter, statusFilter]);

  const loadFindings = async () => {
    try {
      const params: Record<string, string> = {};
      if (severityFilter) params.severity = severityFilter;
      if (statusFilter) params.remediation_status = statusFilter;
      const data = await api.findings.list(params);
      setFindings(data);
      if (data.length > 0 && !selectedFinding) {
        setSelectedFinding(data[0]);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateRemediation = async (status: string) => {
    if (!selectedFinding) return;
    try {
      const updated = await api.findings.updateRemediation(selectedFinding.id, {
        remediation_status: status,
      });
      setSelectedFinding(updated);
      setFindings(findings.map((f) => (f.id === updated.id ? updated : f)));
    } catch (e: any) {
      alert(e.message);
    }
  };

  const handleAskAI = async () => {
    if (!selectedFinding) return;
    setAiLoading(true);
    setAiAnalysis("");
    try {
      const res = await api.ai.explainFinding(selectedFinding.id);
      setAiAnalysis(res.analysis);
    } catch (e: any) {
      setAiAnalysis("Could not fetch AI analysis: " + e.message);
    } finally {
      setAiLoading(false);
    }
  };

  const filteredFindings = findings.filter((f) => {
    if (!searchTerm) return true;
    return (
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.affected_asset.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.cwe_id && f.cwe_id.toLowerCase().includes(searchTerm.toLowerCase()))
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2 text-cyan-400" />
            Vulnerability Findings & Evidence Browser
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Normalized security observations categorized by severity, affected asset, non-destructive reproduction conditions, and remediation status.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3 bg-[#0b1222] border border-slate-800 p-3 rounded-xl text-xs font-mono">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search findings by title, CWE, asset..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="remediated">Remediated</option>
          <option value="verified">Verified</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {/* Split View: List on Left, Detail & Evidence on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Findings List (5 Cols) */}
        <div className="lg:col-span-5 bg-[#0b1222] border border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col h-[750px]">
          <div className="px-4 py-3 bg-slate-900/60 border-b border-slate-800 text-xs font-mono text-slate-400">
            Discovered Issues ({filteredFindings.length})
          </div>

          <div className="overflow-y-auto divide-y divide-slate-800/60 flex-1">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                No findings match the active criteria.
              </div>
            ) : (
              filteredFindings.map((f) => {
                const isSelected = selectedFinding?.id === f.id;
                return (
                  <div
                    key={f.id}
                    onClick={() => {
                      setSelectedFinding(f);
                      setAiAnalysis("");
                    }}
                    className={`p-3.5 cursor-pointer transition font-mono ${
                      isSelected ? "bg-cyan-500/10 border-l-4 border-cyan-500" : "hover:bg-slate-850/40"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        f.severity === "CRITICAL" ? "bg-rose-950 text-rose-300 border border-rose-700/60" :
                        f.severity === "HIGH" ? "bg-amber-950 text-amber-300 border border-amber-700/60" :
                        f.severity === "MEDIUM" ? "bg-yellow-950 text-yellow-300 border border-yellow-700/60" :
                        "bg-slate-800 text-slate-300"
                      }`}>
                        {f.severity}
                      </span>
                      <span className="text-[10px] text-slate-500">{f.cwe_id || "CWE-N/A"}</span>
                    </div>

                    <div className="font-bold text-xs text-slate-200 mt-2 line-clamp-1">
                      {f.title}
                    </div>

                    <div className="text-[11px] text-slate-400 mt-1 line-clamp-1">
                      {f.affected_asset}
                    </div>

                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800/40 text-[10px]">
                      <span className="text-slate-500 uppercase">{f.detection_method.replace(/_/g, " ")}</span>
                      <span className={`capitalize font-semibold ${
                        f.remediation_status === "remediated" ? "text-emerald-400" :
                        f.remediation_status === "in_progress" ? "text-cyan-400" :
                        "text-slate-400"
                      }`}>
                        {f.remediation_status.replace(/_/g, " ")}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Finding Detail & Evidence Drawer (7 Cols) */}
        <div className="lg:col-span-7 bg-[#0b1222] border border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col h-[750px]">
          {selectedFinding ? (
            <div className="overflow-y-auto p-6 space-y-6 font-mono text-xs">
              {/* Finding Title & Badges */}
              <div className="border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-2">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                    selectedFinding.severity === "CRITICAL" ? "bg-rose-950 text-rose-300 border border-rose-700" :
                    selectedFinding.severity === "HIGH" ? "bg-amber-950 text-amber-300 border border-amber-700" :
                    selectedFinding.severity === "MEDIUM" ? "bg-yellow-950 text-yellow-300 border border-yellow-700" :
                    "bg-slate-800 text-slate-300"
                  }`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px]">
                    Risk Score: {selectedFinding.risk_score}/10
                  </span>
                  <span className="text-slate-500 text-[11px]">
                    {selectedFinding.owasp_category} · {selectedFinding.cwe_id}
                  </span>
                </div>

                <h2 className="text-base font-bold text-white mt-2">
                  {selectedFinding.title}
                </h2>
                <div className="text-slate-400 text-xs mt-1">
                  Asset: <code className="text-cyan-300">{selectedFinding.affected_asset}</code>
                </div>
              </div>

              {/* Remediation Status Selector */}
              <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Remediation Workflow</span>
                  <span className="text-white font-bold capitalize">{selectedFinding.remediation_status.replace(/_/g, " ")}</span>
                </div>
                <div className="flex items-center space-x-1">
                  {["open", "in_progress", "remediated", "false_positive"].map((st) => (
                    <button
                      key={st}
                      onClick={() => handleUpdateRemediation(st)}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase transition ${
                        selectedFinding.remediation_status === st
                          ? "bg-cyan-500 text-slate-950 font-bold"
                          : "bg-slate-800 text-slate-400 hover:text-white"
                      }`}
                    >
                      {st.replace(/_/g, " ")}
                    </button>
                  ))}
                </div>
              </div>

              {/* Description & Impact */}
              <div className="space-y-3">
                <div>
                  <h3 className="text-slate-400 text-[11px] uppercase font-bold mb-1">Technical Description</h3>
                  <p className="text-slate-200 leading-relaxed bg-slate-900/40 p-3 rounded border border-slate-800/80">
                    {selectedFinding.description}
                  </p>
                </div>

                <div>
                  <h3 className="text-slate-400 text-[11px] uppercase font-bold mb-1">Potential Impact</h3>
                  <p className="text-rose-300/90 leading-relaxed bg-rose-950/20 p-3 rounded border border-rose-900/40">
                    {selectedFinding.potential_impact}
                  </p>
                </div>
              </div>

              {/* Safe Reproduction Steps */}
              <div>
                <h3 className="text-slate-400 text-[11px] uppercase font-bold mb-1">
                  Non-Destructive Safe Reproduction
                </h3>
                <pre className="bg-slate-900 p-3 rounded border border-slate-800 text-slate-300 text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {selectedFinding.reproduction_steps}
                </pre>
              </div>

              {/* Recommended Remediation */}
              <div>
                <h3 className="text-emerald-400 text-[11px] uppercase font-bold mb-1">
                  Recommended Remediation
                </h3>
                <div className="bg-emerald-950/30 border border-emerald-800/40 text-emerald-200 p-3 rounded leading-relaxed">
                  {selectedFinding.recommended_remediation}
                </div>
              </div>

              {/* Evidence Items */}
              {selectedFinding.evidence_items && selectedFinding.evidence_items.length > 0 && (
                <div>
                  <h3 className="text-slate-400 text-[11px] uppercase font-bold mb-1">
                    Captured Technical Evidence
                  </h3>
                  <div className="space-y-2">
                    {selectedFinding.evidence_items.map((ev: any) => (
                      <div key={ev.id} className="bg-slate-950 border border-slate-800 rounded p-3 text-[11px]">
                        <div className="text-cyan-400 font-bold mb-1">
                          [{ev.request_method}] {ev.request_url}
                        </div>
                        <div className="text-slate-400 mb-2">Status: {ev.response_status}</div>
                        {ev.highlighted_issue && (
                          <div className="text-rose-400 font-bold mb-1">
                            Issue: {ev.highlighted_issue}
                          </div>
                        )}
                        <pre className="text-slate-300 bg-black/50 p-2 rounded max-h-40 overflow-y-auto text-[10px]">
                          {ev.response_snippet}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Defensive Analyst Integration */}
              <div className="border-t border-slate-800 pt-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-cyan-400 flex items-center">
                    <Sparkles className="w-3.5 h-3.5 mr-1" />
                    AI Root Cause & Remediation Advisor
                  </span>
                  <button
                    onClick={handleAskAI}
                    disabled={aiLoading}
                    className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold px-3 py-1 rounded text-[11px] transition flex items-center"
                  >
                    {aiLoading ? "Consulting AI..." : "Explain with AI"}
                  </button>
                </div>

                {aiAnalysis && (
                  <div className="bg-slate-900/90 border border-cyan-500/30 p-4 rounded-lg text-slate-300 text-xs leading-relaxed whitespace-pre-wrap">
                    {aiAnalysis}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-xs font-mono">
              Select a finding from the list to view evidence and reproduction conditions.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
