"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { Scan, ReportSummary } from "@/types";
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldCheck, 
  AlertTriangle, 
  Target, 
  Calendar, 
  Clock, 
  CheckCircle2, 
  Code, 
  FileCode, 
  RefreshCw,
  ExternalLink,
  ChevronRight
} from "lucide-react";

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [report, setReport] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [activeTab, setActiveTab] = useState<"preview" | "markdown">("preview");

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    try {
      const scanList = await api.scans.list();
      setScans(scanList);
      if (scanList.length > 0) {
        setSelectedScanId(scanList[0].id);
        // Auto-generate report for first scan
        handleGenerateReport(scanList[0].id);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (scanId: string) => {
    if (!scanId) return;
    setGenerating(true);
    try {
      const rep = await api.reports.generate({ scan_id: scanId });
      setReport(rep);
    } catch (err: any) {
      alert("Failed to compile report: " + err.message);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadHtml = () => {
    if (!report?.report_html) return;
    const blob = new Blob([report.report_html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Security_Assessment_Report_${report.target_name.replace(/\s+/g, "_")}_${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadMarkdown = () => {
    if (!report?.report_markdown) return;
    const blob = new Blob([report.report_markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Security_Assessment_Summary_${report.target_name.replace(/\s+/g, "_")}_${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    if (!report?.report_html) return;
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      printWindow.document.write(report.report_html);
      printWindow.document.close();
      printWindow.focus();
      printWindow.print();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-[#0b162c] to-slate-900 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 mb-2">
            <FileText className="w-3.5 h-3.5" />
            <span>Executive & Technical Compliance Reports</span>
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-white">
            Security Assessment Reports
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Generate formal, verifiable assessment documentation formatted for technical remediators, compliance auditors, and executive leadership.
          </p>
        </div>

        {report && (
          <div className="flex items-center space-x-2">
            <button
              onClick={handlePrint}
              className="flex items-center space-x-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs px-3 py-2 rounded-xl transition border border-slate-700"
            >
              <Printer className="w-3.5 h-3.5 text-cyan-400" />
              <span>Print / PDF</span>
            </button>
            <button
              onClick={handleDownloadHtml}
              className="flex items-center space-x-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs px-3 py-2 rounded-xl transition shadow-lg shadow-cyan-900/30"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download HTML</span>
            </button>
            <button
              onClick={handleDownloadMarkdown}
              className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 font-mono text-xs px-3 py-2 rounded-xl transition"
            >
              <FileCode className="w-3.5 h-3.5 text-emerald-400" />
              <span>Markdown</span>
            </button>
          </div>
        )}
      </div>

      {/* Scan Selector Toolbar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-[#0e1628] border border-slate-800 p-4 rounded-xl">
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <label className="text-xs font-mono text-slate-400 whitespace-nowrap">
            Select Audit Scan:
          </label>
          <select
            value={selectedScanId}
            onChange={(e) => {
              setSelectedScanId(e.target.value);
              handleGenerateReport(e.target.value);
            }}
            className="bg-slate-950 border border-slate-800 text-white font-mono text-xs rounded-lg px-3 py-2 w-full sm:w-80 focus:outline-none focus:border-cyan-500"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                [{s.status.toUpperCase()}] {s.scan_mode.toUpperCase()} - {new Date(s.created_at).toLocaleString()}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={() => handleGenerateReport(selectedScanId)}
          disabled={generating || !selectedScanId}
          className="flex items-center space-x-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono px-3 py-2 rounded-lg transition disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${generating ? "animate-spin" : ""}`} />
          <span>{generating ? "Compiling..." : "Re-compile Report"}</span>
        </button>
      </div>

      {/* Report Summary Cards */}
      {report && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="bg-[#0e1628] border border-slate-800 p-3.5 rounded-xl">
            <span className="text-[10px] font-mono text-slate-500 uppercase block">Target</span>
            <span className="text-xs font-mono font-bold text-white truncate block mt-0.5" title={report.target_url}>
              {report.target_name}
            </span>
          </div>
          <div className="bg-[#0e1628] border border-slate-800 p-3.5 rounded-xl">
            <span className="text-[10px] font-mono text-slate-500 uppercase block">Posture Score</span>
            <span className={`text-sm font-mono font-bold block mt-0.5 ${
              report.overall_posture_score >= 80 ? "text-emerald-400" : report.overall_posture_score >= 60 ? "text-amber-400" : "text-rose-400"
            }`}>
              {report.overall_posture_score} / 100
            </span>
          </div>
          <div className="bg-[#0e1628] border border-slate-800 p-3.5 rounded-xl">
            <span className="text-[10px] font-mono text-rose-400 uppercase block">Critical</span>
            <span className="text-sm font-mono font-bold text-rose-400 block mt-0.5">
              {report.critical_count}
            </span>
          </div>
          <div className="bg-[#0e1628] border border-slate-800 p-3.5 rounded-xl">
            <span className="text-[10px] font-mono text-orange-400 uppercase block">High</span>
            <span className="text-sm font-mono font-bold text-orange-400 block mt-0.5">
              {report.high_count}
            </span>
          </div>
          <div className="bg-[#0e1628] border border-slate-800 p-3.5 rounded-xl">
            <span className="text-[10px] font-mono text-amber-400 uppercase block">Medium</span>
            <span className="text-sm font-mono font-bold text-amber-400 block mt-0.5">
              {report.medium_count}
            </span>
          </div>
          <div className="bg-[#0e1628] border border-slate-800 p-3.5 rounded-xl">
            <span className="text-[10px] font-mono text-blue-400 uppercase block">Low / Info</span>
            <span className="text-sm font-mono font-bold text-blue-400 block mt-0.5">
              {report.low_count + report.info_count}
            </span>
          </div>
        </div>
      )}

      {/* Tabs & Report Display Container */}
      <div className="bg-[#0e1628] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-3 bg-slate-950/60">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab("preview")}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                activeTab === "preview"
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Interactive HTML Document
            </button>
            <button
              onClick={() => setActiveTab("markdown")}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                activeTab === "markdown"
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Executive Markdown Summary
            </button>
          </div>

          <div className="text-[11px] font-mono text-slate-500">
            Authorization Ref: <strong className="text-slate-400">{report?.authorization_ref || "N/A"}</strong>
          </div>
        </div>

        <div className="p-6">
          {activeTab === "preview" ? (
            report?.report_html ? (
              <div className="bg-white rounded-xl shadow-inner overflow-hidden border border-slate-300">
                <iframe
                  srcDoc={report.report_html}
                  title="Security Assessment Report Preview"
                  className="w-full h-[800px] border-0"
                />
              </div>
            ) : (
              <div className="text-center py-16 text-slate-500 font-mono text-xs">
                No report compiled yet. Select a scan and click "Re-compile Report".
              </div>
            )
          ) : (
            <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap max-h-[800px] overflow-y-auto">
              {report?.report_markdown || "No markdown summary available."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
