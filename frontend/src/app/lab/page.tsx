"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { AuthorizedTarget } from "@/types";
import { 
  FlaskConical, 
  ShieldAlert, 
  Play, 
  ExternalLink, 
  CheckCircle2, 
  AlertCircle, 
  Info, 
  Code, 
  Globe, 
  Layers, 
  Lock, 
  ArrowRight,
  Terminal
} from "lucide-react";

interface LabEndpoint {
  path: string;
  name: string;
  vulnType: string;
  cwe: string;
  owasp: string;
  description: string;
  remediation: string;
  previewUrl: string;
}

const LAB_ENDPOINTS: LabEndpoint[] = [
  {
    path: "/lab/insecure-headers",
    name: "Missing Security Headers",
    vulnType: "Security Misconfiguration",
    cwe: "CWE-693",
    owasp: "A05:2021",
    description: "Response omits Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and X-Content-Type-Options while exposing server version tokens.",
    remediation: "Configure reverse proxy or web application framework to inject HSTS, CSP, and X-Content-Type-Options: nosniff headers.",
    previewUrl: "http://localhost:8888/lab/insecure-headers"
  },
  {
    path: "/lab/cookies",
    name: "Weak Cookie Flags",
    vulnType: "Sensitive Cookie Exposure",
    cwe: "CWE-614 / CWE-1004",
    owasp: "A05:2021",
    description: "Session tokens and tracking IDs are set without HttpOnly, Secure, or SameSite=Strict/Lax attributes, permitting clientside JavaScript access.",
    remediation: "Set Set-Cookie directives with Secure; HttpOnly; SameSite=Lax flags for all session tokens.",
    previewUrl: "http://localhost:8888/lab/cookies"
  },
  {
    path: "/lab/cors",
    name: "Insecure Permissive CORS",
    vulnType: "Cross-Origin Misconfiguration",
    cwe: "CWE-942",
    owasp: "A05:2021",
    description: "API dynamically reflects arbitrary incoming Origin headers while setting Access-Control-Allow-Credentials: true, exposing authenticated responses.",
    remediation: "Enforce a strict server-side allowlist of trusted origins; never dynamically reflect arbitrary origins when credentials are allowed.",
    previewUrl: "http://localhost:8888/lab/cors"
  },
  {
    path: "/robots.txt",
    name: "Information Disclosure (Robots.txt)",
    vulnType: "Information Exposure",
    cwe: "CWE-200",
    owasp: "A05:2021",
    description: "Robots exclusion file publicly reveals internal paths (/admin/secret-portal, /api/v1/private-backup) to unauthenticated crawlers.",
    remediation: "Rely on proper authentication and authorization barriers rather than obscurity in robots.txt for sensitive endpoints.",
    previewUrl: "http://localhost:8888/robots.txt"
  },
  {
    path: "/lab/api/user/102/profile",
    name: "Insecure Direct Object Reference (IDOR)",
    vulnType: "Broken Access Control",
    cwe: "CWE-639",
    owasp: "A01:2021",
    description: "User profile API returns sensitive user objects based solely on the URL record ID without verifying caller authentication or session ownership.",
    remediation: "Implement strict authorization checks: verify that the authenticated user identity matches the requested object owner.",
    previewUrl: "http://localhost:8888/lab/api/user/102/profile"
  },
  {
    path: "/lab/admin/metrics",
    name: "Unauthenticated Admin Telemetry",
    vulnType: "Missing Function Level Access Control",
    cwe: "CWE-306",
    owasp: "A01:2021",
    description: "Administrative performance and internal network cluster topologies are exposed without any authentication challenge.",
    remediation: "Place administrative and metrics endpoints behind authenticated management subnets or RBAC middleware.",
    previewUrl: "http://localhost:8888/lab/admin/metrics"
  },
  {
    path: "/lab/search?q=test",
    name: "Unescaped Parameter Reflection",
    vulnType: "Input Handling Boundary",
    cwe: "CWE-79",
    owasp: "A03:2021",
    description: "Search endpoint reflects URL query parameters directly into HTML responses without contextual entity encoding.",
    remediation: "Use contextual output encoding (e.g. HTML entity encoding) before rendering untrusted input in the DOM.",
    previewUrl: "http://localhost:8888/lab/search?q=test"
  },
  {
    path: "/lab/redirect?target=https://example.com",
    name: "Unvalidated Redirect Parameter",
    vulnType: "Open Redirect",
    cwe: "CWE-601",
    owasp: "A01:2021",
    description: "Target parameter is accepted and processed directly into a 302 HTTP location redirect without host verification.",
    remediation: "Validate destination URLs against a strict domain whitelist or use relative redirect paths.",
    previewUrl: "http://localhost:8888/lab/redirect?target=https://example.com"
  }
];

export default function SafeLabPage() {
  const router = useRouter();
  const [labTarget, setLabTarget] = useState<AuthorizedTarget | null>(null);
  const [launching, setLaunching] = useState(false);
  const [selectedEndpoint, setSelectedEndpoint] = useState<LabEndpoint>(LAB_ENDPOINTS[0]);
  const [liveResponse, setLiveResponse] = useState<string | null>(null);
  const [fetchingLive, setFetchingLive] = useState(false);

  useEffect(() => {
    // Check if the lab target is registered
    api.targets.list().then((targets) => {
      const found = targets.find((t) => t.target_url.includes("8888") || t.target_mode === "training_lab");
      if (found) setLabTarget(found);
    }).catch(() => {});
  }, []);

  const handleLaunchLabScan = async (mode: "passive" | "safe_active" | "lab_simulation") => {
    if (!labTarget) {
      alert("Local Lab Target (port 8888) is not yet registered. Please register it in the Targets section first.");
      router.push("/targets");
      return;
    }

    if (!labTarget.has_active_authorization) {
      alert("Local Lab Target requires an active Authorization Record. Please sign the agreement in the Targets section.");
      router.push("/targets");
      return;
    }

    setLaunching(true);
    try {
      const scan = await api.scans.launch({
        target_id: labTarget.id,
        scan_mode: mode,
      });
      router.push("/scans");
    } catch (err: any) {
      alert("Failed to launch lab scan: " + err.message);
    } finally {
      setLaunching(false);
    }
  };

  const handleInspectLive = async (ep: LabEndpoint) => {
    setSelectedEndpoint(ep);
    setFetchingLive(true);
    setLiveResponse(null);
    try {
      const res = await fetch(ep.previewUrl, { mode: "cors" });
      const text = await res.text();
      setLiveResponse(text);
    } catch (err: any) {
      setLiveResponse(`// Note: Direct browser fetch blocked by CORS or lab not running on port 8888.\n// Run './run_local.sh' to start the local lab.\n// Endpoint: ${ep.previewUrl}`);
    } finally {
      setFetchingLive(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-[#10192e] to-slate-900 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full text-xs font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20 mb-2">
            <FlaskConical className="w-3.5 h-3.5" />
            <span>Isolated Educational Target</span>
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-white">
            Safe Local Vulnerability Lab
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Pre-configured toy application running on <code className="text-cyan-400">http://localhost:8888</code> for safe, isolated verification of scanner modules and OWASP Top 10 detection heuristics.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => handleLaunchLabScan("lab_simulation")}
            disabled={launching}
            className="flex items-center space-x-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-mono text-xs font-semibold px-4 py-2.5 rounded-xl shadow-lg shadow-purple-900/30 transition disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${launching ? "animate-spin" : ""}`} />
            <span>{launching ? "Dispatching..." : "Launch Lab Simulation"}</span>
          </button>
        </div>
      </div>

      {/* Target Status Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-950/70 border border-slate-800/90 rounded-xl px-4 py-3 text-xs font-mono">
        <div className="flex items-center space-x-2 text-slate-300">
          <Globe className="w-4 h-4 text-purple-400" />
          <span>Lab Target: <strong className="text-white">http://localhost:8888</strong></span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">Environment: Isolated Localhost</span>
        </div>

        <div className="flex items-center space-x-2">
          {labTarget?.has_active_authorization ? (
            <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Authorized for Lab Simulation</span>
            </span>
          ) : (
            <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[11px] bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <AlertCircle className="w-3.5 h-3.5" />
              <span>Authorization Agreement Required</span>
            </span>
          )}
        </div>
      </div>

      {/* Lab Endpoints & Interactive Tester Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 1 Col: Endpoints Directory */}
        <div className="space-y-2.5 max-h-[750px] overflow-y-auto pr-1">
          <span className="text-xs font-mono uppercase text-slate-400 block px-1 mb-2">
            Vulnerability Demonstration Endpoints ({LAB_ENDPOINTS.length})
          </span>
          {LAB_ENDPOINTS.map((ep, idx) => {
            const isSelected = selectedEndpoint.path === ep.path;
            return (
              <div
                key={idx}
                onClick={() => setSelectedEndpoint(ep)}
                className={`p-4 rounded-xl border transition cursor-pointer ${
                  isSelected
                    ? "bg-slate-900/90 border-purple-500/60 shadow-lg shadow-purple-950/20"
                    : "bg-[#0e1628]/80 border-slate-800/80 hover:border-slate-700 hover:bg-[#0e1628]"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-xs font-bold font-mono text-white block">
                      {ep.name}
                    </span>
                    <span className="text-[11px] font-mono text-purple-400 block mt-0.5">
                      {ep.path}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                    {ep.cwe}
                  </span>
                </div>
                <div className="flex items-center space-x-2 mt-2 text-[10px] font-mono text-slate-400">
                  <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                    {ep.owasp}
                  </span>
                  <span className="text-slate-500">•</span>
                  <span className="truncate">{ep.vulnType}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right 2 Cols: Deep Dive & Inspection */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-[#0e1628] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    {selectedEndpoint.owasp}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
                    {selectedEndpoint.cwe}
                  </span>
                </div>
                <h2 className="text-lg font-bold font-mono text-white mt-1.5">
                  {selectedEndpoint.name}
                </h2>
                <span className="text-xs font-mono text-slate-400">
                  Target Route: <code className="text-cyan-400">{selectedEndpoint.path}</code>
                </span>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleInspectLive(selectedEndpoint)}
                  disabled={fetchingLive}
                  className="flex items-center space-x-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono px-3 py-2 rounded-lg transition"
                >
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{fetchingLive ? "Fetching..." : "Probe Endpoint"}</span>
                </button>
                <a
                  href={selectedEndpoint.previewUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center space-x-1 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white text-xs font-mono px-3 py-2 rounded-lg transition"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Open URL</span>
                </a>
              </div>
            </div>

            {/* Description Card */}
            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 mb-1">Vulnerability Mechanics</h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                {selectedEndpoint.description}
              </p>
            </div>

            {/* Defensive Remediation */}
            <div>
              <h4 className="text-xs font-mono uppercase text-emerald-400 mb-1 flex items-center space-x-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Defensive Remediation Standard</span>
              </h4>
              <p className="text-xs text-emerald-300 leading-relaxed bg-emerald-950/20 p-3.5 rounded-xl border border-emerald-500/20 font-mono">
                {selectedEndpoint.remediation}
              </p>
            </div>

            {/* Response Preview Terminal */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <h4 className="text-xs font-mono uppercase text-slate-400 flex items-center space-x-1.5">
                  <Code className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Live Endpoint Response / Payload</span>
                </h4>
                <span className="text-[10px] font-mono text-slate-500">
                  {selectedEndpoint.previewUrl}
                </span>
              </div>
              <pre className="text-xs font-mono text-cyan-300 bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto max-h-60">
                {liveResponse || `// Click "Probe Endpoint" above or start the local lab to preview raw output.\n// Service Port: 8888\nGET ${selectedEndpoint.path} HTTP/1.1\nHost: localhost:8888`}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
