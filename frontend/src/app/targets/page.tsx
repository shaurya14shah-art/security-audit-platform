"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { 
  Target, 
  Plus, 
  CheckCircle2, 
  XCircle, 
  FileCheck, 
  Lock, 
  ShieldAlert,
  Calendar,
  ExternalLink
} from "lucide-react";

export default function TargetsPage() {
  const [targets, setTargets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [authorizeModalOpen, setAuthorizeModalOpen] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<any>(null);

  // New Target Form
  const [newTarget, setNewTarget] = useState({
    name: "",
    target_url: "http://localhost:8888",
    target_mode: "localhost",
    ip_or_subnet: "127.0.0.1/32",
    description: "",
  });

  // Authorization Agreement Form
  const [authForm, setAuthForm] = useState({
    authorized_by_name: "",
    authorized_by_email: "",
    authorization_reference: "SEC-AUTH-2026-",
    ownership_confirmed: false,
    valid_from: new Date().toISOString().slice(0, 16),
    valid_until: new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 16),
    permitted_methods: ["passive", "safe_active"],
    contact_info: "",
    signature_statement: "I certify that I possess explicit legal authorization for defensive assessment of this target.",
  });

  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    loadTargets();
  }, []);

  const loadTargets = async () => {
    try {
      const data = await api.targets.list();
      setTargets(data);
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    try {
      await api.targets.create(newTarget);
      setRegisterModalOpen(false);
      setNewTarget({ name: "", target_url: "http://localhost:8888", target_mode: "localhost", ip_or_subnet: "", description: "" });
      loadTargets();
    } catch (e: any) {
      setErrorMsg(e.message);
    }
  };

  const handleSignAuthorization = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTarget) return;
    setErrorMsg("");
    try {
      await api.targets.authorize(selectedTarget.id, {
        ...authForm,
        valid_from: new Date(authForm.valid_from).toISOString(),
        valid_until: new Date(authForm.valid_until).toISOString(),
      });
      setAuthorizeModalOpen(false);
      setSelectedTarget(null);
      loadTargets();
    } catch (e: any) {
      setErrorMsg(e.message);
    }
  };

  const handleRevokeAuthorization = async (targetId: string) => {
    if (!confirm("Are you sure you want to revoke active authorization for this target? All future scans will be blocked.")) return;
    try {
      await api.targets.revoke(targetId);
      loadTargets();
    } catch (e: any) {
      alert(e.message);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center">
            <Target className="w-5 h-5 mr-2 text-cyan-400" />
            Target Scope & Authorization Registry
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Strict pre-flight gatekeeper: Scans cannot execute against any target without an active, signed authorization record.
          </p>
        </div>

        <button
          onClick={() => setRegisterModalOpen(true)}
          className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 px-4 py-2 rounded-lg text-xs font-mono font-bold flex items-center transition shadow-md shadow-cyan-500/10"
        >
          <Plus className="w-4 h-4 mr-1.5" />
          Register Target
        </button>
      </div>

      {errorMsg && (
        <div className="bg-rose-950/60 border border-rose-700/60 text-rose-300 p-3 rounded-lg text-xs font-mono">
          {errorMsg}
        </div>
      )}

      {/* Targets Table */}
      <div className="bg-[#0b1222] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/60 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="px-6 py-3.5">Target Name & URL</th>
                <th className="px-6 py-3.5">Mode</th>
                <th className="px-6 py-3.5">Authorization Status</th>
                <th className="px-6 py-3.5">Valid Window</th>
                <th className="px-6 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {targets.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                    No authorized targets registered. Click 'Register Target' to add an asset.
                  </td>
                </tr>
              ) : (
                targets.map((t) => (
                  <tr key={t.id} className="hover:bg-slate-850/40 transition">
                    <td className="px-6 py-4">
                      <div className="font-bold text-slate-100">{t.name}</div>
                      <div className="text-slate-400 text-[11px] mt-0.5">{t.target_url}</div>
                      {t.description && (
                        <div className="text-slate-500 text-[10px] mt-0.5">{t.description}</div>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] uppercase font-bold">
                        {t.target_mode}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {t.has_active_authorization ? (
                        <div className="flex items-center text-emerald-400 space-x-1.5 font-bold">
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Active Consent</span>
                        </div>
                      ) : (
                        <div className="flex items-center text-rose-400 space-x-1.5 font-bold">
                          <XCircle className="w-4 h-4" />
                          <span>Pending Authorization</span>
                        </div>
                      )}
                      {t.active_authorization && (
                        <div className="text-[10px] text-slate-400 mt-0.5">
                          Ref: {t.active_authorization.authorization_reference}
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 text-slate-400 text-[11px]">
                      {t.active_authorization ? (
                        <div>
                          <div>From: {t.active_authorization.valid_from.slice(0, 10)}</div>
                          <div>Until: {t.active_authorization.valid_until.slice(0, 10)}</div>
                        </div>
                      ) : (
                        <span className="text-slate-600">N/A</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right space-x-2">
                      {!t.has_active_authorization ? (
                        <button
                          onClick={() => {
                            setSelectedTarget(t);
                            setAuthorizeModalOpen(true);
                          }}
                          className="bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-600/40 px-3 py-1.5 rounded text-xs font-bold transition"
                        >
                          Sign Consent
                        </button>
                      ) : (
                        <button
                          onClick={() => handleRevokeAuthorization(t.id)}
                          className="text-rose-400 hover:text-rose-300 text-xs hover:underline transition"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Register Target Modal */}
      {registerModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <h3 className="text-base font-bold font-mono text-white flex items-center">
              <Target className="w-4 h-4 mr-2 text-cyan-400" /> Register Target Asset
            </h3>
            <p className="text-xs text-slate-400">
              Add a target to the defensive testing registry. Scans remain blocked until an explicit authorization agreement is signed.
            </p>

            <form onSubmit={handleCreateTarget} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Target Name</label>
                <input
                  type="text"
                  placeholder="e.g. Production Staging API"
                  value={newTarget.name}
                  onChange={(e) => setNewTarget({ ...newTarget, name: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Target URL</label>
                <input
                  type="url"
                  placeholder="http://localhost:8888 or https://..."
                  value={newTarget.target_url}
                  onChange={(e) => setNewTarget({ ...newTarget, target_url: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Target Mode</label>
                  <select
                    value={newTarget.target_mode}
                    onChange={(e) => setNewTarget({ ...newTarget, target_mode: e.target.value as any })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="localhost">localhost</option>
                    <option value="training_lab">training_lab</option>
                    <option value="docker_container">docker_container</option>
                    <option value="staging_env">staging_env</option>
                    <option value="authorized_domain">authorized_domain</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">IP / CIDR Range</label>
                  <input
                    type="text"
                    placeholder="127.0.0.1/32"
                    value={newTarget.ip_or_subnet}
                    onChange={(e) => setNewTarget({ ...newTarget, ip_or_subnet: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Description / Notes</label>
                <textarea
                  rows={2}
                  value={newTarget.description}
                  onChange={(e) => setNewTarget({ ...newTarget, description: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  placeholder="Purpose of testing, server environment..."
                />
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setRegisterModalOpen(false)}
                  className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 py-1.5 rounded transition"
                >
                  Save Target
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Sign Authorization Modal */}
      {authorizeModalOpen && selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="bg-[#0f172a] border border-emerald-600/40 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4 my-8">
            <div className="flex items-center space-x-2 text-emerald-400">
              <FileCheck className="w-5 h-5" />
              <h3 className="text-base font-bold font-mono text-white">
                Sign Authorization Agreement
              </h3>
            </div>
            <p className="text-xs text-slate-300">
              Target: <strong className="text-cyan-300 font-mono">{selectedTarget.name}</strong> ({selectedTarget.target_url})
            </p>

            <form onSubmit={handleSignAuthorization} className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Authorizing Official</label>
                  <input
                    type="text"
                    placeholder="Jane Doe (Security Director)"
                    value={authForm.authorized_by_name}
                    onChange={(e) => setAuthForm({ ...authForm, authorized_by_name: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-emerald-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Authorizer Email</label>
                  <input
                    type="text"
                    placeholder="security@example.com"
                    value={authForm.authorized_by_email}
                    onChange={(e) => setAuthForm({ ...authForm, authorized_by_email: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-emerald-500"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Authorization Reference ID</label>
                  <input
                    type="text"
                    placeholder="TICKET-2026-091"
                    value={authForm.authorization_reference}
                    onChange={(e) => setAuthForm({ ...authForm, authorization_reference: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-emerald-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Emergency Contact</label>
                  <input
                    type="text"
                    placeholder="ops-pager@example.com"
                    value={authForm.contact_info}
                    onChange={(e) => setAuthForm({ ...authForm, contact_info: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-emerald-500"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Valid From</label>
                  <input
                    type="datetime-local"
                    value={authForm.valid_from}
                    onChange={(e) => setAuthForm({ ...authForm, valid_from: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-emerald-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Valid Until</label>
                  <input
                    type="datetime-local"
                    value={authForm.valid_until}
                    onChange={(e) => setAuthForm({ ...authForm, valid_until: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-emerald-500"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Permitted Testing Methods</label>
                <div className="flex items-center space-x-4 pt-1">
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={authForm.permitted_methods.includes("passive")}
                      onChange={(e) => {
                        const m = authForm.permitted_methods.filter((x) => x !== "passive");
                        if (e.target.checked) m.push("passive");
                        setAuthForm({ ...authForm, permitted_methods: m });
                      }}
                    />
                    <span>Passive Analysis</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={authForm.permitted_methods.includes("safe_active")}
                      onChange={(e) => {
                        const m = authForm.permitted_methods.filter((x) => x !== "safe_active");
                        if (e.target.checked) m.push("safe_active");
                        setAuthForm({ ...authForm, permitted_methods: m });
                      }}
                    />
                    <span>Safe Active Testing</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={authForm.permitted_methods.includes("lab_simulation")}
                      onChange={(e) => {
                        const m = authForm.permitted_methods.filter((x) => x !== "lab_simulation");
                        if (e.target.checked) m.push("lab_simulation");
                        setAuthForm({ ...authForm, permitted_methods: m });
                      }}
                    />
                    <span>Lab Simulation</span>
                  </label>
                </div>
              </div>

              <div className="p-3 bg-emerald-950/40 border border-emerald-700/50 rounded-lg">
                <label className="flex items-start space-x-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={authForm.ownership_confirmed}
                    onChange={(e) => setAuthForm({ ...authForm, ownership_confirmed: e.target.checked })}
                    className="mt-0.5"
                    required
                  />
                  <span className="text-[11px] text-emerald-200 leading-snug">
                    I explicitly confirm that I own this target or possess formal written authorization from the asset owner to conduct defensive security testing within the declared window.
                  </span>
                </label>
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setAuthorizeModalOpen(false)}
                  className="px-3 py-1.5 text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!authForm.ownership_confirmed}
                  className="bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold px-4 py-1.5 rounded transition"
                >
                  Sign & Enforce Agreement
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
