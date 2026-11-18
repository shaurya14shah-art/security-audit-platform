const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

function getAuthHeader(): Record<string, string> {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("sec_auth_token");
    if (token) {
      return { Authorization: `Bearer ${token}` };
    }
  }
  return {};
}

async function fetchJson<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = {
    "Content-Type": "application/json",
    ...getAuthHeader(),
    ...options.headers,
  };

  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorMsg = `HTTP ${res.status} ${res.statusText}`;
    try {
      const errData = await res.json();
      errorMsg = errData.detail || errorMsg;
    } catch (_) {}
    throw new Error(errorMsg);
  }

  return res.json();
}

export const api = {
  auth: {
    login: (body: any) => fetchJson<any>("/auth/login", { method: "POST", body: JSON.stringify(body) }),
    register: (body: any) => fetchJson<any>("/auth/register", { method: "POST", body: JSON.stringify(body) }),
    getMe: () => fetchJson<any>("/auth/me"),
  },
  targets: {
    list: () => fetchJson<any[]>("/targets/"),
    get: (id: string) => fetchJson<any>(`/targets/${id}`),
    create: (body: any) => fetchJson<any>("/targets/", { method: "POST", body: JSON.stringify(body) }),
    authorize: (id: string, body: any) =>
      fetchJson<any>(`/targets/${id}/authorize`, { method: "POST", body: JSON.stringify(body) }),
    revoke: (id: string) => fetchJson<any>(`/targets/${id}/revoke`, { method: "POST" }),
  },
  scans: {
    list: () => fetchJson<any[]>("/scans/"),
    get: (id: string) => fetchJson<any>(`/scans/${id}`),
    launch: (body: any) => fetchJson<any>("/scans/launch", { method: "POST", body: JSON.stringify(body) }),
    cancel: (id: string) => fetchJson<any>(`/scans/${id}/cancel`, { method: "POST" }),
  },
  findings: {
    list: (params: Record<string, string> = {}) => {
      const qs = new URLSearchParams(params).toString();
      return fetchJson<any[]>(`/findings/${qs ? `?${qs}` : ""}`);
    },
    get: (id: string) => fetchJson<any>(`/findings/${id}`),
    updateRemediation: (id: string, body: any) =>
      fetchJson<any>(`/findings/${id}/remediation`, { method: "PATCH", body: JSON.stringify(body) }),
  },
  audit: {
    list: () => fetchJson<any[]>("/audit/"),
    verify: () => fetchJson<any>("/audit/verify"),
  },
  reports: {
    generate: (body: any) => fetchJson<any>("/reports/generate", { method: "POST", body: JSON.stringify(body) }),
  },
  ai: {
    explainFinding: (findingId: string) =>
      fetchJson<any>("/ai/explain-finding", { method: "POST", body: JSON.stringify({ finding_id: findingId }) }),
    summarizeScan: (scanId: string) =>
      fetchJson<any>("/ai/summarize-scan", { method: "POST", body: JSON.stringify({ scan_id: scanId }) }),
  },
};
