export interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface AuthorizationRecord {
  id: string;
  target_id: string;
  authorized_by_name: string;
  authorized_by_email: string;
  authorization_reference: string;
  ownership_confirmed: boolean;
  valid_from: string;
  valid_until: string;
  permitted_methods: string;
  contact_info: string;
  signature_statement: string;
  is_revoked: boolean;
  created_at: string;
}

export interface AuthorizedTarget {
  id: string;
  name: string;
  target_url: string;
  target_mode: "localhost" | "docker_container" | "training_lab" | "staging_env" | "authorized_domain";
  hostname: string;
  ip_or_subnet?: string;
  description?: string;
  is_active: boolean;
  created_at: string;
  has_active_authorization: boolean;
  active_authorization?: AuthorizationRecord;
}

export interface Scan {
  id: string;
  target_id: string;
  authorization_record_id: string;
  status: "pending" | "running" | "completed" | "cancelled" | "blocked_unauthorized" | "failed";
  scan_mode: "passive" | "safe_active" | "lab_simulation";
  progress: number;
  current_phase: string;
  total_requests_sent: number;
  started_at?: string;
  completed_at?: string;
  cancellation_reason?: string;
  created_at: string;
  findings_count: number;
}

export interface Evidence {
  id: string;
  request_method?: string;
  request_url?: string;
  request_headers_json?: string;
  request_body?: string;
  response_status?: string;
  response_headers_json?: string;
  response_snippet?: string;
  highlighted_issue?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  target_id: string;
  title: string;
  cwe_id?: string;
  owasp_category?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  affected_asset: string;
  description: string;
  detection_method: "PASSIVE_ANALYSIS" | "SAFE_ACTIVE_TESTING" | "LOCAL_LAB_EXPLOIT_SIMULATION";
  reproduction_steps: string;
  potential_impact: string;
  recommended_remediation: string;
  risk_score: number;
  remediation_status: "open" | "in_progress" | "remediated" | "verified" | "false_positive";
  remediation_notes?: string;
  created_at: string;
  updated_at: string;
  evidence_items?: Evidence[];
}

export interface AuditLog {
  id: string;
  sequence_number: number;
  timestamp: string;
  user_id?: string;
  username?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  client_ip?: string;
  details_json: string;
  previous_entry_hash: string;
  entry_hash: string;
}

export interface AuditVerification {
  is_valid: boolean;
  total_records_checked: number;
  broken_sequence_index?: number;
  error_message?: string;
  verification_timestamp: string;
  root_genesis_hash: string;
  latest_leaf_hash: string;
}

export interface ReportSummary {
  scan_id: string;
  target_name: string;
  target_url: string;
  target_mode: string;
  assessment_date: string;
  authorizing_party: string;
  authorization_ref: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  overall_posture_score: number;
  report_html?: string;
  report_markdown?: string;
}
