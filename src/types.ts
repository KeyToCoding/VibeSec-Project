export type InputMode = 'code' | 'url' | 'upload' | 'github';

export interface Vulnerability {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  owasp?: string;
  description: string;
  attack_scenario?: string;
  file?: string;
  line_hint?: number | string;
  confidence?: string;
  fix?: string;
  code_snippet?: string;
  model_used?: string;
  rule_id?: string;
}

export interface HallucinatedPackage {
  package: string;
  ecosystem: string;
  status: string;
  title: string;
  description: string;
  risk_analysis: string;
  attack_scenario?: string;
  fix?: string;
}

export interface ScanReportData {
  scan_id?: string;
  created_at?: string;
  input_type?: string;
  target?: string;
  target_url?: string;
  repo_url?: string;
  filename?: string;
  language?: string;
  vulnerabilities: Vulnerability[];
  hallucinated_packages?: HallucinatedPackage[];
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  };
  files_scanned: number;
  files_skipped?: string[];
  summary: string;
  primary_model?: string;
  scan_time_seconds: number;
  header_status?: {
    present: Record<string, string>;
    missing: Record<string, string>;
  };
}

export type VerificationState =
  | 'FIX VERIFIED BY AVAILABLE CHECKS'
  | 'STILL DETECTED'
  | 'VERIFICATION FAILED';

export interface PatchProposalResponse {
  success: boolean;
  patched_code?: string;
  explanation?: string;
  changes_summary?: string[];
  security_caveats?: string;
  unified_diff?: string;
  model_used?: string;
  error?: string;
  can_retry?: boolean;
  original_code?: string;
  filename?: string;
  language?: string;
  is_file_level?: boolean;
  remediation_category?: 'source_code' | 'sensitive_config' | 'env_template' | 'generic';
  remediation_type?: string;
  remediation_steps?: string[];
  recommended_commands?: string[];
}

export interface PatchVerificationResponse {
  verification_state: VerificationState;
  verified: boolean;
  message?: string;
  error?: string;
  target_findings?: any[];
  before_findings?: any[];
  after_findings?: any[];
  remaining_issues?: any[];
  remaining_issues_count?: number;
  unified_diff?: string;
  disclaimer: string;
  syntax_error?: string;
}
