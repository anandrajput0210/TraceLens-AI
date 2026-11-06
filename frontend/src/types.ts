export type Finding = {
  id: string;
  rule_id: string;
  title: string;
  category: string;
  file: string;
  line: number;
  evidence: string;
  base_severity: string;
  confidence: number;
  environment: string;
  environment_confidence: number;
  exposure: string;
  exposure_confidence: number;
  reachability: string;
  context_score: number;
  risk_level: string;
  risk_path: string[];
};

export type ScoringPolicy = {
  levels: { level: string; min: number }[];
  critical_floor: { default: number; test: number };
};

export type Analysis = {
  analysis_id: string;
  status: string;
  progress: number;
  repository: string;
  files_analyzed: number;
  findings_count: number;
  overall_score: number;
  risk_level: string;
  scoring_policy?: ScoringPolicy;
  findings: Finding[];
  errors?: {
    rule_id: string;
    file: string;
    error: string;
  }[];
  error?: string;
};
