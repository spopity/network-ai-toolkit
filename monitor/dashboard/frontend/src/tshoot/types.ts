export type CommandKind = 'read' | 'write' | 'blocked' | 'refused';

export interface CommandEntry {
  id: string;
  command: string;
  kind: CommandKind;
  purpose: string;
  status: 'running' | 'done' | 'blocked' | 'refused';
  ts: number;
  exit_code?: number | null;
  duration_ms?: number;
  output?: string;
  timed_out?: boolean;
  truncated?: boolean;
  error?: string | null;
  reason?: string;
}

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'superseded' | 'blocked' | 'expired';

export interface ApprovalRequest {
  id: string;
  command: string;
  reason: string;
  expected_effect: string;
  rollback: string;
  risk: 'low' | 'medium' | 'high';
  warnings: string[];
  policy_reason: string;
}

export type ChatItem =
  | { kind: 'user'; id: string; content: string }
  | { kind: 'assistant'; id: string; content: string; model?: string; error?: boolean }
  | ({ kind: 'approval'; status: ApprovalStatus } & ApprovalRequest);

export type TshootEvent =
  | { type: 'status' | 'note'; content: string }
  | ({ type: 'command' } & Omit<CommandEntry, 'ts' | 'status'> & { status: string })
  | { type: 'command_result'; id: string; exit_code: number | null; duration_ms: number; output: string; timed_out: boolean; truncated: boolean; error: string | null }
  | ({ type: 'approval' } & ApprovalRequest)
  | { type: 'approval_update'; id: string; status: ApprovalStatus }
  | { type: 'final'; content: string; agent: string; model?: string; awaiting_approval?: string }
  | { type: 'error'; content: string };
