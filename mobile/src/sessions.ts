import { invoke } from '@tauri-apps/api/core';

export interface RemoteSessionInfo {
  session_id: string;
  tty: string;
  shell: string;
  pid: number;
  label: string | null;
  last_cwd: string | null;
  last_command: string | null;
  git_branch: string | null;
  running_command: string | null;
}

export async function connectToDaemon(
  nodeId: string,
  relayUrl?: string,
): Promise<void> {
  await invoke('connect_to_daemon', { nodeId, relayUrl });
}

export async function listSessions(): Promise<RemoteSessionInfo[]> {
  return await invoke('list_sessions');
}

export async function sendQuery(
  sessionId: string,
  query: string,
  think: boolean = false,
): Promise<string> {
  return await invoke('send_query', { sessionId, query, think });
}

export interface SessionHistoryEntry {
  command: string;
  cwd: string | null;
  exit_code: number | null;
  started_at: string;
  duration_ms: number | null;
  summary: string | null;
  output_preview: string | null;
}

export async function getSessionHistory(
  sessionId: string,
  limit: number = 50,
): Promise<SessionHistoryEntry[]> {
  return await invoke('get_session_history', { sessionId, limit });
}
