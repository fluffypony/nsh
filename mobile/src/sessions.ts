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
