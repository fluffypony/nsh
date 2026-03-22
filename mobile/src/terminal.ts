import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebglAddon } from '@xterm/addon-webgl';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

let term: Terminal;
let fitAddon: FitAddon;
let terminalDataUnlisten: (() => void) | null = null;
let resizeObserver: ResizeObserver | null = null;
/** Track which sessions have been attached at least once (for resume vs attach). */
const attachedSessions = new Set<string>();

export async function initTerminal(containerId: string, sessionId: string) {
  const container = document.getElementById(containerId)!;

  term = new Terminal({
    fontSize: 14,
    fontFamily: 'Menlo, Monaco, monospace',
    theme: { background: '#1a1a2e' },
    allowProposedApi: true,
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.loadAddon(new WebLinksAddon());

  term.open(container);

  try {
    term.loadAddon(new WebglAddon());
  } catch {
    console.warn('WebGL addon not available, using canvas renderer');
  }

  fitAddon.fit();

  // Use resume if we previously attached to this session, otherwise fresh attach.
  // Resume consumes the replay buffer so we don't miss output during detach.
  let initialScreen: number[];
  if (attachedSessions.has(sessionId)) {
    try {
      initialScreen = await invoke('resume_session', { sessionId });
    } catch {
      // Resume failed (e.g. session restarted); fall back to fresh attach
      initialScreen = await invoke('attach_session', { sessionId });
    }
  } else {
    initialScreen = await invoke('attach_session', { sessionId });
  }
  attachedSessions.add(sessionId);
  if (initialScreen.length > 0) {
    term.write(new Uint8Array(initialScreen));
  }

  // Forward keystrokes to daemon
  term.onData((data: string) => {
    const bytes = Array.from(new TextEncoder().encode(data));
    invoke('send_input', { bytes });
  });

  // Listen for terminal output from daemon (store unlisten handle)
  terminalDataUnlisten = await listen('terminal-data', (event) => {
    const bytes = new Uint8Array(event.payload as number[]);
    term.write(bytes);
  });

  // Handle resize (store observer for cleanup)
  resizeObserver = new ResizeObserver(() => {
    fitAddon.fit();
    const dims = fitAddon.proposeDimensions();
    if (dims) {
      invoke('resize_terminal', { cols: dims.cols, rows: dims.rows });
    }
  });
  resizeObserver.observe(container);

  // Initial resize notification
  const dims = fitAddon.proposeDimensions();
  if (dims) {
    invoke('resize_terminal', { cols: dims.cols, rows: dims.rows });
  }
}

export function disposeTerminal(sendDetach: boolean = true) {
  if (sendDetach) {
    invoke('detach_session');
  }
  if (terminalDataUnlisten) {
    terminalDataUnlisten();
    terminalDataUnlisten = null;
  }
  if (resizeObserver) {
    resizeObserver.disconnect();
    resizeObserver = null;
  }
  term?.dispose();
}
