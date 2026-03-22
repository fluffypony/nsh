import { connectToDaemon, listSessions, getSessionHistory } from './sessions';
import type { SessionHistoryEntry } from './sessions';
import { initTerminal, disposeTerminal } from './terminal';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { sendNotification } from '@tauri-apps/plugin-notification';

// App entry point — renders based on current state
let currentView: 'pair' | 'sessions' | 'terminal' = 'pair';
/** Persisted sessionId of the currently viewed terminal (survives view transitions). */
let activeSessionId: string | null = null;

function parseConnectionPayload(input: string): {
  nodeId: string;
  relayUrl?: string;
} {
  if (input.startsWith('nsh://')) {
    const path = input.slice('nsh://'.length);
    const slashIdx = path.indexOf('/');
    if (slashIdx > 0) {
      return {
        nodeId: path.slice(0, slashIdx),
        relayUrl: path.slice(slashIdx + 1),
      };
    }
    return { nodeId: path };
  }
  return { nodeId: input };
}

document.addEventListener('DOMContentLoaded', async () => {
  // Listen for session updates to refresh session list
  await listen('session-update', () => {
    if (currentView === 'sessions') {
      renderSessionsView();
    }
  });

  // Wire push notifications to native notification API
  await listen('push-notification', (e: any) => {
    sendNotification({ title: e.payload.title, body: e.payload.body });
  });

  // Listen for real-time state pushes via datagrams
  await listen('state-push', () => {
    if (currentView === 'sessions') {
      renderSessionsView();
    }
  });

  renderPairView();
});

function renderPairView() {
  currentView = 'pair';
  const app = document.getElementById('app')!;
  app.innerHTML = `
    <div class="pair-view">
      <h1>nsh Remote</h1>
      <p>Enter your computer's EndpointId.</p>
      <input type="text" id="node-id-input" placeholder="EndpointId" />
      <button id="connect-btn">Connect</button>
      <p id="status-msg"></p>
    </div>
  `;

  document.getElementById('connect-btn')!.addEventListener('click', async () => {
    const rawInput = (document.getElementById('node-id-input') as HTMLInputElement).value.trim();
    if (!rawInput) return;

    const statusMsg = document.getElementById('status-msg')!;
    statusMsg.textContent = 'Connecting...';

    try {
      const { nodeId, relayUrl } = parseConnectionPayload(rawInput);
      await connectToDaemon(nodeId, relayUrl);
      statusMsg.textContent = 'Connected!';
      renderSessionsView();
    } catch (e) {
      statusMsg.textContent = `Error: ${e}`;
    }
  });
}

async function renderSessionsView() {
  currentView = 'sessions';
  const app = document.getElementById('app')!;
  app.innerHTML = `
    <div class="sessions-view">
      <h2>Active Sessions</h2>
      <div id="session-list">Loading...</div>
      <button id="back-btn">Disconnect</button>
    </div>
  `;

  document.getElementById('back-btn')!.addEventListener('click', async () => {
    await invoke('disconnect_from_daemon');
    renderPairView();
  });

  try {
    const sessions = await listSessions();
    const listEl = document.getElementById('session-list')!;
    if (sessions.length === 0) {
      listEl.innerHTML = '<p>No active sessions.</p>';
      return;
    }
    listEl.innerHTML = sessions
      .map(
        (s) => `
      <div class="session-card" data-id="${s.session_id}">
        <strong>${s.label || s.session_id}</strong>
        <span class="session-detail">${s.shell} (${s.tty})</span>
        ${s.last_cwd ? `<span class="session-cwd">${s.last_cwd}</span>` : ''}
        ${s.git_branch ? `<span class="session-branch">${s.git_branch}</span>` : ''}
        <button class="history-btn" data-id="${s.session_id}">History</button>
      </div>
    `,
      )
      .join('');

    // Attach click handlers to session cards (open terminal)
    listEl.querySelectorAll('.session-card').forEach((card) => {
      card.addEventListener('click', (e) => {
        // Don't trigger if the history button was clicked
        if ((e.target as HTMLElement).classList.contains('history-btn')) return;
        const sessionId = card.getAttribute('data-id')!;
        renderTerminalView(sessionId);
      });
    });

    // Attach click handlers to history buttons
    listEl.querySelectorAll('.history-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const sessionId = (btn as HTMLElement).getAttribute('data-id')!;
        renderHistoryView(sessionId);
      });
    });
  } catch (e) {
    document.getElementById('session-list')!.innerHTML = `<p>Error: ${e}</p>`;
  }
}

function renderTerminalView(sessionId: string) {
  currentView = 'terminal';
  activeSessionId = sessionId;
  const app = document.getElementById('app')!;
  app.innerHTML = `
    <div class="terminal-view">
      <div class="terminal-toolbar">
        <button id="detach-btn">← Back</button>
        <button id="reconnect-btn">Reconnect</button>
        <span>${sessionId}</span>
      </div>
      <div id="terminal-container"></div>
    </div>
  `;

  document.getElementById('detach-btn')!.addEventListener('click', () => {
    disposeTerminal();
    renderSessionsView();
  });

  document.getElementById('reconnect-btn')!.addEventListener('click', async () => {
    try {
      // Detach and clean up terminal UI (skip sending detach from dispose
      // since we send it explicitly here to avoid race conditions)
      await invoke('detach_session');
      disposeTerminal(false);
      // Re-attach fresh
      renderTerminalView(sessionId);
    } catch (e) {
      console.error('Reconnect failed:', e);
      renderSessionsView();
    }
  });

  initTerminal('terminal-container', sessionId);
}

async function renderHistoryView(sessionId: string) {
  const app = document.getElementById('app')!;
  app.innerHTML = `
    <div class="history-view">
      <div class="history-toolbar">
        <button id="history-back-btn">← Back</button>
        <span>History: ${sessionId}</span>
      </div>
      <div id="history-list">Loading...</div>
    </div>
  `;

  document.getElementById('history-back-btn')!.addEventListener('click', () => {
    renderSessionsView();
  });

  try {
    const entries: SessionHistoryEntry[] = await getSessionHistory(sessionId);
    const listEl = document.getElementById('history-list')!;
    if (entries.length === 0) {
      listEl.innerHTML = '<p>No command history.</p>';
      return;
    }
    listEl.innerHTML = entries
      .map(
        (e) => `
      <div class="history-entry ${e.exit_code !== null && e.exit_code !== 0 ? 'history-error' : ''}">
        <code class="history-command">${escapeHtml(e.command)}</code>
        <div class="history-meta">
          ${e.exit_code !== null ? `<span class="history-exit">exit ${e.exit_code}</span>` : ''}
          ${e.cwd ? `<span class="history-cwd">${escapeHtml(e.cwd)}</span>` : ''}
          <span class="history-time">${e.started_at}</span>
          ${e.duration_ms !== null ? `<span class="history-duration">${e.duration_ms}ms</span>` : ''}
        </div>
        ${e.summary ? `<div class="history-summary">${escapeHtml(e.summary)}</div>` : ''}
        ${e.output_preview ? `<pre class="history-output">${escapeHtml(e.output_preview)}</pre>` : ''}
      </div>
    `,
      )
      .join('');
  } catch (e) {
    document.getElementById('history-list')!.innerHTML = `<p>Error: ${e}</p>`;
  }
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
