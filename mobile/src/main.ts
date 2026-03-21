import { connectToDaemon, listSessions } from './sessions';
import { initTerminal, disposeTerminal } from './terminal';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { sendNotification } from '@tauri-apps/plugin-notification';

// App entry point — renders based on current state
let currentView: 'pair' | 'sessions' | 'terminal' = 'pair';

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
      </div>
    `,
      )
      .join('');

    // Attach click handlers to session cards
    listEl.querySelectorAll('.session-card').forEach((card) => {
      card.addEventListener('click', () => {
        const sessionId = card.getAttribute('data-id')!;
        renderTerminalView(sessionId);
      });
    });
  } catch (e) {
    document.getElementById('session-list')!.innerHTML = `<p>Error: ${e}</p>`;
  }
}

function renderTerminalView(sessionId: string) {
  currentView = 'terminal';
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
    disposeTerminal();
    try {
      await invoke('resume_session', { sessionId });
      initTerminal('terminal-container', sessionId);
    } catch (e) {
      console.error('Reconnect failed:', e);
      renderSessionsView();
    }
  });

  initTerminal('terminal-container', sessionId);
}
