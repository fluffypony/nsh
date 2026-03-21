import { connectToDaemon, listSessions } from './sessions';
import { initTerminal, disposeTerminal } from './terminal';

// App entry point — renders based on current state
let currentView: 'pair' | 'sessions' | 'terminal' = 'pair';

document.addEventListener('DOMContentLoaded', () => {
  renderPairView();
});

function renderPairView() {
  currentView = 'pair';
  const app = document.getElementById('app')!;
  app.innerHTML = `
    <div class="pair-view">
      <h1>nsh Remote</h1>
      <p>Enter your computer's EndpointId or scan the QR code.</p>
      <input type="text" id="node-id-input" placeholder="EndpointId" />
      <button id="connect-btn">Connect</button>
      <p id="status-msg"></p>
    </div>
  `;

  document.getElementById('connect-btn')!.addEventListener('click', async () => {
    const nodeId = (document.getElementById('node-id-input') as HTMLInputElement).value.trim();
    if (!nodeId) return;

    const statusMsg = document.getElementById('status-msg')!;
    statusMsg.textContent = 'Connecting...';

    try {
      await connectToDaemon(nodeId);
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

  document.getElementById('back-btn')!.addEventListener('click', () => {
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
        <span>${sessionId}</span>
      </div>
      <div id="terminal-container"></div>
    </div>
  `;

  document.getElementById('detach-btn')!.addEventListener('click', () => {
    disposeTerminal();
    renderSessionsView();
  });

  initTerminal('terminal-container', sessionId);
}
