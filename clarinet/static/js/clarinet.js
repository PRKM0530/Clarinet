/**
 * clarinet.js  –  v2
 * WebSocket live-alert manager + toast system + sidebar toggle.
 */

'use strict';

// ── WebSocket ─────────────────────────────────────────────────────────────────

// wss on https pages: browsers block plain ws from a secure page, which would silently stop live alerts
const WS_URL = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/alerts`;
let ws = null;
let wsReconnectTimeout = null;

function wsConnect() {
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;

  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    setWsState('connected');
    ws._ping = setInterval(() => ws.readyState === WebSocket.OPEN && ws.send('ping'), 25_000);
  };

  ws.onmessage = ({ data }) => {
    if (data === 'pong') return;
    try { onAlert(JSON.parse(data)); } catch {}
  };

  ws.onerror = () => ws.close();

  ws.onclose = () => {
    clearInterval(ws._ping);
    setWsState('disconnected');
    if (!wsReconnectTimeout)
      wsReconnectTimeout = setTimeout(() => {
        wsReconnectTimeout = null;
        setWsState('connecting');
        wsConnect();
      }, 5_000);
  };
}

function setWsState(state) {
  const dot   = document.getElementById('ws-indicator');
  const label = document.getElementById('ws-label');
  if (!dot) return;
  dot.className = `ws-dot ${state}`;
  if (label) label.textContent = { connected: 'Live', connecting: 'Connecting', disconnected: 'Offline' }[state] ?? state;
}

// ── Alert handler ─────────────────────────────────────────────────────────────

function onAlert(data) {
  document.dispatchEvent(new CustomEvent('clarinet:alert', { detail: data }));
  showToast(data);
  bumpAlertBadge();
  browserNotify(data);
}

// Current mode and the counts shown next to Alerts and Devices in the sidebar
function setBadge(href, count, extraClass) {
  const link = document.querySelector(`#sidebar a[href="${href}"]`);
  if (!link) return;
  let badge = link.querySelector('.sidebar-badge, .sidebar-badge-warn');
  if (!count) { badge?.remove(); return; }
  if (!badge) {
    badge = document.createElement('span');
    link.appendChild(badge);
  }
  badge.className = extraClass || 'sidebar-badge';
  badge.textContent = count;
}

function loadStatus() {
  fetch('/api/status/topbar', { credentials: 'same-origin', headers: { 'X-Clarinet-Poll': '1' } })
    .then(r => (r.ok ? r.json() : null))
    .then(s => {
      if (!s) return;
      const mode = document.getElementById('mode-label');
      if (mode && s.mode_word) mode.textContent = s.mode_word;
      setBadge('/alerts', s.open_alerts, 'sidebar-badge');
      if (s.new_devices !== null && s.new_devices !== undefined) setBadge('/devices', s.new_devices, 'sidebar-badge-warn');
    })
    .catch(() => { /* the page works without it */ });
}

// Browser notifications (DASH-3): shown while the dashboard is open, in addition to the toast.
// Browsers only allow asking for permission after a click, so ask once, on the first click.
function browserNotify(data) {
  try {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    new Notification(data.title || 'Clarinet alert', { body: data.message || '', tag: String(data.alert_id || data.title) });
  } catch (e) { /* notifications are optional */ }
}

document.addEventListener('click', function askForNotifications() {
  try {
    if ('Notification' in window && Notification.permission === 'default' && !localStorage.getItem('notifAsked')) {
      localStorage.setItem('notifAsked', '1');
      Notification.requestPermission();
    }
  } catch (e) { /* ignore */ }
  document.removeEventListener('click', askForNotifications);
});

function bumpAlertBadge() {
  const badge = document.querySelector('a[href="/alerts"] .sidebar-badge');
  if (badge) {
    badge.textContent = parseInt(badge.textContent || '0') + 1;
  } else {
    const link = document.querySelector('a[href="/alerts"]');
    if (link) {
      const b = document.createElement('span');
      b.className = 'sidebar-badge';
      b.textContent = '1';
      link.appendChild(b);
    }
  }
}

// ── Toast system ──────────────────────────────────────────────────────────────

const CLASSES = { CRITICAL: 'toast-danger', WARNING: 'toast-warning', INFO: 'toast-info' };

function showToast(data) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const level   = data.level ?? 'INFO';
  const cls     = CLASSES[level] ?? CLASSES.INFO;

  const el = document.createElement('div');
  el.className = `toast ${cls}`;
  el.innerHTML = `
    <div class="toast-body">
      <div class="toast-title">${esc(data.title)}</div>
      <div class="toast-msg">${esc(data.message ?? '')}</div>
    </div>
    <button class="toast-close" type="button" aria-label="Dismiss" onclick="this.closest('.toast').remove()">&times;</button>`;

  container.appendChild(el);
  setTimeout(() => el.style.opacity = '0', 7_000);
  setTimeout(() => el.remove(), 7_300);
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Show / hide on every password field ──────────────────────────────────────

function addPasswordToggles(root) {
  (root || document).querySelectorAll('input[type="password"]').forEach(input => {
    if (input.dataset.hasToggle) return;
    input.dataset.hasToggle = '1';

    const wrap = document.createElement('div');
    wrap.className = 'password-field';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'password-toggle';
    button.setAttribute('aria-label', 'Show password');
    button.setAttribute('aria-pressed', 'false');
    button.innerHTML = '<i class="bi bi-eye" aria-hidden="true"></i>';
    button.addEventListener('click', () => {
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(reveal));
      button.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
      button.innerHTML = `<i class="bi ${reveal ? 'bi-eye-slash' : 'bi-eye'}" aria-hidden="true"></i>`;
    });
    wrap.appendChild(button);
  });
}

// ── Sidebar mobile toggle ─────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  addPasswordToggles();
  const btn  = document.getElementById('sidebar-toggle');
  const nav  = document.getElementById('sidebar');

  btn?.addEventListener('click', () => nav?.classList.toggle('open'));

  document.addEventListener('click', e => {
    if (nav?.classList.contains('open') && !nav.contains(e.target) && !btn?.contains(e.target))
      nav.classList.remove('open');
  });

  // Start WS only on authenticated pages
  if (document.getElementById('ws-indicator')) {
    wsConnect();
    loadStatus();
    setInterval(loadStatus, 60_000);
  }
});
