/**
 * clarinet.js  –  v2
 * WebSocket live-alert manager + toast system + sidebar toggle.
 */

'use strict';

// ── WebSocket ─────────────────────────────────────────────────────────────────

const WS_URL = `ws://${location.host}/ws/alerts`;
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
  showToast(data);
  bumpAlertBadge();
  browserNotify(data);
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

const ICONS = { CRITICAL: 'bi-exclamation-octagon-fill', WARNING: 'bi-exclamation-triangle-fill', INFO: 'bi-info-circle-fill' };
const CLASSES = { CRITICAL: 'toast-danger', WARNING: 'toast-warning', INFO: 'toast-info' };

function showToast(data) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const level   = data.level ?? 'INFO';
  const icon    = ICONS[level]  ?? ICONS.INFO;
  const cls     = CLASSES[level] ?? CLASSES.INFO;

  const el = document.createElement('div');
  el.className = `toast ${cls}`;
  el.innerHTML = `
    <i class="bi ${icon} toast-icon"></i>
    <div class="toast-body">
      <div class="toast-title">${esc(data.title)}</div>
      <div class="toast-msg">${esc(data.message ?? '')}</div>
    </div>
    <button class="toast-close" onclick="this.closest('.toast').remove()">×</button>`;

  container.appendChild(el);
  setTimeout(() => el.style.opacity = '0', 7_000);
  setTimeout(() => el.remove(), 7_300);
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Sidebar mobile toggle ─────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const btn  = document.getElementById('sidebar-toggle');
  const nav  = document.getElementById('sidebar');

  btn?.addEventListener('click', () => nav?.classList.toggle('open'));

  document.addEventListener('click', e => {
    if (nav?.classList.contains('open') && !nav.contains(e.target) && !btn?.contains(e.target))
      nav.classList.remove('open');
  });

  // Start WS only on authenticated pages
  if (document.getElementById('ws-indicator')) wsConnect();
});
