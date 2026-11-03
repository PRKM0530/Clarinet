/**
 * device_speed.js
 * Measures the link between this device and Clarinet: round-trip time (latency and jitter),
 * download and upload speed. It sends only the numbers to /speed/device/result.
 * Nothing is sent to any other website.
 */
'use strict';

(function () {
  const BASE = '/speed/device';
  const SECONDS_PER_DIRECTION = 3;
  const BLOCK = 2 * 1024 * 1024;

  const now = () => performance.now();
  const mbps = (bytes, ms) => (bytes * 8) / 1e6 / (ms / 1000);

  async function latency() {
    const times = [];
    for (let i = 0; i < 10; i++) {
      const start = now();
      const response = await fetch(`${BASE}/probe/ping?t=${Date.now()}_${i}`, { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok && response.status !== 204) throw new Error('ping');
      times.push(now() - start);
    }
    times.sort((a, b) => a - b);
    const kept = times.slice(0, 8);                       // the slowest couple are usually one-off hiccups
    const mean = kept.reduce((a, b) => a + b, 0) / kept.length;
    const jitter = kept.slice(1).reduce((sum, t, i) => sum + Math.abs(t - kept[i]), 0) / (kept.length - 1);
    return { latency: mean, jitter };
  }

  async function download() {
    let bytes = 0;
    const start = now();
    while (now() - start < SECONDS_PER_DIRECTION * 1000) {
      const response = await fetch(`${BASE}/probe/down?bytes=${BLOCK}&t=${Date.now()}`, { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error('download');
      bytes += (await response.arrayBuffer()).byteLength;
    }
    return mbps(bytes, now() - start);
  }

  async function upload() {
    const payload = new Uint8Array(BLOCK);
    let bytes = 0;
    const start = now();
    while (now() - start < SECONDS_PER_DIRECTION * 1000) {
      const response = await fetch(`${BASE}/probe/up`, { method: 'POST', body: payload, cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error('upload');
      bytes += payload.byteLength;
    }
    return mbps(bytes, now() - start);
  }

  async function run(button, say) {
    button.disabled = true;
    try {
      say('Measuring delay...');
      const ping = await latency();
      say('Measuring download...');
      const down = await download();
      say('Measuring upload...');
      const up = await upload();
      say('Saving...');
      const response = await fetch(`${BASE}/result`, {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ download_mbps: down, upload_mbps: up, latency_ms: ping.latency, jitter_ms: ping.jitter }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'The result could not be saved.');
      location.reload();
    } catch (error) {
      const own = error && error.message && !['ping', 'download', 'upload'].includes(error.message);
      say(own ? error.message : 'The test did not finish. Check that you are still connected, then try again.', true);
      button.disabled = false;
    }
  }

  document.addEventListener('click', event => {
    const button = event.target.closest('[data-device-speed-test]');
    if (!button) return;
    const note = document.getElementById(button.dataset.note);
    run(button, (text, failed) => {
      if (note) { note.textContent = text; note.classList.toggle('text-bad', Boolean(failed)); }
    });
  });
})();
