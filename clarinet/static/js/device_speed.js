/**
 * device_speed.js
 * Measures the link between this device and Clarinet: round-trip time (latency and jitter),
 * download and upload speed. It sends only the numbers to /speed/device/result.
 * Nothing is sent to any other website.
 *
 * Two ways to run: the "Test this device" button, and quietly in the background when the page is open on
 * the owner's device and the last test is older than the interval (the server decides: /speed/device/due).
 */
'use strict';

(function () {
  const BASE = '/speed/device';
  const SECONDS_PER_DIRECTION = 3;
  const BLOCK = 2 * 1024 * 1024;
  const LOCK_KEY = 'clarinet-speed-lock';

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

  /** One full measurement, saved to the server. `say` reports progress. */
  async function measureAndSave(say) {
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
    return data;
  }

  /** The computer that runs Clarinet: measure its own internet connection on the server and wait for it. */
  async function hostTest(say) {
    const start = await fetch(`${BASE}/host-test`, { method: 'POST', credentials: 'same-origin' });
    const first = await start.json().catch(() => ({}));
    if (!start.ok) throw new Error(first.error || 'The test could not start.');
    say('Measuring this computer\'s internet speed. This takes about a minute...');
    for (let i = 0; i < 60; i++) {
      await new Promise(resolve => setTimeout(resolve, 3000));
      const status = await (await fetch(`${BASE}/host-test/status`, { credentials: 'same-origin', cache: 'no-store' })).json();
      if (!status.running) {
        if (status.error) throw new Error(status.error);
        return;
      }
    }
    throw new Error('The test is taking too long. Try again in a moment.');
  }

  async function run(button, say) {
    button.disabled = true;
    try {
      if (button.dataset.host) await hostTest(say);
      else await measureAndSave(say);
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

  // ---- the quiet test
  let busy = false;
  async function checkIfDue() {
    if (busy || document.hidden) return;                                        // only while someone is looking
    if (navigator.connection && navigator.connection.saveData) return;          // respect "data saver"
    try {
      const locked = Number(localStorage.getItem(LOCK_KEY) || 0);
      if (Date.now() - locked < 3 * 60 * 1000) return;                           // another tab is already testing
      const response = await fetch(`${BASE}/due`, { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok || !(await response.json()).due) return;
      localStorage.setItem(LOCK_KEY, String(Date.now()));
    } catch (error) { return; }
    busy = true;
    try {
      await measureAndSave(() => {});
      document.dispatchEvent(new CustomEvent('clarinet:speed-tested'));
    } catch (error) { /* try again at the next check */ }
    busy = false;
  }
  if (document.getElementById('sidebar')) {                                       // only inside the app, not on sign-in pages
    setTimeout(checkIfDue, 10 * 1000);
    setInterval(checkIfDue, 5 * 60 * 1000);
  }
})();
