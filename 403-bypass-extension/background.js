// background.js — service worker (module)
// Runs the 403-bypass test engine. State lives here so the popup can close
// and reopen without losing an in-progress run.

import { buildTests } from "./techniques.js";

const DEFAULTS = {
  rate: "normal",
  timeoutMs: 12000,
  credentials: "include", // mirror the operator's browser session
  maxBodyBytes: 200 * 1024,
};

// Global request-pacing profiles. rps caps request *starts* per second across
// the whole run (not just in-flight count), so we stay gentle on the target.
const RATE_PROFILES = {
  polite: { rps: 5, concurrency: 3, label: "Polite ~5 rps" },
  normal: { rps: 12, concurrency: 6, label: "Normal ~12 rps" },
  fast: { rps: 25, concurrency: 10, label: "Fast ~25 rps" },
};

function sleep(ms, signal) {
  return new Promise((resolve) => {
    if (ms <= 0) return resolve();
    const t = setTimeout(resolve, ms);
    if (signal) signal.addEventListener("abort", () => { clearTimeout(t); resolve(); }, { once: true });
  });
}

// Token-bucket-ish pacer: enforces a minimum spacing between request starts,
// adds jitter, and backs off automatically when the server answers 429/503.
class Pacer {
  constructor(rps) {
    this.base = 1000 / rps;
    this.interval = this.base;
    this.next = 0;
    this.cooldownUntil = 0;
    this.throttled = false;
  }
  note(status) {
    if (status === 429 || status === 503) {
      this.interval = Math.min(this.interval * 1.6, this.base * 10);
      this.cooldownUntil = performance.now() + 1500;
      this.throttled = true;
    } else if (this.interval > this.base) {
      this.interval = Math.max(this.base, this.interval * 0.9);
      if (this.interval <= this.base * 1.05) this.throttled = false;
    }
  }
  async acquire(signal) {
    const now = performance.now();
    const slot = Math.max(now, this.next, this.cooldownUntil);
    const jitter = 0.85 + Math.random() * 0.3;
    this.next = slot + this.interval * jitter;
    await sleep(slot - now, signal);
  }
}

let ruleSeq = 9000; // session DNR rule ids

/** @type {Set<chrome.runtime.Port>} */
const ports = new Set();

let state = freshState();
let currentAbort = null;

function freshState() {
  return {
    running: false,
    target: "",
    options: null,
    baseline: null, // {status, size, redirected, finalUrl, error}
    results: [], // ordered as completed
    total: 0,
    done: 0,
    startedAt: 0,
    finishedAt: 0,
    error: null,
    throttled: false,
  };
}

function broadcast() {
  const msg = { type: "state", state };
  for (const p of ports) {
    try { p.postMessage(msg); } catch (_) {}
  }
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "bypass") return;
  ports.add(port);
  port.onDisconnect.addListener(() => ports.delete(port));
  port.onMessage.addListener((msg) => handleMessage(msg, port));
  // Send current snapshot immediately.
  port.postMessage({ type: "state", state });
});

async function handleMessage(msg, port) {
  switch (msg.type) {
    case "getState":
      port.postMessage({ type: "state", state });
      break;
    case "start":
      startRun(msg.url, msg.options || {}).catch((e) => {
        state.running = false;
        state.error = String(e && e.message || e);
        broadcast();
      });
      break;
    case "stop":
      if (currentAbort) currentAbort.abort();
      break;
    case "clear":
      if (!state.running) {
        state = freshState();
        broadcast();
      }
      break;
  }
}

async function startRun(rawUrl, userOpts) {
  if (state.running) return;

  let target;
  try {
    target = new URL(rawUrl);
    if (!/^https?:$/.test(target.protocol)) throw new Error("URL must be http(s)");
  } catch (e) {
    state = freshState();
    state.error = "Invalid URL: " + String(e.message || e);
    broadcast();
    return;
  }

  const opts = { ...DEFAULTS, ...userOpts };
  const profile = RATE_PROFILES[opts.rate] || RATE_PROFILES.normal;
  opts.concurrency = profile.concurrency;
  opts.rps = profile.rps;
  opts.rateLabel = profile.label;
  const pacer = new Pacer(profile.rps);
  const { baseline, tests } = buildTests(target.href, opts);

  state = freshState();
  state.running = true;
  state.target = target.href;
  state.options = opts;
  state.total = tests.length;
  state.startedAt = Date.now();
  broadcast();

  currentAbort = new AbortController();
  const { signal } = currentAbort;

  // Baseline request.
  state.baseline = await doFetch(baseline.url, baseline.method, {}, opts, signal);
  broadcast();

  // Split header-rule tests (sequential, DNR) from plain tests (pooled).
  const ruleTests = tests.filter((t) => t.useHeaderRule);
  const plainTests = tests.filter((t) => !t.useHeaderRule);

  try {
    await runPool(plainTests, opts.concurrency, async (t) => {
      await pacer.acquire(signal);
      if (signal.aborted) return;
      const headers = t.header ? { [t.header]: t.headerValue } : {};
      const r = await doFetch(t.url, t.method, headers, opts, signal);
      pacer.note(r.status);
      state.throttled = pacer.throttled;
      recordResult(t, r);
    }, signal);

    // Sequential DNR header tests.
    for (const t of ruleTests) {
      if (signal.aborted) break;
      await pacer.acquire(signal);
      if (signal.aborted) break;
      const r = await fetchWithHeaderRule(t.url, t.header, t.headerValue, opts, signal);
      pacer.note(r.status);
      state.throttled = pacer.throttled;
      recordResult(t, r);
    }
  } catch (e) {
    if (!signal.aborted) state.error = String(e && e.message || e);
  }

  state.running = false;
  state.finishedAt = Date.now();
  currentAbort = null;
  broadcast();
}

function classify(baseline, r) {
  if (r.error) return "error";
  const s = r.status;
  if (s >= 200 && s < 300) return "success";
  if (s >= 300 && s < 400) return "redirect";
  if (r.redirected) return "redirect";
  const baseStatus = baseline && baseline.status;
  if (s !== baseStatus && s !== 403 && s !== 401) return "changed";
  return "same";
}

function recordResult(t, r) {
  const verdict = classify(state.baseline, r);
  state.results.push({
    id: t.id,
    category: t.category,
    label: t.label,
    method: t.method,
    url: t.url,
    header: t.header || null,
    headerValue: t.headerValue || null,
    normalized: !!t.normalized,
    usedRule: !!t.useHeaderRule,
    status: r.status,
    size: r.size,
    redirected: r.redirected,
    finalUrl: r.finalUrl,
    ms: r.ms,
    error: r.error || null,
    verdict,
  });
  state.done = state.results.length;
  // Throttle broadcasts a bit to avoid flooding the popup.
  maybeBroadcast();
}

let lastBroadcast = 0;
function maybeBroadcast() {
  const now = Date.now();
  if (state.done >= state.total || now - lastBroadcast > 120) {
    lastBroadcast = now;
    broadcast();
  }
}

async function doFetch(rawUrl, method, headers, opts, signal) {
  const t0 = performance.now();
  const ctrl = new AbortController();
  const onAbort = () => ctrl.abort();
  signal.addEventListener("abort", onAbort, { once: true });
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs);
  try {
    const res = await fetch(rawUrl, {
      method,
      headers,
      redirect: "follow",
      credentials: opts.credentials,
      cache: "no-store",
      signal: ctrl.signal,
    });
    let size = 0;
    if (method !== "HEAD") {
      try {
        const reader = res.body && res.body.getReader ? res.body.getReader() : null;
        if (reader) {
          while (size < opts.maxBodyBytes) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
          }
          try { await reader.cancel(); } catch (_) {}
        } else {
          const buf = await res.arrayBuffer();
          size = buf.byteLength;
        }
      } catch (_) {
        const cl = res.headers.get("content-length");
        if (cl) size = parseInt(cl, 10) || 0;
      }
    }
    return {
      status: res.status,
      size,
      redirected: res.redirected,
      finalUrl: res.url,
      ms: Math.round(performance.now() - t0),
      error: null,
    };
  } catch (err) {
    const aborted = ctrl.signal.aborted;
    return {
      status: null,
      size: 0,
      redirected: false,
      finalUrl: rawUrl,
      ms: Math.round(performance.now() - t0),
      error: aborted ? "timeout/aborted" : String(err && err.message || err),
    };
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", onAbort);
  }
}

// Send a request with a forbidden header (Host/Origin/Referer) injected via
// declarativeNetRequest, since fetch() would silently drop it.
async function fetchWithHeaderRule(url, header, value, opts, signal) {
  const id = ++ruleSeq;
  const rule = {
    id,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [{ header, operation: "set", value }],
    },
    condition: {
      urlFilter: url,
      resourceTypes: ["xmlhttprequest", "other"],
    },
  };
  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [id],
      addRules: [rule],
    });
  } catch (e) {
    return { status: null, size: 0, redirected: false, finalUrl: url, ms: 0, error: "dnr-rule-failed: " + (e.message || e) };
  }
  try {
    // Also set it directly (harmless if dropped); DNR guarantees it lands.
    return await doFetch(url, "GET", { [header]: value }, opts, signal);
  } finally {
    try {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [id] });
    } catch (_) {}
  }
}

// Simple bounded-concurrency worker pool.
async function runPool(items, concurrency, worker, signal) {
  let idx = 0;
  const n = Math.max(1, Math.min(concurrency, 20));
  const workers = [];
  for (let i = 0; i < n; i++) {
    workers.push((async () => {
      while (true) {
        if (signal.aborted) return;
        const cur = idx++;
        if (cur >= items.length) return;
        await worker(items[cur]);
      }
    })());
  }
  await Promise.all(workers);
}

// Clean up any leftover session rules on startup.
chrome.runtime.onStartup?.addListener(clearAllSessionRules);
chrome.runtime.onInstalled.addListener(clearAllSessionRules);
async function clearAllSessionRules() {
  try {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    if (rules.length) {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: rules.map((r) => r.id),
      });
    }
  } catch (_) {}
}
