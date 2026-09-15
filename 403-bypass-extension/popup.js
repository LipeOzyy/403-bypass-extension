// popup.js — UI controller. Talks to the background engine over a Port.

const $ = (id) => document.getElementById(id);
const port = chrome.runtime.connect({ name: "bypass" });

let lastState = null;
let filter = "all";

// Prefill target with the active tab URL.
(async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url && /^https?:/.test(tab.url)) $("url").value = tab.url;
  } catch (_) {}
})();

port.onMessage.addListener((msg) => {
  if (msg.type === "state") {
    lastState = msg.state;
    render(msg.state);
  }
});

$("startBtn").addEventListener("click", () => {
  const url = $("url").value.trim();
  if (!url) { $("url").focus(); return; }
  const options = {
    path: $("c-path").checked,
    encoding: $("c-encoding").checked,
    param: $("c-param").checked,
    headers: $("c-headers").checked,
    methods: $("c-methods").checked,
    credentials: $("c-creds").checked ? "include" : "omit",
    rate: $("rate").value,
  };
  port.postMessage({ type: "start", url, options });
});

$("stopBtn").addEventListener("click", () => port.postMessage({ type: "stop" }));
$("clearBtn").addEventListener("click", () => port.postMessage({ type: "clear" }));

$("filterChips").addEventListener("click", (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  filter = btn.dataset.f;
  [...$("filterChips").children].forEach((b) => b.classList.toggle("active", b === btn));
  if (lastState) renderRows(lastState);
});

$("copyBtn").addEventListener("click", () => {
  if (!lastState) return;
  const header = "id,category,technique,method,status,size,ms,redirected,finalUrl,verdict,url\n";
  const rows = lastState.results.map((r) =>
    [r.id, r.category, csv(r.label), r.method, r.status ?? "ERR", r.size, r.ms,
     r.redirected, csv(r.finalUrl || ""), r.verdict, csv(r.url)].join(",")
  ).join("\n");
  navigator.clipboard.writeText(header + rows).then(() => {
    const b = $("copyBtn"); const t = b.textContent;
    b.textContent = "Copied!"; setTimeout(() => (b.textContent = t), 1200);
  });
});

function csv(s) {
  s = String(s ?? "");
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function render(state) {
  const running = state.running;
  $("startBtn").disabled = running;
  $("stopBtn").disabled = !running;
  $("clearBtn").disabled = running;

  // Baseline
  if (state.baseline) {
    const b = state.baseline;
    $("baseline").textContent = b.error
      ? `Baseline: ERROR (${b.error})`
      : `Baseline: ${b.status}  ·  ${fmtSize(b.size)}${b.redirected ? "  ·  redirected" : ""}`;
  } else {
    $("baseline").textContent = state.error ? `Error: ${state.error}` : "Baseline: —";
  }

  // Progress
  const pct = state.total ? Math.round((state.done / state.total) * 100) : 0;
  $("progFill").style.width = pct + "%";
  $("progCount").textContent = `${state.done} / ${state.total}`;
  $("throttle").hidden = !state.throttled;

  // Summary pills
  const counts = { success: 0, redirect: 0, changed: 0, error: 0 };
  for (const r of state.results) if (counts[r.verdict] !== undefined) counts[r.verdict]++;
  const sum = $("summary");
  sum.innerHTML = "";
  const defs = [
    ["success", "2xx hits", counts.success],
    ["redirect", "3xx", counts.redirect],
    ["changed", "changed", counts.changed],
    ["error", "errors", counts.error],
  ];
  for (const [cls, name, n] of defs) {
    if (n === 0) continue;
    const el = document.createElement("span");
    el.className = "pill " + cls;
    el.textContent = `${n} ${name}`;
    sum.appendChild(el);
  }

  renderRows(state);
}

function renderRows(state) {
  const tbody = $("rows");
  const empty = $("empty");
  let list = state.results;

  // Sort: interesting verdicts first, then by id.
  const rank = { success: 0, redirect: 1, changed: 2, error: 4, same: 3 };
  list = [...list].sort((a, b) => (rank[a.verdict] - rank[b.verdict]) || (a.id - b.id));

  if (filter !== "all") list = list.filter((r) => r.verdict === filter);

  tbody.innerHTML = "";
  if (list.length === 0) {
    empty.style.display = state.results.length ? "block" : "block";
    empty.textContent = state.results.length ? "No rows match this filter." :
      "No results yet. Enter a 403 endpoint and hit Start bypass.";
    return;
  }
  empty.style.display = "none";

  const frag = document.createDocumentFragment();
  for (const r of list) {
    const tr = document.createElement("tr");
    const status = r.error ? "ERR" : r.status;
    const normFlag = r.normalized ? '<span class="norm-flag" title="Browser likely normalized this path before sending">~</span> ' : "";
    tr.innerHTML =
      `<td>${r.id}</td>` +
      `<td class="cat">${r.category}</td>` +
      `<td class="tech" title="${esc(r.label)}\n${esc(r.url)}">${normFlag}${esc(r.label)}</td>` +
      `<td>${r.method}</td>` +
      `<td class="st ${r.verdict}">${status}${r.redirected ? "↪" : ""}</td>` +
      `<td>${r.error ? "—" : fmtSize(r.size)}</td>` +
      `<td>${r.ms}</td>`;
    frag.appendChild(tr);
  }
  tbody.appendChild(frag);
}

function fmtSize(n) {
  if (n == null) return "—";
  if (n < 1024) return n + "B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + "K";
  return (n / 1048576).toFixed(1) + "M";
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

port.postMessage({ type: "getState" });
