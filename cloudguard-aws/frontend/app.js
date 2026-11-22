"use strict";
const C = window.CLOUDGUARD;
const $ = (id) => document.getElementById(id);
let token = null, roles = [], ws = null, wsTimer = null, pingTimer = null, current = null;

// ---------- small helpers ----------
const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* storage may be blocked */ } },
  del(k) { try { sessionStorage.removeItem(k); } catch { /* ignore */ } },
};
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  Object.assign(n, props);
  kids.forEach((k) => n.append(k));
  return n;
}
const isAdmin = () => roles.includes("admin");

async function api(path, options = {}) {
  const res = await fetch(C.apiUrl + path, {
    ...options,
    headers: { Authorization: token, "Content-Type": "application/json" },
  });
  if (res.status === 401) { signOut(); throw new Error("Session expired. Please sign in again."); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
  return data;
}

// ---------- sign in (Cognito, direct) ----------
async function signIn(email, password) {
  const res = await fetch("https://cognito-idp." + C.region + ".amazonaws.com/", {
    method: "POST",
    headers: { "Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth" },
    body: JSON.stringify({ AuthFlow: "USER_PASSWORD_AUTH", ClientId: C.clientId, AuthParameters: { USERNAME: email, PASSWORD: password } }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.__type === "NotAuthorizedException" ? "Wrong email or password." : (data.message || "Sign in failed."));
  if (data.ChallengeName) throw new Error("This account needs a password change. Ask an admin to reset it.");
  return data.AuthenticationResult.IdToken;
}

function start() {
  $("login").hidden = true; $("app").hidden = false; $("who").hidden = false;
  $("logout").onclick = signOut;
  connectWs();
  refresh();
}

function signOut() {
  token = null; store.del("cg_token");
  if (ws) { ws.onclose = null; ws.close(); ws = null; }
  clearTimeout(wsTimer); clearInterval(pingTimer);
  $("app").hidden = true; $("who").hidden = true; $("login").hidden = false;
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-error").textContent = "";
  try {
    token = await signIn($("email").value.trim(), $("password").value);
    $("password").value = "";
    store.set("cg_token", token);
    await boot();
  } catch (err) { $("login-error").textContent = err.message; }
});

async function boot() {
  const me = await api("/me");
  roles = me.roles;
  $("user").textContent = me.user;
  $("role").textContent = roles.join(", ") || "no role";
  $("scan").disabled = !isAdmin();
  $("scan-hint").textContent = isAdmin() ? "" : "Viewers can read results. Only admins can start scans.";
  start();
}

// ---------- data ----------
async function refresh() {
  try {
    const q = new URLSearchParams();
    if ($("f-status").value) q.set("status", $("f-status").value);
    if ($("f-sev").value) q.set("severity", $("f-sev").value);
    const [score, findings, scans] = await Promise.all([api("/score"), api("/findings?" + q), api("/scans")]);
    renderScore(score); renderFindings(findings.findings); renderScans(scans.scans);
  } catch (err) { $("scan-status").textContent = err.message; }
}

function renderScore(s) {
  $("score").textContent = s.score;
  $("score").style.color = s.score >= 80 ? "var(--ok)" : s.score >= 50 ? "var(--med)" : "var(--crit)";
  $("score-sub").textContent = s.open + " open finding" + (s.open === 1 ? "" : "s");
  const sev = $("sev"); sev.replaceChildren();
  ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach((k) => {
    sev.append(el("div", {}, el("b", { className: k, textContent: s.by_severity[k] }), el("span", { className: "muted", textContent: k })));
  });
}

function renderFindings(list) {
  const body = $("findings"); body.replaceChildren();
  $("empty").hidden = list.length > 0;
  list.forEach((f) => {
    const btn = el("button", { className: "ghost", textContent: "Details" });
    btn.onclick = () => openDetail(f);
    body.append(el("tr", {},
      el("td", {}, el("span", { className: "badge " + f.severity, textContent: f.severity })),
      el("td", { textContent: f.rule_id + " – " + f.title }),
      el("td", { className: "res", textContent: f.resource }),
      el("td", { textContent: f.status }),
      el("td", {}, btn)));
  });
}

function renderScans(list) {
  const ul = $("scans"); ul.replaceChildren();
  if (!list.length) ul.append(el("li", { className: "muted", textContent: "No scans yet." }));
  list.forEach((s) => {
    const sum = s.summary ? " – score " + s.summary.score + ", " + s.summary.new + " new, " + s.summary.fixed + " fixed" : "";
    ul.append(el("li", { textContent: (s.created_at || "").replace("T", " ").slice(0, 19) + "  " + s.status + sum }));
  });
}

function openDetail(f) {
  current = f;
  $("d-title").textContent = f.rule_id + " – " + f.title;
  $("d-desc").textContent = f.description;
  $("d-fix").textContent = f.remediation;
  $("d-meta").textContent = "Resource: " + f.resource + " | First seen: " + f.first_seen + " | Status: " + f.status;
  $("d-resolve").hidden = !isAdmin() || f.status !== "open";
  $("d-note-wrap").hidden = $("d-resolve").hidden;
  $("detail").showModal();
}
$("d-close").onclick = () => $("detail").close();
$("d-resolve").onclick = async () => {
  try {
    await api("/findings/" + current.finding_id + "/resolve", { method: "POST", body: JSON.stringify({ note: $("d-note").value }) });
    $("d-note").value = ""; $("detail").close(); refresh();
  } catch (err) { $("d-meta").textContent = err.message; }
};

$("scan").onclick = async () => {
  $("scan").disabled = true;
  try {
    const r = await api("/scans", { method: "POST", body: "{}" });
    $("scan-status").textContent = "Scan queued (" + r.scan_id.slice(-6) + ")";
  } catch (err) { $("scan-status").textContent = err.message; $("scan").disabled = !isAdmin(); }
};
["f-status", "f-sev"].forEach((id) => $(id).addEventListener("change", refresh));

// ---------- live updates (WebSocket) ----------
function setLive(on) { const l = $("live"); l.className = "live " + (on ? "on" : "off"); l.textContent = on ? "● live" : "● offline"; }

function feed(text) {
  const ul = $("feed");
  ul.prepend(el("li", { textContent: new Date().toLocaleTimeString() + "  " + text }));
  while (ul.children.length > 40) ul.lastChild.remove();
}

function connectWs() {
  if (!token) return;
  ws = new WebSocket(C.wsUrl + "?token=" + encodeURIComponent(token));
  ws.onopen = () => { setLive(true); pingTimer = setInterval(() => ws.readyState === 1 && ws.send("ping"), 240000); };
  ws.onclose = () => { setLive(false); clearInterval(pingTimer); wsTimer = setTimeout(connectWs, 5000); };
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === "scan.started") feed("Scan started");
    else if (m.type === "finding.created") feed("New " + m.finding.severity + ": " + m.finding.title + " (" + m.finding.resource + ")");
    else if (m.type === "scan.completed") { feed("Scan finished. Score " + m.summary.score); $("scan-status").textContent = "Scan finished."; $("scan").disabled = !isAdmin(); refresh(); }
    else if (m.type === "scan.failed") { feed("Scan failed"); $("scan-status").textContent = "Scan failed."; $("scan").disabled = !isAdmin(); refresh(); }
  };
}

// resume after a page refresh
(async () => {
  token = store.get("cg_token");
  if (token) { try { await boot(); } catch { signOut(); } }
})();
