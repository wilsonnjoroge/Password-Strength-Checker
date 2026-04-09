/* ── Refs ─────────────────────────────────────────────────────────────────── */
const input       = document.getElementById("passwordInput");
const toggleBtn   = document.getElementById("toggleBtn");
const copyBtn     = document.getElementById("copyBtn");
const eyeOpen     = document.getElementById("eyeOpen");
const eyeClosed   = document.getElementById("eyeClosed");
const meterBar    = document.getElementById("meterBar");
const badge       = document.getElementById("resultBadge");
const statsRow    = document.getElementById("statsRow");
const statEntropy = document.getElementById("statEntropy");
const statCrack   = document.getElementById("statCrack");
const pwnedStat   = document.getElementById("pwnedStat");
const statPwned   = document.getElementById("statPwned");
const checklist   = document.querySelectorAll(".checklist li");
const tipsBox     = document.getElementById("tipsBox");
const tipsList    = document.getElementById("tipsList");
const clearBtn    = document.getElementById("clearHistoryBtn");

/* Meter width % per score level */
const METER_MAP = {
  "very-weak":   "15%",
  "weak":        "30%",
  "medium":      "58%",
  "strong":      "80%",
  "very-strong": "100%",
};

/* ── Show/hide toggle ─────────────────────────────────────────────────────── */
toggleBtn?.addEventListener("click", () => {
  const hidden = input.type === "password";
  input.type = hidden ? "text" : "password";
  eyeOpen.style.display  = hidden ? "none"  : "";
  eyeClosed.style.display = hidden ? ""     : "none";
  input.focus();
});

/* ── Copy ─────────────────────────────────────────────────────────────────── */
copyBtn?.addEventListener("click", () => {
  if (!input.value) return;
  navigator.clipboard.writeText(input.value).then(() => {
    copyBtn.title = "Copied!";
    setTimeout(() => (copyBtn.title = "Copy password"), 1500);
  });
});

/* ── Clear history ────────────────────────────────────────────────────────── */
clearBtn?.addEventListener("click", () => {
  fetch("/clear-history", { method: "POST" }).then(() => {
    document.querySelector(".history-wrap")?.remove();
  });
});

/* ── Debounce helper ──────────────────────────────────────────────────────── */
function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

/* ── Update UI ────────────────────────────────────────────────────────────── */
function applyResult(data) {
  const cls = data.color_class;

  /* Badge */
  badge.className = `result-badge ${cls}`;
  badge.textContent = `Strength: ${data.label}`;
  badge.classList.remove("hidden");

  /* Meter */
  meterBar.style.width = METER_MAP[cls] || "0%";
  meterBar.className = `meter-bar ${cls}`;

  /* Stats */
  statEntropy.textContent = `${data.entropy} bits`;
  statCrack.textContent   = data.crack_time;
  statsRow.classList.remove("hidden");

  /* Breach count */
  if (data.pwned_count > 0) {
    statPwned.textContent = `${data.pwned_count.toLocaleString()} breaches`;
    pwnedStat.style.display = "";
  } else {
    pwnedStat.style.display = "none";
  }

  /* Criteria checklist */
  checklist.forEach(li => {
    const key = li.dataset.key;
    const pass = data.criteria?.[key];
    li.classList.toggle("pass", !!pass);
    li.classList.toggle("fail", !pass);
  });

  /* Tips */
  if (data.tips?.length) {
    tipsList.innerHTML = data.tips.map(t => `<li>${t}</li>`).join("");
    tipsBox.classList.remove("hidden");
  } else {
    tipsBox.classList.add("hidden");
  }
}

function resetUI() {
  badge.classList.add("hidden");
  statsRow.classList.add("hidden");
  tipsBox.classList.add("hidden");
  meterBar.style.width = "0%";
  meterBar.className = "meter-bar";
  checklist.forEach(li => li.classList.remove("pass", "fail"));
}

/* ── Main check ───────────────────────────────────────────────────────────── */
const doCheck = debounce(async (password) => {
  if (!password) { resetUI(); return; }

  try {
    const res  = await fetch("/check", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ password }),
    });
    const data = await res.json();
    applyResult(data);
  } catch (err) {
    console.error("Check failed:", err);
  }
}, 400);          /* 400 ms debounce — fast but won't hammer HIBP */

input?.addEventListener("input", e => doCheck(e.target.value));