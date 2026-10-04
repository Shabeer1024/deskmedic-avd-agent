/* Presentation-only enhancements.
 *
 * app.js owns every decision and every API call. This file adds nothing to the
 * workflow - it only reflects state the backend already returned. Keeping the
 * two separate means the console's safety properties are unchanged by anything
 * here: no fetch, no approval logic, no risk evaluation.
 */
"use strict";

(() => {
  const byId = (id) => document.getElementById(id);

  /* ---------------------------------------------------- character counter */
  const description = byId("description");
  const counter = byId("char-count");
  if (description && counter) {
    const sync = () => {
      const max = description.getAttribute("maxlength") || 1000;
      counter.textContent = `${description.value.length}/${max}`;
    };
    description.addEventListener("input", sync);
    sync();
  }

  /* ------------------------------------------------- right-rail examples */
  // The rail's issue buttons reuse the same data-example contract app.js
  // already binds on the intake chips, so one click path, one source of truth.
  document.querySelectorAll(".issue-list button[data-example]").forEach((button) => {
    button.addEventListener("click", () => {
      const chip = document.querySelector(`.examples .link[data-example="${button.dataset.example}"]`);
      if (chip) chip.click();
      byId("intake")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  /* ------------------------------------------------------- ask the agent */
  byId("ask-agent")?.addEventListener("click", () => {
    byId("intake")?.scrollIntoView({ behavior: "smooth", block: "start" });
    description?.focus();
  });

  /* --------------------------------------------------------- nav + steps */
  const navItems = [...document.querySelectorAll(".nav-item")];
  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      navItems.forEach((n) => n.classList.remove("is-active"));
      item.classList.add("is-active");
    });
  });

  const STEP_ORDER = ["describe", "diagnose", "approve", "remediate", "verify"];

  /** Reflect the incident's real state onto the stepper. Derived from what the
   *  backend rendered, never from anything this file decides. */
  function syncStepper() {
    const result = byId("result");
    if (!result || result.hidden) return;

    let reached = "diagnose";
    if (!byId("remediation-card")?.hidden) reached = "approve";
    if (!byId("execution-card")?.hidden) reached = "remediate";
    if (!byId("verification-card")?.hidden) reached = "verify";

    const index = STEP_ORDER.indexOf(reached);
    document.querySelectorAll(".stepper li").forEach((li, i) => {
      li.classList.toggle("is-done", i < index);
      li.classList.toggle("is-current", i === index);
    });

    document.querySelectorAll(".pipe-step").forEach((step, i) => {
      step.classList.toggle("is-active", i === index);
    });
  }

  // The renderer toggles [hidden] on those cards; observing the attribute keeps
  // the stepper honest without app.js needing to know this file exists.
  const result = byId("result");
  if (result) {
    new MutationObserver(syncStepper).observe(result, {
      attributes: true,
      attributeFilter: ["hidden"],
      subtree: true,
    });
  }

  /* -------------------------------------------- header identity + config */
  // Reads the same two endpoints app.js already calls. Read-only, and failure
  // is silent: the badges app.js renders remain the authoritative display.
  async function decorateHeader() {
    try {
      const [meRes, capsRes] = await Promise.all([fetch("/api/me"), fetch("/api/capabilities")]);
      if (!meRes.ok || !capsRes.ok) return;
      const me = await meRes.json();
      const caps = await capsRes.json();

      const upn = me.upn || "";
      const label = upn.split("@")[0].replace(/[._-]+/g, " ").trim();
      const initials = label
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((part) => part[0].toUpperCase())
        .join("") || "··";

      const nameEl = byId("user-name");
      const initialsEl = byId("user-initials");
      if (nameEl) nameEl.textContent = label.replace(/\b\w/g, (c) => c.toUpperCase()) || upn;
      if (initialsEl) initialsEl.textContent = initials;

      const kv = byId("capability-kv");
      if (kv) {
        const rows = [
          ["Mode", caps.mode],
          ["Diagnostics", `${caps.diagnostic_tools?.length ?? 0} read-only tools`],
          ["Remediation", caps.remediation_enabled ? "enabled" : "disabled"],
          ["Blocked risk", (caps.blocked_risk_levels || []).join(", ") || "none"],
          ["Signed in as", upn],
          ["Role", (me.roles || []).join(", ") || "—"],
        ];
        kv.replaceChildren();
        for (const [k, v] of rows) {
          const dt = document.createElement("dt");
          dt.textContent = k;
          const dd = document.createElement("dd");
          dd.textContent = v;
          kv.append(dt, dd);
        }
      }
    } catch {
      /* header decoration is cosmetic - never block the console on it */
    }
  }

  decorateHeader();

  /* ------------------------------------------------- estate discovery ---- */
  // Populates the host pool / session host / resource group pickers from what
  // the subscription actually contains, so an engineer selects a real target
  // instead of typing a name that may not exist here. Selecting a host pool
  // narrows the session host list to that pool and fills in its resource group.
  //
  // Everything stays free-text: if discovery fails or returns nothing, the
  // inputs behave exactly as before and the console is still usable.
  let ESTATE = null;

  const fillList = (datalistId, values) => {
    const list = byId(datalistId);
    if (!list) return;
    list.replaceChildren();
    for (const value of values) {
      const option = document.createElement("option");
      option.value = value.value ?? value;
      if (value.label) option.label = value.label;
      list.appendChild(option);
    }
  };

  const sessionHostsFor = (poolName) => {
    if (!ESTATE) return [];
    const pools = poolName
      ? ESTATE.host_pools.filter((p) => p.name === poolName)
      : ESTATE.host_pools;
    return pools.flatMap((p) =>
      (p.session_hosts || []).map((h) => ({ value: h.name, label: `${h.name} — ${h.status}` })),
    );
  };

  function applyPoolSelection() {
    const poolInput = byId("host_pool");
    const rgInput = byId("resource_group");
    if (!poolInput || !ESTATE) return;

    const pool = ESTATE.host_pools.find((p) => p.name === poolInput.value.trim());
    // Only auto-fill the resource group when it is empty or was itself
    // auto-filled - never overwrite something typed deliberately.
    if (pool && rgInput && (!rgInput.value.trim() || rgInput.dataset.auto === "1")) {
      rgInput.value = pool.resource_group;
      rgInput.dataset.auto = "1";
    }
    fillList("dl-session-hosts", sessionHostsFor(pool ? pool.name : ""));
  }

  async function loadEstate() {
    const note = byId("discovery-note");
    try {
      const response = await fetch("/api/estate");
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      ESTATE = await response.json();

      const pools = ESTATE.host_pools || [];
      fillList("dl-host-pools", pools.map((p) => ({ value: p.name, label: `${p.name} — ${p.resource_group}` })));
      fillList("dl-resource-groups", [...new Set(pools.map((p) => p.resource_group))]);
      fillList("dl-session-hosts", sessionHostsFor(""));
      if (ESTATE.subscription_id) fillList("dl-subscriptions", [ESTATE.subscription_id]);

      const hostCount = pools.reduce((n, p) => n + (p.session_hosts || []).length, 0);
      if (note) {
        if (pools.length) {
          note.textContent = `Discovered ${pools.length} host pool(s) and ${hostCount} session host(s) in this subscription.`;
          note.className = "discovery ok";
        } else {
          note.textContent =
            ESTATE.error
              ? `Discovery unavailable (${ESTATE.error}). Type names by hand.`
              : "No host pools discovered in this subscription. Type names by hand.";
          note.className = "discovery warn";
        }
        note.hidden = false;
      }

      // If exactly one pool exists, preselect it - the common case in a lab.
      const poolInput = byId("host_pool");
      if (poolInput && pools.length === 1 && !poolInput.value.trim()) {
        poolInput.value = pools[0].name;
      }
      applyPoolSelection();
    } catch (error) {
      if (note) {
        note.textContent = `Estate discovery unavailable (${error.message}). Type names by hand.`;
        note.className = "discovery warn";
        note.hidden = false;
      }
    }
  }

  byId("host_pool")?.addEventListener("input", applyPoolSelection);
  byId("host_pool")?.addEventListener("change", applyPoolSelection);
  byId("resource_group")?.addEventListener("input", (e) => {
    // Once touched by hand, stop auto-filling it.
    e.target.dataset.auto = "";
  });

  loadEstate();

  /* ------------------------------------------------------- mode switch ---- */
  // Read-only  -> console presents no identity -> backend refuses every write.
  // Troubleshoot -> console presents an approver -> approve + execute allowed.
  //
  // This never overrides REMEDIATION_ENABLED. That kill switch lives in the
  // backend config precisely so a browser cannot turn remediation on, and the
  // switch is disabled here when it is off, with the reason shown.
  const MODE_KEY = "avd-agent-mode";
  const switcher = byId("mode-switch");

  function setMode(mode, { persist = true } = {}) {
    document.body.dataset.mode = mode;
    switcher?.querySelectorAll(".mode-opt").forEach((button) => {
      const on = button.dataset.mode === mode;
      button.classList.toggle("is-on", on);
      button.setAttribute("aria-pressed", String(on));
    });
    if (persist) {
      try { localStorage.setItem(MODE_KEY, mode); } catch { /* private window */ }
    }
    // Badges and the capability panel describe the *current* identity, so both
    // have to be re-read whenever it changes.
    if (typeof loadEnvironment === "function") loadEnvironment();
    decorateHeader();
  }

  switcher?.addEventListener("click", (event) => {
    const button = event.target.closest(".mode-opt");
    if (!button || switcher.dataset.locked === "1") return;
    setMode(button.dataset.mode);
  });

  let stored = "readonly";
  try { stored = localStorage.getItem(MODE_KEY) || "readonly"; } catch { /* ignore */ }
  document.body.dataset.mode = stored;
  setMode(stored, { persist: false });

  // Reflect the backend kill switch: if remediation is disabled server-side,
  // Troubleshoot cannot do anything, so say so rather than letting it look live.
  (async () => {
    try {
      const response = await fetch("/api/capabilities");
      if (!response.ok) return;
      const caps = await response.json();
      if (caps.remediation_enabled) return;

      switcher?.setAttribute("data-locked", "1");
      switcher?.setAttribute(
        "title",
        "Remediation is disabled in this environment (REMEDIATION_ENABLED=false). " +
          "Set it to true in .env and restart the agent to allow execution.",
      );
      switcher?.classList.add("is-locked");
      if (document.body.dataset.mode === "troubleshoot") setMode("readonly");
    } catch { /* cosmetic only */ }
  })();
})();
