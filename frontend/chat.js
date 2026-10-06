/* Conversational front end.
 *
 * This file talks to /api/chat and renders the conversation. It makes exactly
 * one kind of state-changing call - the approval, and only when a human clicks
 * the button. The model's reply can *propose* a fix; it can never approve one,
 * so there is no path from "the agent said so" to a change on a session host.
 */
"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const log = byId("chat-log");
  const form = byId("chat-form");
  const input = byId("chat-text");
  const send = byId("chat-send");
  const activity = byId("activity-log");
  const dot = byId("activity-dot");

  if (!form || !log) return;

  /** Full conversation, replayed to the backend each turn so the agent has
   *  context. Kept client-side: the server holds no chat session. */
  const messages = [];
  let incidentId = null;

  /* ------------------------------------------------------------- rendering */
  const node = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  function bubble(role, text) {
    const wrap = node("div", `msg ${role}`);
    wrap.appendChild(node("span", "who", role === "user" ? "You" : "Agent"));
    const body = node("div", "bubble");
    // textContent, never innerHTML: a reply is untrusted content and must not
    // be able to inject markup into the console.
    body.appendChild(node("p", null, text));
    wrap.appendChild(body);
    log.appendChild(wrap);
    log.scrollTop = log.scrollHeight;
    return body;
  }

  function setBusy(busy, label) {
    send.disabled = busy;
    input.disabled = busy;
    send.textContent = busy ? "Working…" : "Send";
    dot?.classList.toggle("is-busy", busy);
    if (busy && label) pushActivity({ tool: label, status: "running", summary: "in progress…" });
  }

  function pushActivity(entry) {
    activity.querySelector(".idle")?.remove();
    const li = node("li", `act ${entry.status || ""}`);
    li.appendChild(node("span", "act-tool", entry.tool));
    li.appendChild(node("span", "act-sum", entry.summary || ""));
    activity.appendChild(li);
    activity.scrollTop = activity.scrollHeight;
    return li;
  }

  function resetActivity() {
    activity.replaceChildren();
    activity.appendChild(node("li", "idle", "Nothing running."));
    setNow("");
  }

  /* --------------------------------------------------------- live progress */
  // A "Now:" line above the activity list shows the step in flight.
  const now = (() => {
    let el = byId("activity-now");
    if (!el) {
      el = node("div", "act-now");
      el.id = "activity-now";
      activity.parentNode.insertBefore(el, activity);
    }
    return el;
  })();

  function setNow(text, status) {
    now.textContent = text ? `Now: ${text}` : "";
    now.className = `act-now ${status || "running"}`;
    now.hidden = !text;
  }

  /* ------------------------------------------------------------- stepper */
  // Describe -> Diagnose -> Approve -> Fix -> Verify, driven by the live
  // stages the server streams, so the bar follows the agent in real time.
  const STEPS = ["describe", "diagnose", "approve", "remediate", "verify"];

  function setStep(step, { done = false, failed = false } = {}) {
    const index = STEPS.indexOf(step);
    document.querySelectorAll(".stepper li").forEach((li, i) => {
      li.classList.toggle("is-done", i < index || (done && i === index));
      li.classList.toggle("is-current", i === index && !done);
      li.classList.toggle("is-failed", failed && i === index);
    });
    document.querySelectorAll(".pipe-step").forEach((el, i) => el.classList.toggle("is-active", i === index));
  }

  function stepFromStage(text, status) {
    const t = text.toLowerCase();
    if (t.startsWith("understanding") || t.startsWith("issue type") || t.startsWith("running")
        || t.startsWith("finding")) return setStep("diagnose");
    if (t.startsWith("no root cause")) return setStep("diagnose", { done: true });
    if (t.startsWith("root cause")) return setStep("diagnose", { done: true });
    if (t.startsWith("fix ready")) return setStep("approve");
    if (t.startsWith("approved by") || t.startsWith("automation job")) return setStep("remediate");
    if (t.includes("verifying") || t.includes("checking current state")) return setStep("verify");
    if (t.startsWith("resolved")) return setStep("verify", { done: true });
    if (t.startsWith("not fixed")) return setStep("verify", { failed: true });
    return undefined;
  }

  const newChannel = () =>
    (crypto.randomUUID ? crypto.randomUUID() : `ch-${Date.now()}-${Math.random().toString(16).slice(2)}`);

  /** Subscribe to the server's live progress for one request. Rows for the
   *  same tool call are updated in place: "running" becomes its result. */
  function watch(channel) {
    const rows = new Map();
    let count = 0;
    let sawStage = false;
    let source = null;
    try {
      source = new EventSource(`/api/progress/${channel}`);
    } catch {
      return { close() {}, count: () => 0 };
    }
    source.onmessage = (message) => {
      let event;
      try { event = JSON.parse(message.data); } catch { return; }
      if (event.kind === "keepalive") return;
      if (event.kind === "done") {
        source.close();
        setNow("");
        if (!sawStage) setStep("describe");  // a plain answer, no investigation
        return;
      }
      count += 1;
      if (event.kind === "stage") {
        sawStage = true;
        stepFromStage(event.text, event.status);
        setNow(event.text, event.status);
        pushActivity({ tool: "▸ " + event.text, status: event.status, summary: "" });
        return;
      }
      if (event.kind === "job") {
        stepFromStage(event.text, event.status);
        setNow(event.text, event.status);
        pushActivity({ tool: event.text, status: event.status, summary: "" });
        return;
      }
      if (event.kind === "tool") {
        const summary = event.status === "running"
          ? `checking… ${event.summary || ""}`
          : `${event.summary || ""}${event.seconds !== undefined ? `  (${event.seconds}s)` : ""}`;
        const existing = rows.get(event.key);
        if (existing) {
          existing.className = `act ${event.status}`;
          existing.querySelector(".act-sum").textContent = summary;
        } else {
          rows.set(event.key, pushActivity({ tool: event.text, status: event.status, summary }));
        }
        if (event.status === "running") setNow(`checking ${event.text}`);
      }
    };
    source.onerror = () => { /* the request result still renders normally */ };
    return { close: () => source && source.close(), count: () => count };
  }

  /* ---------------------------------------------------- approval affordance */
  // Rendered only when the BACKEND says a plan is awaiting approval. The button
  // calls the same /approval endpoint the form uses, with the same permission
  // check behind it.
  function renderApproval(container, incident) {
    const plan = incident?.remediation;
    if (!plan) return;

    const card = node("div", "approve-card");
    card.appendChild(node("strong", null, plan.title || "Proposed fix"));
    card.appendChild(node("p", "approve-why", plan.rationale || ""));

    const meta = node("dl", "kv");
    [
      ["Action", plan.action_id],
      ["Runbook", plan.script_name],
      ["Risk", plan.risk],
      ["Target", `${incident.target?.resource_group || ""}/${incident.target?.resource_name || ""}`],
      ["Impact", plan.expected_impact],
    ].forEach(([k, v]) => {
      if (!v) return;
      meta.appendChild(node("dt", null, k));
      meta.appendChild(node("dd", null, String(v)));
    });
    card.appendChild(meta);

    const details = node("details", "script-peek");
    details.appendChild(node("summary", null, "Show the PowerShell that will run"));
    details.appendChild(node("pre", "code", plan.script || ""));
    card.appendChild(details);

    const noteLabel = node("label", "approve-note");
    noteLabel.appendChild(node("span", "hint", "Approver note (recorded in the audit trail)"));
    const note = node("input");
    note.placeholder = "e.g. approved on ticket INC12345";
    noteLabel.appendChild(note);
    card.appendChild(noteLabel);

    const actions = node("div", "actions");
    const approve = node("button", "primary", "Approve & Execute");
    const reject = node("button", "ghost", "Reject");
    actions.append(approve, reject);
    card.appendChild(actions);
    container.appendChild(card);
    log.scrollTop = log.scrollHeight;

    const decide = async (approved) => {
      approve.disabled = reject.disabled = true;
      approve.textContent = approved ? "Executing…" : "Rejecting…";
      const channel = newChannel();
      const live = watch(channel);
      dot?.classList.add("is-busy");
      try {
        const decision = await post(`/api/incidents/${incident.incident_id}/approval`, {
          plan_id: plan.plan_id,
          approved,
          note: note.value.trim(),
        }, channel);
        if (!approved) {
          bubble("agent", "Rejected. Nothing was changed.");
          card.remove();
          return;
        }
        pushActivity({ tool: "approval", status: "healthy", summary: "approved by you" });

        // Execution needs the single-use token the approval just issued - the
        // server refuses to run a plan without proof of a human decision.
        const token = decision && decision.approval && decision.approval.token;
        if (!token) throw new Error("the approval did not return a token, so nothing was run");
        const executed = await post(`/api/incidents/${incident.incident_id}/execute`, {
          plan_id: plan.plan_id,
          token,
        }, channel);
        renderExecution(executed, live.count() > 0);
      } catch (error) {
        bubble("agent", `That failed: ${error.message}`);
      } finally {
        card.remove();
        dot?.classList.remove("is-busy");
        setTimeout(() => live.close(), 1500);
      }
    };

    approve.addEventListener("click", () => decide(true));
    reject.addEventListener("click", () => decide(false));
  }

  function renderExecution(incident, streamed) {
    const execution = incident.execution;
    if (execution && !streamed) {
      pushActivity({
        tool: execution.script_name || "runbook",
        status: execution.succeeded ? "healthy" : "unhealthy",
        summary: execution.succeeded ? "completed" : execution.error || "failed",
      });
      (execution.output || []).forEach((line) =>
        pushActivity({ tool: "output", status: "info", summary: line }),
      );
    }

    const verification = incident.verification;
    if (verification && !streamed) {
      (verification.checks || []).forEach((check) =>
        pushActivity({
          tool: "verify",
          status: check.passed ? "healthy" : "unhealthy",
          summary: check.description,
        }),
      );
    }

    const ok = verification?.passed ?? execution?.succeeded;
    const seconds = execution && execution.duration_ms ? ` in ${Math.round(execution.duration_ms / 1000)}s` : "";
    bubble(
      "agent",
      ok
        ? `Done${seconds} — the fix ran and every post-check passed.`
        : `The fix did not complete: ${execution?.error || verification?.summary || "see the activity panel"}`,
    );
  }

  /* ------------------------------------------------------------------ http */

  /** Identity this panel presents. Defined here rather than borrowed from
   *  app.js so chat keeps working even if that file is stale in a cache - and
   *  so the two panels cannot drift apart on what "troubleshoot" means.
   *
   *  Local-development affordance only: behind Easy Auth, Azure sets these
   *  headers itself and discards anything the browser sends. */
  function identityHeaders() {
    if (document.body.dataset.mode !== "troubleshoot") return {};
    return {
      "X-MS-CLIENT-PRINCIPAL-NAME": document.body.dataset.approverUpn || "approver@local",
      "X-MS-CLIENT-PRINCIPAL-ROLES": "avd.approver",
    };
  }

  async function post(path, body, channel) {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...identityHeaders(),
        ...(channel ? { "X-Progress-Channel": channel } : {}),
      },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const d = payload.detail;
      const message = Array.isArray(d)
        ? d.map((e) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ")
        : d;
      throw new Error(message || `${response.status} ${response.statusText}`);
    }
    return payload;
  }

  /* ------------------------------------------------------------------ turn */
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;

    bubble("user", text);
    messages.push({ role: "user", content: text });
    input.value = "";
    resetActivity();
    setStep("diagnose");
    const channel = newChannel();
    const live = watch(channel);
    setBusy(true);
    setNow("thinking");

    try {
      const turn = await post("/api/chat", { messages, incident_id: incidentId }, channel);
      const streamed = live.count() > 0;

      if (!streamed) {
        resetActivity();
        (turn.activity || []).forEach(pushActivity);
      }

      if (turn.incident_id) incidentId = turn.incident_id;

      const body = bubble("agent", turn.reply || "");
      messages.push({ role: "assistant", content: turn.reply || "" });

      // An investigation returns the full evidence list; show it as work done.
      const incident = turn.incident;
      if (incident && !streamed) {
        (incident.steps || []).forEach((step) =>
          pushActivity({
            tool: step.tool,
            status: step.status,
            summary: step.summary || step.stage,
          }),
        );
      }

      if (turn.awaiting_approval && incident) renderApproval(body, incident);
    } catch (error) {
      bubble("agent", `Something went wrong: ${error.message}`);
    } finally {
      setBusy(false);
      setTimeout(() => live.close(), 1500);
    }
  });
})();
