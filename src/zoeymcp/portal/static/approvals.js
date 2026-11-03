// The Approvals queue (M8 design H.1-H.4): the calls the vault holds, and the gateway's prompts
// relayed to it, waiting for the operator, oldest first, and the ones decided recently with how
// each went; the nav entry's count; and Home's approvals item. Like app.js it holds no decision:
// the vault sends every row and every sentence, each string shown through textContent, and the
// composed text whole in a pre (its lines from the vault, nothing cut). Approve is the vault's
// approval.decide action, bound to the hold and the digest of the text shown, one passkey for one
// call; Deny needs the session and the same digest, and sends nothing (Q14 (a)). There is no
// control that decides more than one. The page asks for its lists every 5 s while it is open and
// for the count every 10 s while signed in, on routes that don't move the session's idle clock
// (MISS-8); a countdown is the page's own, from the absolute deadline the vault sends. It uses
// app.js's API, step-up and guard() (window.zoeyPortal), and app.js calls its Home hook
// (window.zoeyApprovals) as it draws Home. In managed mode (M8 design A.4, G-5) review.js calls
// its hooks for Hold in the vault: on a server row's approve tools, a policy.save the vault
// plans as a narrowing, and Turn off vault approval, tool.vault_approval_off, one passkey for one
// tool, or for every writer of a connector a toolkit writes through (A.2 row 4); and a box on each
// tool of a review, which drift.js's Save sends as held. With no out-of-band approver the hold
// controls are disabled, with the line that says why.
"use strict";

(function () {
  const { api, fill, visit, afterFailure, button, prepare, closeConfirm, on } = window.zoeyPortal;

  const LISTS_EVERY = 5000;
  const COUNT_EVERY = 10000;
  // Home's item's one action (attention.approvals_item's kind).
  const ACTION_TEXT = { approvals: "Open the queue" };
  const RELAY = "relay";
  const NONE_WAITING = "Nothing waits for your approval.";
  const NONE_DECIDED = "Nothing was decided here since the vault started.";
  const GONE = "That approval no longer waits: Decided recently says how it went.";
  const APPROVED = "Approved: the vault runs that one call now, exactly as shown.";
  const DENIED = "Denied: nothing was sent.";
  const NO_APPROVER = "Set up an approver first (Telegram or the Approvals queue): a host step, " +
    "operations.md \u00a736.2";
  const HOLD = "Hold in the vault";
  const HOLD_OFF = "Turn off vault approval";
  const HELD_SAVED = "Saved: the vault holds those calls now and asks you on your approvers.";
  const OFF_SAVED = "Saved: the gateway asks for those calls again; any waiting were withdrawn.";

  // The hold opened: its ID and the digest of the text shown, which a decision is bound to.
  let open = null;
  // A request of the page's own timers in flight: the next tick skips (one at a time).
  let asking = false;

  function $(id) {
    return document.getElementById(id);
  }

  // An element with its text, and its class if any (review.js's make()).
  function make(tag, text, className) {
    const element = document.createElement(tag);
    element.textContent = text === undefined ? "" : text;
    element.className = className || "";
    return element;
  }

  // The bar shows only for a full session: the timers ask nothing before it does.
  function signedIn() {
    return !$("bar").hidden;
  }

  // The page's own countdown to the vault's absolute deadline (H.1).
  function left(deadline) {
    const minutes = Math.max(0, Math.ceil((deadline * 1000 - Date.now()) / 60000));
    return minutes + " min left";
  }

  function named(row) {
    return row.ref + ": " + row.server_shown + " -> " + row.tool_shown;
  }

  function waitingText(row) {
    const client = row.client_shown === null ? "not reported" : row.client_shown;
    return named(row) + ". " + row.how_shown + "; client " + client + " (as the gateway " +
      "reports it); asked " + row.asked_shown + "; answer by " + row.deadline_shown + " (" +
      left(row.deadline) + "); on " + row.surfaces.join(" and ") +
      (row.telegram_shown === null ? "" : "; " + row.telegram_shown) + ".";
  }

  function rows(list, found, empty, draw) {
    list.replaceChildren();
    for (const row of found) {
      list.append(draw(row));
    }
    if (found.length === 0) {
      list.append(make("li", empty));
    }
  }

  // --- the lists (H.1) ------------------------------------------------------------------------

  async function lists() {
    const answer = await api("GET", "/api/approvals");
    $("approvals-off").hidden = answer.enabled;
    $("approvals-notice").textContent = answer.notice === null ? "" : answer.notice;
    $("approvals-notice").hidden = answer.notice === null;
    rows($("approvals-waiting"), answer.waiting, NONE_WAITING, (row) => {
      const entry = make("li", waitingText(row) + " ");
      entry.append(button("Open", () => openHold(row.approval)));
      return entry;
    });
    rows($("approvals-decided"), answer.decided, NONE_DECIDED,
      (row) => make("li", named(row) + ": " + row.outcome_shown + "."));
    if (open !== null && !answer.waiting.some((row) => row.approval === open.approval)) {
      closeHold();
      $("status").textContent = GONE;
    }
    count(answer.waiting.length);
  }

  async function showQueue() {
    closeHold();
    await visit("approvals", lists);
  }

  // One hold, opened: the composed text whole, as the vault split it into lines (H.1).
  async function openHold(approval) {
    let shown;
    try {
      shown = await api("GET", fill("/api/approvals/{approval}", { approval: approval }));
    } catch (error) {
      afterFailure(error);
      return lists().catch(afterFailure);
    }
    open = { approval: shown.approval, text_sha256: shown.text_sha256 };
    $("approvals-open-title").textContent = "Approval request " + named(shown);
    $("approvals-open-how").textContent = waitingText(shown);
    $("approvals-relayed").hidden = shown.kind !== RELAY;
    $("approvals-text").textContent =
      shown.text_lines.map((line) => line.join("")).join("\n");
    $("approvals-open").hidden = false;
  }

  function closeHold() {
    open = null;
    $("approvals-open").hidden = true;
    $("approvals-text").textContent = "";
  }

  // Approve (H.3): the vault's plan is the whole text again and one sentence, before the passkey.
  async function approve() {
    const held = open;
    if (held === null) {
      return;
    }
    await prepare("approval.decide",
      { approval: held.approval, text_sha256: held.text_sha256, decision: "approve" },
      async () => {
        closeConfirm();
        closeHold();
        await lists();
        $("status").textContent = APPROVED;
      });
  }

  // Deny (Q14 (a)): the session and the digest of the text shown; nothing is sent.
  async function deny() {
    const held = open;
    if (held === null) {
      return;
    }
    try {
      await api("POST", fill("/api/approvals/{approval}/deny", { approval: held.approval }),
        { text_sha256: held.text_sha256 });
      closeHold();
      await lists();
      $("status").textContent = DENIED;
    } catch (error) {
      afterFailure(error);
    }
  }

  // --- the count, and Home's item ---------------------------------------------------------------

  function count(waiting) {
    $("nav-approvals").textContent = waiting ? "Approvals (" + waiting + ")" : "Approvals";
  }

  async function badge() {
    count((await api("GET", "/api/approvals/count")).count);
  }

  // Home's approvals item (CR-11): the vault's own words, with or without the gateway's report;
  // drift.js shows the block by the same answer's rule.
  async function home() {
    const answer = await api("GET", "/api/attention");
    const list = $("attention-approvals");
    list.replaceChildren();
    if (answer.approvals !== null) {
      const entry = make("li", answer.approvals.text_shown + ". ");
      entry.append(button(ACTION_TEXT[answer.approvals.action.kind], showQueue));
      list.append(entry);
    }
    await badge();
  }

  // A timer's ask: one at a time, and only signed in. Only a session that ended is said (the
  // page goes back to login); anything else waits for the next tick.
  async function quietly(work) {
    if (asking || !signedIn()) {
      return;
    }
    asking = true;
    try {
      await work();
    } catch (error) {
      if (error.reason === "no_session") {
        afterFailure(error);
      }
    } finally {
      asking = false;
    }
  }

  function tickLists() {
    if (!$("approvals").hidden) {
      quietly(lists);
    }
  }

  function tickCount() {
    quietly(badge);
  }

  // Hold in the vault, or Turn off vault approval, on a managed server row (A.4): per approve
  // tool, or per connector a toolkit writes through; holding is disabled with no approver.
  function servers(list, rows) {
    rows.forEach((listed, index) => {
      if (!("vault_approval" in listed)) {
        return; // declarative, or an onboarding's row
      }
      const controls = listed.connectors.length ? listed.connectors.map((name) => holdButton(
        listed, { connector: name }, "connector " + name)) : listed.approve.map((named) =>
        holdButton(listed, { server: listed.server, tool: named.name }, named.name_shown));
      list.children[index].append(...controls);
      if (controls.length && !listed.approver) {
        list.children[index].append(make("p", NO_APPROVER));
      }
    });
  }

  function holdButton(listed, data, shown) {
    const held = data.tool ? listed.vault_approval.includes(data.tool) :
      listed.vault_approval.length > 0;
    const control = button((held ? HOLD_OFF : HOLD) + ": " + shown, () => holdSaved(held, data));
    control.disabled = !held && !listed.approver;
    return control;
  }

  // The step-up for one button: its kind and the form its data takes, each a literal.
  async function holdSaved(held, data) {
    const base = (await api("GET", "/api/session")).revision;
    const done = () => {
      closeConfirm();
      $("status").textContent = held ? OFF_SAVED : HELD_SAVED;
      window.zoeyDrift.review();
    };
    if (held && data.connector) {
      await prepare("tool.vault_approval_off", { base: base, connector: data.connector }, done);
    } else if (held) {
      await prepare("tool.vault_approval_off", { base: base, server: data.server,
        tool: data.tool }, done);
    } else if (data.connector) {
      await prepare("policy.save", { base: base, connector: data.connector }, done);
    } else {
      await prepare("policy.save", { base: base, server: data.server, tool: data.tool }, done);
    }
  }

  // review.js's hook once a managed review is drawn: Hold in the vault on each tool's row, ticked
  // where the vault holds it. Unticking one is a save the vault refuses (turning it off is its
  // own step, on the server's row); with no approver an unticked box is disabled.
  function review(held, view) {
    if (!("vault_approval" in view)) {
      return;
    }
    for (const entry of held.entries.filter((each) => each.tool.kind === "tool" && each.box)) {
      entry.hold = Object.assign(document.createElement("input"), { type: "checkbox" });
      entry.hold.checked = view.vault_approval.includes(entry.tool.name);
      entry.hold.disabled = !entry.hold.checked && !view.approver;
      const label = make("label", "", "include");
      label.append(entry.hold, " " + HOLD + " (approve only)");
      entry.item.append(label);
    }
    if (!view.approver) {
      $("review-drift").append(make("p", NO_APPROVER));
    }
  }

  // What Save sends as held (drift.js's save): each ticked box of an included approve tool; none
  // on a review drawn without boxes, so the vault keeps the policy's own.
  function heldNames(held) {
    const boxed = held.entries.filter((entry) => entry.hold);
    return boxed.length ? boxed.filter((entry) => entry.hold.checked && entry.box.checked &&
      entry.choice.value === "approve").map((entry) => entry.tool.name) : undefined;
  }

  on("nav-approvals", showQueue);
  on("approvals-approve", approve);
  on("approvals-deny", deny);
  on("approvals-close", closeHold);
  setInterval(tickLists, LISTS_EVERY);
  setInterval(tickCount, COUNT_EVERY);
  window.zoeyApprovals = Object.freeze({ home: home, servers: servers, review: review,
    held: heldNames });
})();
