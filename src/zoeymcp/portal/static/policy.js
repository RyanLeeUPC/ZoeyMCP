// The Policy page's managed half (M6 design H.1-H.4, M.1, M.4): the head's revision and the one
// the gateway runs, the host's export command, the history (50 revisions a page, one in
// quarantine a gap), a revision's diff from its parent, and Roll back to each kept revision but
// the head. Like app.js it holds no decision: the vault sends every row, each string shown
// through textContent, and a rollback is its policy.rollback action, which plans the target's
// content on the head the page showed and refuses anything wider before any prompt, or in the
// dialog at the confirm (G.5, G.7). The plan lists the store entries the rollback leaves unused
// first (G.7 row 7). Each connector's row has Pause or Resume and its limits (G.3), and Give to
// clients, which drift.js draws on the MCP servers page's server rows, is here (J14 step 5):
// both are saves of one thing, connector.limits and client.servers. It draws
// when the Policy page opens, beside app.js's view of the policy, through app.js's guard() (on()
// and button(), window.zoeyPortal), and words a next step as review.js does (window.zoeyReview).
"use strict";

(function () {
  const { api, fill, afterFailure, button, prepare, closeConfirm, on } = window.zoeyPortal;

  // What made a revision (H.1, J6): its kind (common/policy/plan.py's WriteKind), in words.
  const KIND_TEXT = {
    "policy.save": "a save",
    "tool.repin": "a re-pin",
    "tool.allow": "a move to allow",
    "client.servers": "servers given to a client",
    "connector.limits": "a connector's limits",
    "policy.rollback": "a rollback",
    "policy.import": "an import",
    "policy.seed": "the seed",
    "policy.resume": "a return to managed mode",
    "policy.reseed": "a reseed",
    "policy.acknowledge": "an acknowledgment",
  };
  // Which revision the gateway runs (K.1): the head's, another, or none reported yet.
  const GATEWAY_TEXT = {
    applied: "The gateway runs the head.",
    pending: "The gateway hasn't taken the head yet: it takes a new revision within seconds.",
    unknown: "The gateway hasn't reported its status since the vault started.",
  };
  const GAP = "in quarantine: it doesn't verify, so it can't be shown or rolled back to.";
  const NOT_RUNNING = " is saved but not running: send SIGHUP to the vault or restart it.";
  // A head that moved since the page showed it (Y8): the page is drawn again at the head now. A
  // history page of one says which revision the head is.
  const ONE = "?limit=1";
  const MOVED = "The policy moved to revision {now} since this page showed revision {head}: it " +
    "is drawn again, so press Roll back again to plan it on revision {now}.";
  const LIMITS_MOVED = "The policy moved to revision {now} since this page showed revision " +
    "{head}: it is drawn again, so press the connector's button again.";
  // A connector's row (G.3): whether it sends, and its limits, by the field each sets.
  const PAUSED = "paused: every send is refused.";
  const SENDING = "sending.";
  const LIMIT_TEXT = {
    max_per_day: "Sends a day",
    max_subject_chars: "Subject characters",
    max_body_chars: "Body characters",
  };
  const NO_CLIENTS = "The policy has no client: a client is added on the host (zoeymcp policy " +
    "export, edit, zoeymcp policy import).";

  // The next page's before (H.1), and what the last rollback's answer said, shown once drawn.
  let older = null;
  let said = "";

  function $(id) {
    return document.getElementById(id);
  }

  // An element with its text (review.js's make()).
  function make(tag, text) {
    const element = document.createElement(tag);
    element.textContent = text;
    return element;
  }

  // The Policy page (M.1): in managed mode the head, the revision the gateway runs, the export
  // command with the deployment's exec prefix and the history's first page; in declarative mode
  // nothing, app.js's view says it all. A view the vault refuses is app.js's to say.
  async function draw() {
    let view;
    try {
      view = await api("GET", "/api/policy");
    } catch (error) {
      return;
    }
    $("policy-managed").hidden = view.mode !== "managed";
    if (view.mode !== "managed") {
      return;
    }
    $("policy-saved").textContent = said;
    said = "";
    $("policy-head").textContent = "The head is revision " + view.revision + "." +
      (view.not_running === null ? "" : " Revision " + view.not_running + NOT_RUNNING);
    const gateway = view.gateway;
    $("policy-gateway").textContent = GATEWAY_TEXT[gateway.state] +
      (gateway.revision === null ? "" : " Its view is revision " + gateway.revision + "'s.");
    $("policy-export").textContent = window.zoeyReview.stepText(view.export, true) + ".";
    $("policy-connectors").replaceChildren(...view.connectors.map((each) =>
      connectorRow(each, view.revision)));
    $("policy-diff").hidden = true;
    await history();
  }

  // A connector's row (M.1, G.3): whether it sends, and its three limits, each in a field; Pause or
  // Resume, and Save limits with the fields' values, each connector.limits on the head the page
  // shows. Its recipients, host, port and sender are the host's (an import, COV-1).
  function connectorRow(connector, head) {
    const item = make("li", connector.name_shown + ": " + (connector.paused ? PAUSED : SENDING));
    const fields = Object.keys(LIMIT_TEXT).map((name) => {
      const field = document.createElement("input");
      field.type = "number";
      field.value = String(connector[name]);
      item.append(" " + LIMIT_TEXT[name] + " ", field);
      return field;
    });
    item.append(" ", button(connector.paused ? "Resume" : "Pause", () => limits(head, (done) =>
      prepare("connector.limits", { base: head, connector: connector.name,
        paused: !connector.paused }, done))), " ", button("Save limits", () => limits(head,
      (done) => prepare("connector.limits", { base: head, connector: connector.name,
        max_per_day: Number(fields[0].value), max_subject_chars: Number(fields[1].value),
        max_body_chars: Number(fields[2].value) }, done))));
    return item;
  }

  // Pause, Resume or Save limits (G.3): a head that moved since the page showed it is found
  // first and the page drawn again at it, as for Roll back; confirmed, the page is drawn again at
  // the new head, and so it is after a refused prepare.
  async function limits(head, ask) {
    const now = await api("GET", "/api/policy/revisions" + ONE).catch(afterFailure);
    if (now === undefined) {
      return;
    }
    if (now.head !== head) {
      said = LIMITS_MOVED.replace("{now}", now.head).replace("{head}", head);
      return draw();
    }
    await ask((done) => {
      closeConfirm();
      said = wrote(done);
      $("nav-policy").click();
    });
    if (!$("confirm").open) {
      await draw();
    }
  }

  // What a save's answer says: the new revision, and each step left, as review.js words them.
  function wrote(done) {
    return ["Revision " + done.revision + " written."].concat(done.next.map((step) =>
      window.zoeyReview.stepText(step, true) + ".")).join(" ");
  }

  // Give to clients (G.3, J14 step 5), drawn by drift.js under each server's row: a box per
  // client, ticked where it reaches the server at the revision the vault read them at, and Save,
  // planned on that revision, so a head that moved since is policy_moved, never a merge (G.10).
  async function give(server, block) {
    const found = await api("GET", "/api/servers").catch(afterFailure);
    if (found === undefined) {
      return;
    }
    block.replaceChildren(found.clients.length ? "" : NO_CLIENTS);
    const boxes = found.clients.map((client) => {
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = client.servers.includes(server);
      const label = make("label", " " + client.name_shown);
      label.prepend(box);
      block.append(label, " ");
      return { client: client, box: box };
    });
    block.append(button("Save", () => gave(server, block, boxes.filter((each) =>
      each.box.checked !== each.client.servers.includes(server)), found.revision)));
  }

  // client.servers changes one client's servers, sent whole (G.3), so each client whose box
  // changed is a save of its own, one passkey each, in turn; then the MCP servers page is drawn
  // again. A refused prepare (a head that moved since the boxes were drawn) draws them again at
  // the head now, so the next Save plans on it.
  async function gave(server, block, changed, base) {
    if (!changed.length) {
      return $("nav-servers").click();
    }
    const kept = changed[0].client.servers.filter((name) => name !== server);
    const servers = changed[0].box.checked ? kept.concat([server]) : kept;
    await prepare("client.servers", { base: base, client: changed[0].client.name,
      servers: servers }, (done) => {
      closeConfirm();
      $("status").textContent = wrote(done);
      return gave(server, block, changed.slice(1), done.revision);
    });
    if (!$("confirm").open) {
      await give(server, block);
    }
  }

  // A page of history (H.1), newest first: from the head, or below ``before`` for Older
  // revisions, which a page with more below it shows.
  async function history(before) {
    let page;
    try {
      page = await api("GET", "/api/policy/revisions" +
        (before === undefined ? "" : "?before=" + before));
    } catch (error) {
      return afterFailure(error);
    }
    const list = $("policy-history");
    if (before === undefined) {
      list.replaceChildren();
    }
    for (const entry of page.revisions) {
      list.append(revision(entry, page.head));
    }
    older = page.next;
    $("policy-older").hidden = older === null;
  }

  // One revision (J6): its number, who saved it and when, and what made it (a rollback's
  // target, an acknowledged restore's jump, the host's reason); Show the changes, and Roll back
  // to it unless it is the head. A rollback needs no diff: a revision whose parent is no longer
  // kept or is in quarantine, whose changes can't be shown, is still a target (D.8, H.3).
  function revision(entry, head) {
    if (entry.gap) {
      return make("li", "Revision " + entry.revision + ": " + GAP);
    }
    const words = [entry.saved_shown.charAt(0).toUpperCase() + entry.saved_shown.slice(1) +
      ": " + (KIND_TEXT[entry.kind] || entry.kind)];
    if (entry.target !== null) {
      words.push("the content of revision " + entry.target);
    }
    if (entry.jumped_from !== null) {
      words.push("after revision " + entry.jumped_from);
    }
    if (entry.revision === head) {
      words.push("the head");
    }
    const item = make("li", words.join(", ") + "." +
      (entry.reason_shown === null ? "" : " Reason: " + entry.reason_shown));
    item.append(" ", button("Show the changes", () => changes(entry.revision)));
    if (entry.revision !== head) {
      item.append(" ", button("Roll back to revision " + entry.revision,
        () => rollback(entry.revision, head)));
    }
    return item;
  }

  // A value as the policy view shows it: a string as it is, anything else as JSON.
  function value(shown) {
    return typeof shown === "string" ? shown : JSON.stringify(shown);
  }

  // A diff row (H.2): its path, what happened and whether it widens the policy; the values as the
  // policy view shows them. A hidden field, or one shown as names, sends only its marker (set,
  // changed or removed) as new and no old; recipients send both counts, old -> new.
  function row(change) {
    const marked = change.hidden && change.old === null;
    let values = value(change.new);
    if (change.op === "removed") {
      values = marked ? change.new : value(change.old);
    } else if (change.op === "changed" && !marked) {
      values = value(change.old) + " -> " + value(change.new);
    }
    return make("li", change.path_shown.join(".") + ": " + change.op + ", " + change.direction +
      ": " + values);
  }

  // A revision's diff from its parent (H.2), each change on its row; then Roll back to this,
  // unless it is the head.
  async function changes(number) {
    let answer;
    try {
      answer = await api("GET", fill("/api/policy/revisions/{revision}", { revision: number }));
    } catch (error) {
      return afterFailure(error);
    }
    const from = answer.against === null ? "an empty policy" : "revision " + answer.against;
    const count = answer.rows.length + (answer.rows.length === 1 ? " change" : " changes");
    $("policy-diff-title").textContent = "Revision " + answer.revision + ", from " + from + ": " +
      count;
    $("policy-diff-rows").replaceChildren(...answer.rows.map(row));
    const actions = $("policy-diff-actions");
    actions.replaceChildren();
    if (answer.revision !== answer.head) {
      actions.append(button("Roll back to revision " + answer.revision,
        () => rollback(answer.revision, answer.head)));
    }
    $("policy-diff").hidden = false;
  }

  // What a rollback's answer says: the new revision, and each step left (a restart, the
  // gateway), with its command and where it runs (M.7), as review.js words every next step.
  function written(done, target) {
    return ["Revision " + done.revision + " written, with revision " + target + "'s content."]
      .concat(done.next.map((step) => window.zoeyReview.stepText(step, true) + ".")).join(" ");
  }

  // Roll back to this (H.3, J6): the vault plans the target's content on the head this page
  // showed and lists it, the store entries it leaves unused first; anything wider, or a client
  // or caller the policy removed brought back, is refused with the host's way. Confirmed, the
  // page is drawn again at the new head. A head that moved since the page showed it (a confirm
  // the dialog answered changed, another session's save) is found first: the page is drawn
  // again at the head now, so the next press plans on it; so it is after any refused prepare.
  async function rollback(target, head) {
    let now;
    try {
      now = await api("GET", "/api/policy/revisions" + ONE);
    } catch (error) {
      return afterFailure(error);
    }
    if (now.head !== head) {
      said = MOVED.replace(/\{now\}/g, now.head).replace("{head}", head);
      return draw();
    }
    await prepare("policy.rollback", { base: head, revision: target }, (done) => {
      closeConfirm();
      said = written(done, target);
      $("nav-policy").click();
    });
    if (!$("confirm").open) {
      await draw();
    }
  }

  on("nav-policy", draw);
  on("policy-older", () => history(older));
  window.zoeyPolicy = Object.freeze({ give: give });
})();
