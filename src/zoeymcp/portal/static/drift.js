// Home's attention list (M6 design M.7, K.1), what the gateway reports on the MCP servers rows, and
// the review screen's drift columns and controls (J.2, J.3), drawn through review.js's hooks; and
// Clear the marks and Allow without asking (J.4, J3, J13). Like app.js it holds no decision: the
// vault builds every item from the gateway's status report and the one attention decision (J.5),
// and every row, its two definitions and their diff from the review's report, each string shown
// through textContent; a clear is the vault's tool.clear action, and the gateway's own check. It
// uses app.js's API, step-up and guard() (window.zoeyPortal), and review.js calls it when it draws
// (window.zoeyDrift).
"use strict";

(function () {
  const { api, fill, afterFailure, button, prepare, closeConfirm } = window.zoeyPortal;

  // The buttons for an item's action; an unknown kind draws none.
  const ACTION_TEXT = { review: "Review", clear: "Clear the marks" };
  const MISSING = "The gateway no longer has the reviewed copy: the new definition is shown whole.";
  // A re-pinned allow tool whose new definition the server no longer marks read-only (Q8).
  const PROPOSED = "The new definition isn't marked read-only: approve is proposed. Choose " +
    "allow above to keep it, and the fragment says you kept it.";
  // What accepting it chooses: the stricter classification, never a move toward allow (Q27-1).
  const APPROVE = "approve";
  // Allow without asking moves one included approve tool, the one whose button was pressed (J3).
  const ALLOW = "allow";
  const MOVED = "Moved from approve to allow by Allow without asking: calls to this tool will " +
    "run with no prompt. Generate's fragment says so in a comment.";
  const NOT_MOVED = "Allow without asking: the review shows that tool not included as approve " +
    "(or the toolkit declares it consequential), so nothing was moved.";
  // A tool in these states matches its pin (gateway/review.py's MATCHING): Clear the marks is
  // enabled only when every included tool is in one, and one is marked (J13).
  const MATCHING = ["ok", "marked", "blocked"];
  // A clear job is read every 2 s, for at most 3 minutes: the gateway takes it within 60 s and
  // answers within 2 minutes (vault/reviewjobs.py).
  const CLEAR_EVERY = 2000;
  const CLEAR_READS = 90;

  // Allow without asking: the job whose review screen moves a tool, and the tool, while it waits;
  // and the review screen footer() drew last (review.js's held), which it moves once drawn.
  let moving = null;
  let drawn = null;

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

  // A checkbox with its words, appended to ``place``; the box, for lists() to read.
  function check(place, text) {
    const box = document.createElement("input");
    box.type = "checkbox";
    const label = make("label", "", "check");
    label.append(box, " " + text);
    place.append(label);
    return box;
  }

  // A server's review: the MCP servers page, where its row has Review.
  function review() {
    $("nav-servers").click();
  }

  // What the gateway reports, labelled as its own: the time of its report, or that none came.
  function reported(answer) {
    if (answer.reported_ago === null) {
      return "The gateway hasn't reported its status since the vault started.";
    }
    const said = "The gateway reports, " + answer.reported_ago + " s ago: ";
    const more = answer.more ? " " + answer.more + " more: run zoeymcp health." : "";
    return said + (answer.items.length ? "" : "nothing needs you.") + more;
  }

  // Clear the marks (J.4, J13): a passkey, then the vault queues a clear job, which the gateway
  // runs only if every included tool matches its pin again. The page reads the job as it reads a
  // review: done, it says which marks went and draws again (``after``); refused, the vault's
  // sentence names the tools that still don't match (clear_not_clean).
  async function clear(server, after) {
    await prepare("tool.clear", { server: server }, async (job) => {
      closeConfirm();
      $("status").textContent = "The gateway is listing the server's tools again.";
      for (let reads = 0; reads < CLEAR_READS; reads += 1) {
        let read;
        try {
          read = await api("GET", fill("/api/review/jobs/{job}", { job: job.job }));
        } catch (error) {
          return afterFailure(error);
        }
        if (read.state === "done") {
          $("status").textContent = "Cleared the drift marks of " + read.server_shown +
            (read.cleared_shown.length ? ": " + read.cleared_shown.join(", ") : "") + ".";
          return after();
        }
        await new Promise((resolve) => setTimeout(resolve, CLEAR_EVERY));
      }
      $("status").textContent = "The gateway hasn't answered the clear yet: review the server.";
    });
  }

  // What an item's button does: a review opens the MCP servers page; a clear asks for a passkey.
  function act(action, after) {
    return action.kind === "clear" ? () => clear(action.server, after) : review;
  }

  // Home's list (M.7): each item with its one action, below the checklist.
  async function home() {
    const answer = await api("GET", "/api/attention");
    $("attention-block").hidden = !answer.gateway;
    $("attention-text").textContent = reported(answer);
    const list = $("attention");
    list.replaceChildren();
    for (const item of answer.items) {
      const entry = document.createElement("li");
      entry.textContent = item.text_shown + ". ";
      const label = ACTION_TEXT[item.action.kind];
      if (label !== undefined) {
        entry.append(button(label, act(item.action, home)));
      }
      list.append(entry);
    }
  }

  // Allow without asking, declarative (J3): the review screen opens with that one tool moved
  // from approve to allow on its own row, and Generate's fragment says so. The move is that job's
  // alone: a review the vault refused queues nothing, and a job that fails or is replaced by
  // another review never draws, so no later review of the server moves the tool.
  async function allow(server, name, queue) {
    moving = null;
    const job = await queue(server); // none when the vault refused it
    if (job === undefined) {
      return;
    }
    if (drawn !== null && drawn.job === job) {
      move(drawn.entries.find((entry) => entry.tool.name === name));
    } else {
      moving = { job: job, name: name }; // footer() moves it when the job's review draws
    }
  }

  // The MCP servers rows (review.js's listServers, one item per row in order): under each server,
  // Allow without asking for each included approve tool; and where the gateway reports on it,
  // what it reports (Home's items for that server) with Clear the marks for marked tools, above
  // the row's own Review again, which asks for a fresh review (J.2).
  async function servers(list, rows, queue) {
    rows.forEach((row, index) => {
      for (const named of typeof row.server === "string" ? row.approve : []) {
        list.children[index].append(button("Allow " + named.name_shown + " without asking",
          () => allow(row.server, named.name, queue)));
      }
    });
    let answer;
    try {
      answer = await api("GET", "/api/attention");
    } catch (error) {
      return;
    }
    rows.forEach((row, index) => {
      const said = answer.items.filter((item) => item.action.server === row.server);
      if (typeof row.server === "string" && said.length) {
        const steps = list.children[index].querySelector("ul.steps");
        steps.before(make("p", "The gateway reports: " +
          said.map((each) => each.text_shown).join("; ") + "."));
        if (said.some((each) => each.action.kind === "clear")) {
          steps.before(button(ACTION_TEXT.clear, () => clear(row.server, () => queue(row.server,
            true))));
        }
      }
    });
  }

  // A definition's ASCII JSON lines in ``pre``, each line's continuation chunks under it, marked
  // by the stylesheet (review.js's renderDefinition): a line's chunks joined are the line.
  function lines(pre, found) {
    for (const line of found) {
      line.forEach((chunk, index) => pre.append(make("span", chunk, index ? "more" : "")));
    }
  }

  // A drifted tool's two columns (J.2): Reviewed, the definition the policy pinned, which the
  // vault checked against the pin (or why it isn't shown), and Now, the one the server lists, which
  // the vault pinned itself; then the vault's line diff between them. Nothing cut.
  function columns(tool) {
    const block = make("div", "", "drift");
    const reviewed = make("pre", "", "definition");
    if (tool.reviewed_missing) {
      reviewed.append(make("span", MISSING));
    }
    lines(reviewed, tool.reviewed_lines);
    const now = make("pre", "", "definition");
    lines(now, tool.definition_lines);
    const diff = make("pre", "", "definition diff");
    lines(diff, tool.diff_lines);
    block.append(make("div", "Reviewed (" + tool.pinned + ")"), make("div", "Now (" + tool.pin +
      ")"), reviewed, now, diff);
    return block;
  }

  // review.js's row hook: a drifted tool's columns and Accept the new definition (a re-pin, which
  // keeps its classification, Q8); Decline for a pinnable tool the policy doesn't include, which
  // records it left out at the definition shown (J.3).
  function row(entry) {
    const tool = entry.tool;
    const place = entry.item; // the row's list item
    if (tool.state === "drift") {
      place.append(columns(tool));
      if (tool.pinnable && tool.name !== null) {
        entry.repin = check(place, "Accept the new definition");
        if (tool.proposed) {
          place.append(make("p", PROPOSED));
          entry.repin.addEventListener("change", () => {
            entry.choice.value = entry.repin.checked ? APPROVE : tool.prefill;
          });
        }
      }
    }
    if (entry.box !== null && tool.pinnable && !tool.included) {
      entry.decline = check(place, "Decline: leave it out, recorded at this definition");
    }
  }

  // review.js's footer hook: Review again, a fresh review that never reuses the done one, since
  // a server can change a tool with no change to the policy (J.2); Clear the marks when a tool is
  // marked, enabled only when every included tool matches its pin (J13); and the tool Allow
  // without asking asked to move, if this is the review of the job it queued (J3).
  function footer(held, view, queue) {
    const drifted = view.tools.filter((tool) => tool.state === "drift").length;
    $("review-drift").replaceChildren(drifted ? drifted + (drifted === 1 ? " tool" : " tools") +
      " changed since the review. " : "", button("Review again", () => queue(held.server, true)));
    const included = view.tools.filter((tool) => tool.included);
    if (included.some((tool) => tool.state === "marked")) {
      const clearing = button(ACTION_TEXT.clear, () => clear(held.server, () => queue(held.server,
        true)));
      clearing.disabled = !included.every((tool) => MATCHING.includes(tool.state));
      $("review-drift").append(" ", clearing);
    }
    drawn = held;
    const asked = moving;
    moving = null;
    if (asked !== null && asked.job === held.job) {
      move(held.entries.find((entry) => entry.tool.name === asked.name));
    }
  }

  // The one move Allow without asking makes: an included approve tool's choice, set to allow on
  // its row, which says so; never a toolkit's consequential tool (J3).
  function move(entry) {
    if (entry === undefined || entry.choice === null || !entry.box.checked ||
      entry.tool.classification !== APPROVE || entry.tool.consequential === true) {
      $("status").textContent = NOT_MOVED;
      return;
    }
    const place = entry.item; // the row's list item
    entry.choice.value = ALLOW;
    place.append(make("p", MOVED));
  }

  // The lists Generate sends (review.js's chosen() adds the included ones): the drifted tools
  // whose new definition is accepted and still included, the tools declined and not included, and
  // whether the rest are recorded as declined.
  function lists(held) {
    const found = { include: [], allow: [], approve: [], repin: [], decline: [],
      decline_rest: $("review-decline-rest").checked };
    for (const entry of held === null ? [] : held.entries) {
      if (entry.repin && entry.repin.checked && entry.box.checked) {
        found.repin.push(entry.tool.name);
      }
      if (entry.decline && entry.decline.checked && !entry.box.checked) {
        found.decline.push(entry.tool.name);
      }
    }
    return found;
  }

  window.zoeyDrift = Object.freeze({
    home: home, review: review, servers: servers, row: row, footer: footer, lists: lists,
  });
})();
