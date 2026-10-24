// Home's attention list (M6 design M.7, K.1), what the gateway reports on the MCP servers rows, and
// the review screen's drift columns and controls (J.2, J.3), drawn through review.js's hooks. Like
// app.js it holds no decision: the vault builds every item from the gateway's status report and
// the one attention decision (J.5), and every row, its two definitions and their diff from the
// review's report, each string shown through textContent. It uses app.js's API and guard()
// (window.zoeyPortal), and review.js calls it when it draws (window.zoeyDrift).
"use strict";

(function () {
  const { api, button } = window.zoeyPortal;

  // The buttons for an item's action; an unknown kind draws none.
  const ACTION_TEXT = { review: "Review" };
  const MISSING = "The gateway no longer has the reviewed copy: the new definition is shown whole.";
  // A re-pinned allow tool whose new definition the server no longer marks read-only (Q8).
  const PROPOSED = "The new definition isn't marked read-only: approve is proposed. Choose " +
    "allow above to keep it, and the fragment says you kept it.";
  // What accepting it chooses: the stricter classification, never a move toward allow (Q27-1).
  const APPROVE = "approve";

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
        entry.append(button(label, review));
      }
      list.append(entry);
    }
  }

  // The MCP servers rows (review.js's listServers, one item per row in order): under each server
  // the gateway reports on, what it reports (Home's items for that server), above the row's own
  // Review again, which asks for a fresh review (J.2). Without the gateway's report, nothing.
  async function servers(list, rows) {
    let answer;
    try {
      answer = await api("GET", "/api/attention");
    } catch (error) {
      return;
    }
    rows.forEach((row, index) => {
      const said = answer.items.filter((item) => item.action.server === row.server);
      if (typeof row.server === "string" && said.length) {
        list.children[index].querySelector("ul.steps").before(make("p", "The gateway reports: " +
          said.map((each) => each.text_shown).join("; ") + "."));
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
  // a server can change a tool with no change to the policy (J.2).
  function footer(held, view, queue) {
    const drifted = view.tools.filter((tool) => tool.state === "drift").length;
    $("review-drift").replaceChildren(drifted ? drifted + (drifted === 1 ? " tool" : " tools") +
      " changed since the review. " : "", button("Review again", () => queue(held.server, true)));
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
