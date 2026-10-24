// Home's attention list (M6 design M.7, K.1), and from step 8 the drift review's columns and
// controls. Like app.js it holds no decision: the vault builds every item from the gateway's
// status report and the one attention decision (J.5), words it and names its one action, each
// string shown through textContent. It uses app.js's API and guard() (window.zoeyPortal).
"use strict";

(function () {
  const { api, button } = window.zoeyPortal;

  // The buttons for an item's action; an unknown kind draws none.
  const ACTION_TEXT = { review: "Review" };

  function $(id) {
    return document.getElementById(id);
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

  window.zoeyDrift = Object.freeze({ home: home, review: review });
})();
