// The MCP servers section (M7 design K.1, K.4, K.5). Like app.js it holds no decision: the vault
// decides every row's state, words every plan line, refusal and next step, and builds both
// fragments, each string shown through textContent. It lists the servers, adds one by URL and runs
// the review screen (the vault's rows filtered in memory), through app.js's API, step-up, Connect
// and guard() (window.zoeyPortal). A client secret typed here is write-only, as the Secrets page's
// is: sent once, in onboard.register's prepare, its field emptied as soon as that request is made.
"use strict";

(function () {
  const { api, fill, visit, fail, textOf, afterFailure, button, on, prepare, closeConfirm,
    renderSummary, connect, when } = window.zoeyPortal;

  // A row's state, in words (K.1); the vault decides which.
  const STATES = {
    discovering: "being discovered",
    needs_register: "discovered: register its client, or make the YAML",
    needs_commit: "fragment 1 made, not yet in the running policy",
    needs_connect: "in the policy, not connected yet",
    needs_review: "connected, its tools not reviewed yet",
    reviewed: "reviewed",
    blocked: "stopped at your egress proxy",
  };
  // Where a next step's command runs (M.7). The vault sends it without the compose command and
  // its files, which only the host knows (ZOEYMCP_COMPOSE_CMD): put yours in front.
  const VIA = {
    exec: "in the vault's container: docker compose exec",
    exec_gateway: "in the gateway's container: docker compose exec",
    run: "in a one-off vault container: docker compose run --rm --no-deps",
    run_mount: "in a one-off vault container with this directory at /w: docker compose run " +
      "--rm --no-deps -v \"$PWD:/w:ro\"",
    up: "recreate the vault: docker compose up -d",
  };
  const STAGES = {
    discovered: "What the vault found",
    registered: "What the vault found (fragment 1 made)",
    blocked: "Stopped at your egress proxy",
    committed: "Already in the policy, and it matches what the server publishes",
  };
  const WAITING = {
    queued: "Queued: waiting for the gateway to take it.",
    sent: "The gateway is reviewing the server.",
  };
  const NOTES = {
    blocked: "A tool this server lists blocks the whole server: see its findings.",
    pinning_off: "This toolkit is served with pinning off: its tools aren't pinned.",
  };
  // What a registration's answer notes (vault/oauth/dcr.py's NOTES: test_portal_static.py).
  const CLIENT_NOTES = {
    grant_types_absent: "The authorization server didn't say which grants it registered: the " +
      "authorization code alone is assumed, and sign-in refuses an answer with no refresh token.",
  };
  const FIRST = "Fragment 1 of 2";
  // The vault's reason for a tool the server doesn't annotate (portal/reviewview.py's
  // WHY_UNANNOTATED, kept equal by test_portal_static.py): the "not annotated" chip's tools.
  const UNANNOTATED = "the server doesn't annotate it";

  let rows = []; // the rows last read
  let shownBoarding = null; // the onboarding the plan shows, for its Cancel
  let namedFor = null; // the URL the name fields were filled in for
  let pendingConnect = null; // a row's Connect: its server's review is queued once it completes
  let reviewing = null; // the review shown: its job, its server and a row per tool
  let fragment = null; // the fragment shown, and how to make it again at another indent
  let ticks = 0;
  let asking = false; // the rows are being read again

  function $(id) {
    return document.getElementById(id);
  }

  // An element with its text, and its class if any.
  function make(tag, text, className) {
    const element = document.createElement(tag);
    element.textContent = text === undefined ? "" : text;
    element.className = className || "";
    return element;
  }

  // A typed field's value, or undefined when it is empty (JSON leaves undefined out).
  function given(id) {
    return $(id).value.trim() || undefined;
  }

  function hostOf(url) {
    try {
      return new URL(url).host;
    } catch (error) {
      return url;
    }
  }

  // --- next steps and refusals (M.7) ---------------------------------------------------------

  // A step as text: its label, the command with the redirect J1's files take, where it runs (with
  // -T when its input is piped in); an allow_hosts step's hosts and Squid lines on lines below.
  // With a button, the label is the button's and the command is the host's way to the same.
  function stepText(step, labelled) {
    let text = labelled ? step.label : "";
    if (typeof step.command === "string") {
      text += (labelled ? ": " : "Or from the host: ") + step.command + (step.redirect || "");
    }
    if (typeof step.via === "string") {
      text += " (" + VIA[step.via] + (step.piped ? " -T, its input piped in" : "") + ")";
    }
    return [text].concat(step.hosts || [], step.squid || []).join("\n");
  }

  // What the button of a step the page can take does; the page takes only the first (M.7), and
  // only what its context names: the onboarding, server or credential the answer or row is for.
  function runner(step, context) {
    const runs = {
      register: context.boarding && (() => prepareRegister(context.boarding)),
      make_fragment: context.boarding && (() => makeFragment(context.boarding, 0)),
      show_fragment: context.boarding && (() => makeFragment(context.boarding, 0)),
      allow_hosts: context.boarding && context.row && (() => openOnboarding(context.boarding)),
      connect: context.credential && context.server && (() => connectFor(context)),
      review: context.server && (() => queueReview(context.server)),
      choose: context.server && (() => queueReview(context.server)),
    };
    return runs[step.do] || null;
  }

  function renderSteps(list, steps, context) {
    list.replaceChildren();
    steps.forEach((step, index) => {
      const run = index === 0 ? runner(step, context) : null;
      const item = make("li", stepText(step, run === null));
      if (run !== null) {
        const label = step.do === "allow_hosts" ? "Show the hosts to allow" : step.label;
        item.prepend(button(label, run), " ");
      }
      list.append(item);
    });
  }

  function renderChecks(list, findings) {
    list.replaceChildren();
    for (const finding of findings) {
      list.append(make("li", finding.level + " at " + finding.path + ": " + finding.message_shown));
    }
  }

  // A refusal: the vault's sentence, with its detail, and what it carries: the next steps, the
  // issuers to choose from (D.3), or check's findings.
  function refused(error, context) {
    afterFailure(error);
    const answer = error && error.answer ? error.answer : {};
    if (typeof answer.detail === "string" && error.reason !== "no_session") {
      fail(textOf(error) + " (" + answer.detail + ")");
    }
    renderSteps($("refusal-next"), Array.isArray(answer.next) ? answer.next : [], context);
    for (const issuer of Array.isArray(answer.issuers) ? answer.issuers : []) {
      const item = make("li");
      item.append(button("Use " + issuer, () => useIssuer(issuer)));
      $("refusal-next").append(item);
    }
    renderChecks($("refusal-check"), Array.isArray(answer.check) ? answer.check : []);
  }

  function clearRefusal() {
    $("refusal-next").replaceChildren();
    $("refusal-check").replaceChildren();
  }

  function hidePanels() {
    $("plan").hidden = $("fragment").hidden = $("review").hidden = true;
    shownBoarding = reviewing = fragment = null;
  }

  // --- the rows (K.1) ------------------------------------------------------------------------

  function rowText(row) {
    const text = row.name_shown + " (" + row.kind + "): " + (STATES[row.state] || row.state);
    if ("onboarding" in row) {
      return text + ", until " + when(row.expires) + ". " + row.server_url;
    }
    if (row.state !== "reviewed") {
      return text + ".";
    }
    const clients = row.clients_shown.join(", ") || "no client yet";
    return text + ": " + row.tools + (row.tools === 1 ? " tool" : " tools") + " served to " +
      clients + ".";
  }

  async function listServers() {
    rows = (await api("GET", "/api/servers")).servers;
    const list = $("server-list");
    list.replaceChildren();
    for (const row of rows) {
      const item = make("li", rowText(row));
      const steps = make("ul", "", "steps");
      renderSteps(steps, row.next, { row: true, boarding: row.onboarding, server: row.server,
        credential: row.credential });
      item.append(steps);
      if (row.state === "blocked") {
        item.append(button("Try again", () => retry(row)));
      }
      if ("onboarding" in row) {
        item.append(button("Cancel", () => cancelOnboarding(row.onboarding)));
      }
      list.append(item);
    }
    if (rows.length === 0) {
      list.append(make("li", "The policy has no remote or toolkit server yet."));
    }
  }

  // Connect opens app.js's dialog (M5); once it completes, the server's review is queued (K.1).
  // A Connect that opened no dialog (refused, or a client_credentials test) holds nothing.
  async function connectFor(context) {
    pendingConnect = { credential: context.credential, server: context.server };
    try {
      await connect(context.credential, false);
    } finally {
      pendingConnect = $("connect").open ? pendingConnect : null;
    }
  }

  async function connected(credential) {
    const held = pendingConnect;
    pendingConnect = null;
    if (held !== null && held.credential === credential) {
      await queueReview(held.server);
    }
  }

  // --- add by URL (K.1 item 2, K.2, K.3) -----------------------------------------------------

  // A private server's discovery lifts the address guard for its host:port, so it is the
  // onboard.discover_private action, confirmed with a passkey (TI-3); any other is a plain read.
  async function discover() {
    clearRefusal();
    if ($("add-private").checked) {
      await prepare("onboard.discover_private", {
        url: $("add-url").value.trim(), allow_private: true, credential: given("add-credential"),
        route: given("add-route"), server: given("add-server"), issuer: given("add-issuer"),
        scope: given("add-scope"), client_id: given("add-client-id"),
        client_auth: given("add-client-auth"), redirect_uri: given("add-redirect"),
        client_name: given("add-client-name")
      }, afterPrivateDiscovery);
      return;
    }
    let answer;
    try {
      answer = await api("POST", "/api/onboard/discover", {
        url: $("add-url").value.trim(), credential: given("add-credential"),
        route: given("add-route"), server: given("add-server"), issuer: given("add-issuer"),
        scope: given("add-scope"), client_id: given("add-client-id"),
        client_auth: given("add-client-auth"), redirect_uri: given("add-redirect"),
        client_name: given("add-client-name")
      });
    } catch (error) {
      refused(error, {});
      if (error.reason === "proxy_refused") {
        await listServers(); // the onboarding is blocked now (D.11): its row says what to do
      }
      return;
    }
    await showOnboarding(answer);
  }

  async function afterPrivateDiscovery(result) {
    closeConfirm();
    await showOnboarding(result);
  }

  // The plan (D.8) as rows, the authorization server's host in large type (RFC 9728 7.8), the
  // hosts the built-in role allows for it, the draft check and the next steps; the URL and the
  // names it chose go into the fields, to edit for a discovery again.
  async function showOnboarding(answer) {
    hidePanels();
    const plan = answer.plan || {};
    const names = answer.names || {};
    const boarding = answer.onboarding;
    const context = { boarding: boarding, server: names.server, credential: names.credential };
    shownBoarding = typeof boarding === "string" ? boarding : null;
    $("plan-title").textContent = STAGES[answer.stage] || answer.stage;
    $("plan-issuer").textContent = typeof plan.issuer === "string" ?
      "Authorization server: " + hostOf(plan.issuer) : "";
    $("plan-blocked").textContent = typeof answer.blocked_on === "string" ?
      "Your egress proxy refused the vault's connection to " + answer.blocked_on + "." : "";
    renderSummary("plan-rows", answer.rows_shown || []);
    const allowed = answer.allowance || [];
    $("plan-allowance").textContent = allowed.length === 0 ? "" :
      "The built-in egress role allows these hosts for this onboarding: " + allowed.join(", ");
    renderChecks($("plan-check"), answer.draft_check || []);
    renderSteps($("plan-next"), answer.next || [], context);
    $("plan-cancel").hidden = shownBoarding === null;
    $("plan").hidden = false;
    fillNames(plan.server_url || answer.server_url, names);
    await listServers();
  }

  // An onboarding's URL and names in the fields: the same again resumes it (D.11).
  function fillNames(url, names) {
    if (typeof url === "string" && typeof names.server === "string") {
      $("add-url").value = namedFor = url;
      $("add-credential").value = names.credential;
      $("add-route").value = names.route;
      $("add-server").value = names.server;
    }
  }

  // Another URL typed empties them, so a second server never takes the first one's names; a
  // cancel always does.
  function clearNames(always) {
    if (always === true || (namedFor !== null && $("add-url").value.trim() !== namedFor)) {
      namedFor = null;
      $("add-credential").value = $("add-route").value = $("add-server").value = "";
    }
  }

  // This session's onboarding as it stands, shown; false once its refusal is.
  async function openOnboarding(boarding) {
    clearRefusal();
    let answer;
    try {
      answer = await api("GET", fill("/api/onboard/{onboarding}", { onboarding: boarding }));
    } catch (error) {
      refused(error, {});
      return false;
    }
    await showOnboarding(answer);
    return true;
  }

  // A blocked onboarding carries on with the same URL and names (D.11): its own, read again
  // into the fields whatever they held; its other options are the form's.
  async function retry(row) {
    if (await openOnboarding(row.onboarding)) {
      await discover();
    }
  }

  async function useIssuer(issuer) {
    $("add-issuer").value = issuer;
    $("add-more").open = true;
    await discover();
  }

  async function cancelOnboarding(boarding) {
    clearRefusal();
    try {
      await api("DELETE", fill("/api/onboard/{onboarding}", { onboarding: boarding }));
    } catch (error) {
      return refused(error, {});
    }
    hidePanels();
    clearNames(true);
    await listServers();
    $("status").textContent = "Onboarding cancelled.";
  }

  // The client secret goes into the prepare's body and its field is emptied as soon as that
  // request is made, whatever the vault answers (G); the confirm sends or stores it.
  async function prepareRegister(boarding) {
    clearRefusal();
    const sent = prepare(
      "onboard.register",
      { onboarding: boarding, client_secret: $("add-client-secret").value || undefined },
      afterRegistered
    );
    $("add-client-secret").value = "";
    await sent;
  }

  async function afterRegistered(result) {
    closeConfirm();
    showFragment(FIRST, result, 0, (indent) => makeFragment(result.onboarding, indent));
    await listServers();
  }

  // A given public client's fragment 1 (nothing sent or stored), or a registered one's again, at
  // any indent (OPS-2): it writes nothing, so it needs no passkey.
  async function makeFragment(boarding, indent) {
    clearRefusal();
    let answer;
    try {
      answer = await api("POST", fill("/api/onboard/{onboarding}/fragment",
        { onboarding: boarding }), { indent: indent });
    } catch (error) {
      return refused(error, { boarding: boarding });
    }
    showFragment(FIRST, answer, indent, (again) => makeFragment(boarding, again));
    await listServers();
  }

  // --- a fragment (J2 step 4, E.4) -----------------------------------------------------------

  // The vault's fragment, shown and copied as the same string; its check, what was stored for
  // fragment 1, and the steps that apply it. ``again`` makes it at another indent.
  function showFragment(title, answer, indent, again) {
    fragment = { yaml: answer.diff.yaml, again: again };
    $("fragment-title").textContent = title;
    const summary = [];
    if (typeof answer.credential === "string") {
      summary.push(["Credential", answer.credential], ["Client ID", answer.client_id_shown],
        ["Client authentication", answer.client_auth],
        ["Client secret", answer.secret_stored ? "stored as " + answer.secret_name : "none"]);
    }
    // A stored secret's expiry, 0 for never (RFC 7591); and what a registration's answer noted.
    const expires = answer.client_secret_expires_at;
    if (answer.secret_stored && typeof expires === "number") {
      summary.push(["The client secret expires", expires > 0 ? when(expires) : "never"]);
    }
    for (const note of Array.isArray(answer.notes) ? answer.notes : []) {
      summary.push(["Note", CLIENT_NOTES[note] || note]);
    }
    renderSummary("fragment-summary", summary);
    $("fragment-indent").value = String(indent);
    $("fragment-text").textContent = fragment.yaml;
    renderChecks($("fragment-check"), answer.diff.check);
    renderSteps($("fragment-next"), answer.next || [], {});
    $("fragment-carries").hidden = title !== FIRST;
    $("fragment").hidden = false;
  }

  async function reindent() {
    if (fragment !== null) {
      const value = $("fragment-indent").value;
      await fragment.again(value === "compose" ? "compose" : Number(value));
    }
  }

  // Copy puts on the clipboard exactly the text shown: the vault's fragment, as it came (K.4).
  async function copyFragment() {
    try {
      await navigator.clipboard.writeText(fragment.yaml);
      $("status").textContent = "Copied the fragment.";
    } catch (error) {
      fail("The browser didn't let the page copy it: select the text and copy it yourself.");
    }
  }

  // --- the review (K.1 item 4, F.6) ----------------------------------------------------------

  // Queue a review for the gateway's poll (F.2), then ask how it stands until it is done.
  async function queueReview(server) {
    if ($("servers").hidden) {
      await visit("servers", listServers);
    }
    clearRefusal();
    let job;
    try {
      job = await api("POST", fill("/api/review/{server}", { server: server }), {});
    } catch (error) {
      return refused(error, { server: server });
    }
    hidePanels();
    reviewing = { job: job.job, server: server, done: false, asking: false, entries: [] };
    $("review-title").textContent = "Review of " + job.server_shown;
    $("review-state").textContent = WAITING[job.state] || "";
    $("review-body").hidden = true;
    $("review").hidden = false;
    await pollReview();
  }

  async function pollReview() {
    const held = reviewing;
    if (held === null || held.done || held.asking) {
      return;
    }
    held.asking = true;
    try {
      const answer = await api("GET", fill("/api/review/jobs/{job}", { job: held.job }));
      if (reviewing === held && answer.state === "done") {
        held.done = true;
        renderReview(held, answer);
      } else if (reviewing === held) {
        $("review-state").textContent = WAITING[answer.state] || "";
      }
    } catch (error) {
      held.done = true; // a failed or unknown job stays so: stop asking
      if (reviewing === held) {
        $("review-state").textContent = "";
        refused(error, { server: held.server });
      }
    } finally {
      held.asking = false;
    }
  }

  function countText(counts) {
    return counts.tools + (counts.tools === 1 ? " tool: " : " tools: ") + counts.read_only +
      " the server marks read-only, " + counts.not_annotated + " not annotated, " +
      counts.with_findings + " with findings, " + counts.with_errors + " with an error" +
      (counts.included ? "; " + counts.included + " included now." : ".");
  }

  // The vault's rows, once: the page filters them in memory, and every control is a plain
  // element (about a hundred tools, J4).
  function renderReview(held, answer) {
    $("review-title").textContent = "Review of " + answer.server_shown + " (" + answer.kind + ")";
    $("review-state").textContent = "";
    const about = [answer.server_info_shown, answer.era, answer.protocol_version];
    $("review-info").textContent = "The server says it is: " +
      (about.filter((part) => typeof part === "string").join(", ") || "nothing");
    $("review-instructions").textContent = answer.instructions_shown === null ? "" :
      "Its instructions:\n" + answer.instructions_shown;
    $("review-notes").textContent = answer.notes.map((note) => NOTES[note] || note).join(" ");
    $("review-counts").textContent = countText(answer.counts);
    held.entries = answer.tools.map(toolEntry);
    $("review-tools").replaceChildren(...held.entries.map((entry) => entry.item));
    $("review-body").hidden = false;
    filter();
    tally();
  }

  // One tool (K.1): its include box, or why it can't be included; its classification, at the
  // server's suggestion once included and labelled as the server's (E-9); its badges, its
  // findings, and its definition on request.
  function toolEntry(tool) {
    const item = make("li");
    const entry = { tool: tool, item: item, box: null, choice: null };
    const head = make("p");
    if (tool.name !== null && (tool.pinnable || tool.included)) {
      entry.box = document.createElement("input");
      entry.box.type = "checkbox";
      entry.box.checked = tool.included;
      const label = make("label", "", "include");
      label.append(entry.box, " Include ");
      head.append(label);
    } else {
      head.append("Can't be included: " + (tool.not_pinnable || "its name isn't a tool name") +
        ". ");
    }
    head.append(make("b", tool.name_shown), tool.title_shown ? " " + tool.title_shown : "",
      make("span", tool.state, "badge"), make("span", "suggested " + tool.suggested, "badge"));
    item.append(head);
    if (entry.box !== null) {
      entry.choice = document.createElement("select");
      for (const kind of ["allow", "approve"]) {
        const option = make("option", kind); // its value is its text
        option.disabled = kind === "allow" && tool.consequential === true;
        entry.choice.append(option);
      }
      entry.choice.value = tool.classification || tool.suggested;
      entry.choice.hidden = !tool.included;
      item.append(entry.choice, make("span", " suggested by the server: " + tool.suggested +
        " (" + tool.suggested_why + ")"));
    }
    if (tool.description_shown) {
      item.append(make("p", tool.description_shown, "description"));
    }
    const findings = make("ul");
    for (const finding of tool.findings) {
      findings.append(make("li", finding.level + ": " + finding.message_shown));
    }
    item.append(findings);
    if (tool.definition_lines.length) {
      const definition = make("pre", "", "definition");
      definition.hidden = true;
      const toggle = button("Show definition", () => {
        if (!definition.hasChildNodes()) {
          renderDefinition(definition, tool.definition_lines);
        }
        definition.hidden = !definition.hidden;
        toggle.textContent = definition.hidden ? "Show definition" : "Hide definition";
      });
      item.append(toggle, definition);
    }
    return entry;
  }

  // A definition's ASCII JSON lines (F.6), each line's continuation chunks under it, marked by
  // the stylesheet: a line's chunks joined are the line, nothing cut.
  function renderDefinition(pre, lines) {
    for (const line of lines) {
      line.forEach((chunk, index) => pre.append(make("span", chunk, index ? "more" : "")));
    }
  }

  // The chips keep the tools that match any chip ticked; the box, those whose shown name or title
  // holds its text.
  function filter() {
    const text = $("review-filter").value.trim().toLowerCase();
    const chips = [
      [$("review-chip-read-only").checked, (tool) => tool.suggested === "allow"],
      [$("review-chip-unannotated").checked, (tool) => tool.suggested_why === UNANNOTATED],
      [$("review-chip-findings").checked,
        (tool) => tool.findings.some((found) => found.level === "warning")],
    ].filter((chip) => chip[0]);
    for (const entry of reviewing === null ? [] : reviewing.entries) {
      const tool = entry.tool;
      const named = (tool.name_shown + " " + (tool.title_shown || "")).toLowerCase();
      entry.item.hidden = !named.includes(text) ||
        (chips.length > 0 && !chips.some((chip) => chip[1](tool)));
    }
  }

  function chosen() {
    const lists = { include: [], allow: [], approve: [] };
    for (const entry of reviewing === null ? [] : reviewing.entries) {
      if (entry.box !== null && entry.box.checked) {
        lists.include.push(entry.tool.name);
        if (entry.choice.value === "allow" || entry.choice.value === "approve") {
          lists[entry.choice.value].push(entry.tool.name);
        }
      }
    }
    return lists;
  }

  // Generate's count; it stays disabled until every included tool is classified (K.1).
  function tally() {
    const lists = chosen();
    const count = lists.include.length;
    $("review-generate").textContent = "Generate (" + count + (count === 1 ? " tool: " :
      " tools: ") + lists.allow.length + " allow, " + lists.approve.length + " approve)";
    $("review-generate").disabled = lists.allow.length + lists.approve.length < count;
  }

  // An include box ticked starts at the server's suggestion, or the policy's classification.
  function changed(event) {
    const entry = reviewing === null ? undefined :
      reviewing.entries.find((each) => each.box === event.target);
    if (entry !== undefined) {
      entry.choice.hidden = !entry.box.checked;
      entry.choice.value = entry.tool.classification || entry.tool.suggested;
    }
    tally();
  }

  // Select suggested includes every pinnable tool the shared rule suggests allow: the server
  // marks it read-only and not destructive (CR-3). It is the only bulk allow (C26).
  function selectSuggested() {
    for (const entry of reviewing === null ? [] : reviewing.entries) {
      if (entry.box !== null && entry.tool.pinnable && entry.tool.suggested === "allow" &&
        !entry.box.checked) {
        entry.box.checked = true;
        entry.choice.hidden = false;
        entry.choice.value = "allow";
      }
    }
    tally();
  }

  function clearChoices() {
    for (const entry of reviewing === null ? [] : reviewing.entries) {
      if (entry.box !== null) {
        entry.box.checked = false;
        entry.choice.hidden = true;
      }
    }
    tally();
  }

  // Fragment 2 from these choices (F.6): the vault builds it, or refuses diff_invalid or
  // review_stale. It writes nothing.
  async function generate(indent, lists) {
    const held = reviewing;
    clearRefusal();
    let answer;
    try {
      answer = await api("POST", fill("/api/review/jobs/{job}/diff", { job: held.job }), {
        include: lists.include, allow: lists.allow, approve: lists.approve, indent: indent
      });
    } catch (error) {
      return refused(error, { server: held.server });
    }
    showFragment("Fragment 2 of 2", answer, indent, (again) => generate(again, lists));
  }

  // --- start ----------------------------------------------------------------------------------

  // Every 2 s while the tab is visible: a review under way is asked how it stands; and every
  // 6 s, while a row waits on its commit and this section is shown, the rows are read again, so
  // the page carries on once the vault sees the commit (J2 step 4).
  async function tick() {
    if (document.visibilityState !== "visible") {
      return;
    }
    await pollReview();
    ticks += 1;
    if (ticks % 3 !== 0 || asking || $("servers").hidden ||
      !rows.some((row) => row.state === "needs_commit")) {
      return;
    }
    asking = true;
    await listServers().catch(afterFailure); // a refusal shows, and the next read is the same
    asking = false;
  }

  on("nav-servers", () => visit("servers", listServers));
  on("add-discover", discover);
  on("plan-cancel", () => cancelOnboarding(shownBoarding));
  on("fragment-copy", copyFragment);
  on("review-suggested", selectSuggested);
  on("review-clear", clearChoices);
  on("review-generate", () => generate(0, chosen()));
  // Not clicks: a box, a choice or a chip changed, the filter typed in, another indent chosen.
  $("review-tools").addEventListener("change", changed);
  $("review-filters").addEventListener("change", filter);
  $("review-filters").addEventListener("input", filter);
  $("add-url").addEventListener("input", clearNames);
  $("fragment-indent").addEventListener("change", reindent);
  setInterval(tick, 2000);
  window.zoeyReview = Object.freeze({ connected: connected });
})();
