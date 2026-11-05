// The portal's page (M5 design K). It holds no decision: every rule is the vault's, and every
// text the vault sends is shown as it is, through textContent. It words only what the browser
// itself refuses. Every change is a fetch() with POST or DELETE and the session's header half,
// the one thing kept in sessionStorage (F.2). Passkey prompts open only from click handlers.
// A full session changes things only through actions (F.4): prepare, show the vault's summary,
// then confirm with a passkey. Secrets are write-only (G): a value typed here is sent once, in
// its prepare, and the field is emptied as soon as the request is made. A connect whose login
// can take the portal's callback (H.6) polls its login until the provider sends it back.
"use strict";

(function () {
  const TOKEN = "session";
  const HEADER = "X-ZoeyMCP-Session";
  const PAGES = ["blocked", "login", "setup", "home", "credentials", "sessions", "passkeys",
    "secrets", "ledger", "policy", "servers", "approvals"];
  const SETUP_STEPS = ["setup-code-step", "setup-name-step", "setup-done-step"];
  // The help's "Learn more" links: the docs at this release's tag (dev's while unreleased).
  const DOCS = "https://github.com/RyanLeeUPC/ZoeyMCP/blob/dev/docs/";
  // A finding's level, as its tag's word and tone (the Zoey design system's Tag).
  const LEVEL = { error: ["Error", "z-tag--danger"], warning: ["Warning", "z-tag--warning"],
    info: ["Info", ""] };

  // What the browser refuses, worded here (M.2); the vault words every other refusal.
  const BROWSER_TEXT = {
    ip_literal: "Passkeys don't work on IP addresses. Open the portal at the name listed in " +
      "admin.origins, such as localhost with its port.",
    insecure: "This page isn't a secure context, so the browser won't use passkeys here. Use " +
      "localhost, or https with a certificate this browser trusts.",
    no_webauthn:
      "This browser doesn't support passkeys. Use a current Chrome, Edge, Firefox or Safari.",
    no_get_public_key:
      "This browser can't hand the vault a new passkey's key. Update it, or use another browser.",
    NotAllowedError: "The passkey prompt was cancelled or timed out, or no passkey for this " +
      "address was chosen. Try again.",
    InvalidStateError: "This authenticator already holds a passkey enrolled here. Use another " +
      "authenticator, or a setup code issued with --reset to replace it.",
    SecurityError: "The browser refused a passkey on this address. Open the portal at an " +
      "address listed in admin.origins.",
    NotSupportedError:
      "This authenticator supports none of the vault's key types (ES256, Ed25519, RS256).",
    network: "The vault didn't answer. Check that it is running, then try again.",
  };
  const PROMPT_ERRORS = ["NotAllowedError", "InvalidStateError", "SecurityError",
    "NotSupportedError"];
  const VIA = { setup_code: "with a setup code", setup_code_reset: "with a reset setup code",
    portal: "from a signed-in session" };

  // The buttons for health's actions (I.1); the vault words every other action (todo).
  const ACTION_TEXT = { connect: "Connect", reset: "Try again", add_passkey: "Add a passkey",
    set_secret: "Set it on the Secrets page", delete_secret: "See the Secrets page",
    review_passkeys: "Review the passkeys", review: "Review" };
  const SECTION = { credential: "Credential", connector: "Connector", store: "The store",
    egress: "Egress", passkeys: "Passkeys", ledger_copy: "The reported ledger",
    gateway: "The gateway reports", policy: "The policy", approvals: "Approvals" };

  let pending = null; // the action being confirmed: its ID, step-up options and what follows
  let creating = null; // a confirmed passkey.enrol's ceremony, until the passkey is created
  let renaming = null; // the fingerprint the rename form is for
  let connecting = null; // the connect dialog's credential, its flow and whether to poll it
  let older = null; // the ledger's next page: its archive, if any, and the seq it ends below

  function $(id) {
    return document.getElementById(id);
  }

  class Refused extends Error {
    constructor(text, reason, status, answer) {
      super(text);
      this.reason = reason;
      this.status = status;
      this.answer = answer;
    }
  }

  // A route's path with its parameters filled in, each one encoded (M.1's templates).
  function fill(template, values) {
    return template.replace(/\{([a-z]+)\}/g, (match, name) => encodeURIComponent(values[name]));
  }

  // --- the API --------------------------------------------------------------------------------

  async function api(method, path, body) {
    const headers = {};
    const saved = sessionStorage.getItem(TOKEN);
    if (saved !== null) {
      headers[HEADER] = saved;
    }
    const init = { method: method, headers: headers, credentials: "same-origin",
      redirect: "error", cache: "no-store" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(path, init);
    } catch (error) {
      throw new Refused(BROWSER_TEXT.network, "network", 0);
    }
    const answer = await response.json().catch(() => null);
    if (response.ok) {
      return answer;
    }
    const reason = answer && typeof answer.reason === "string" ? answer.reason : "";
    const text = answer && typeof answer.error === "string" ? answer.error :
      "The vault refused that (HTTP " + response.status + ").";
    if (response.status === 401) {
      sessionStorage.removeItem(TOKEN); // whatever the cause, this session is gone (F.2)
    }
    throw new Refused(text, reason, response.status, answer);
  }

  function signedOut(error) {
    return error instanceof Refused && error.reason === "no_session";
  }

  function textOf(error) {
    if (error instanceof Refused) {
      return error.message;
    }
    if (error && PROMPT_ERRORS.indexOf(error.name) !== -1) {
      return BROWSER_TEXT[error.name];
    }
    return "The passkey prompt failed (" + String(error && error.name ? error.name : error) + ").";
  }

  // --- the page -------------------------------------------------------------------------------

  function show(page) {
    // A save that draws its page again (drift.js saved, approvals.js holdSaved) keeps its words.
    const again = !$(page).hidden;
    $("loading").hidden = true;
    for (const id of PAGES) {
      $(id).hidden = id !== page;
      const nav = $("nav-" + id); // the nav's current page, for the eye and the screen reader
      if (nav) nav.ariaCurrent = id === page ? "page" : null;
    }
    if (page !== "secrets") {
      $("secret-value").value = ""; // a value typed but not sent doesn't stay in the page
    }
    if (page !== "servers") {
      $("add-client-secret").value = ""; // nor does a client secret for an onboarding (M7 K.1)
    }
    if (!again) $("status").textContent = "";
  }

  function step(id) {
    const at = SETUP_STEPS.indexOf(id);
    SETUP_STEPS.forEach((other, n) => {
      $(other).hidden = other !== id;
      const shown = $("setup-steps").children[n];
      shown.ariaCurrent = n === at ? "step" : null;
      shown.dataset.state = n < at ? "done" : "";
    });
  }

  // An error line: its text, hidden when there is none.
  function say(id, text) {
    $(id).textContent = text;
    $(id).hidden = text === "";
  }
  const fail = (text) => say("error", text);
  const clearError = () => say("error", "");
  const connectError = (text) => say("connect-error", text);
  const confirmError = (text) => say("confirm-error", text);

  // A refusal's text, and the text the provider's answer carried, labelled as such (H.3).
  function carried(text, said) {
    return text + (said ? " The answer carried this text: " + said : "");
  }

  function when(seconds) {
    return new Date(seconds * 1000).toLocaleString();
  }

  // An element with its classes and, if given, its text.
  function make(tag, className, text) {
    const element = document.createElement(tag);
    element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function renderBar(session) {
    $("bar").hidden = session.scope !== "full";
    $("bar-origin").textContent = session.origin;
    const name = session.credential_name_shown;
    $("bar-passkey").textContent =
      session.credential === null ? "" : "Passkey " + (name === null ? "" : name + " ") +
        "(" + session.credential + ")";
    $("bar-ends").textContent = "Ends by " + new Date(session.expires_at * 1000)
      .toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + " or 15 idle minutes";
    const counts = session.health_summary;
    const health = $("bar-health");
    health.hidden = counts === null;
    if (counts === null) return;
    health.textContent = counts.error ? counts.error + (counts.error > 1 ? " errors" : " error") :
      counts.warning ? counts.warning + (counts.warning > 1 ? " warnings" : " warning") : "Healthy";
    health.className = "z-health" + (counts.error ? " z-health--error" :
      counts.warning ? " z-health--warning" : "");
  }

  function renderBanners(banners) {
    const list = $("banners");
    list.replaceChildren();
    for (const banner of banners) {
      const item = make("li", "banner z-alert z-alert--warning");
      item.append(make("span", "z-alert__mark", "!"), make("p", "z-alert__text", banner.text));
      item.firstChild.ariaHidden = "true";
      list.append(item);
    }
  }

  // A page from the vault: what it shows is filled in, then it appears; a refusal is said.
  async function visit(page, fill) {
    clearError();
    try {
      await fill();
      show(page);
    } catch (error) {
      afterFailure(error);
    }
  }

  function showLogin() {
    $("bar").hidden = true;
    renderBanners([]);
    show("login");
  }

  // Where a stored session leads: setup's name step, or Home; without one, the login page.
  async function enter() {
    if (sessionStorage.getItem(TOKEN) === null) {
      showLogin();
      return;
    }
    let session;
    try {
      session = await api("GET", "/api/session");
    } catch (error) {
      showLogin();
      if (!signedOut(error)) {
        fail(textOf(error));
      }
      return;
    }
    renderBar(session);
    renderBanners(session.banners);
    if (session.scope === "setup") {
      show("setup");
      $("setup-reset").hidden = !session.reset;
      step("setup-name-step");
      return;
    }
    $("home-text").textContent =
      "Signed in on " + session.origin + ". Passkeys enrolled for " + session.rp_id + ": " +
      session.passkeys_here + ".";
    try {
      const health = await api("GET", "/api/health");
      $("home-ready").textContent = health.summary.error + health.summary.warning ?
        "What needs you, errors first:" : "Everything is ready.";
      renderFindings($("checklist"), health.checklist);
      if (window.zoeyDrift) await window.zoeyDrift.home(); // M6 M.7: Home's attention list
      if (window.zoeyApprovals) await window.zoeyApprovals.home(); // M8 H.1: its approvals item
      show("home");
    } catch (error) {
      afterFailure(error);
    }
  }

  // --- health and credentials (I, H) ----------------------------------------------------------

  function actionControl(action) {
    const runs = {
      connect: () => connect(action.credential, false),
      reset: () => prepare("oauth.reset", { credential: action.credential }, afterReset),
      set_secret: () => showSecrets(String(action.ref).replace(/^store:/, "")),
      delete_secret: () => showSecrets(action.secret),
      add_passkey: showPasskeys,
      review_passkeys: showPasskeys,
      review: () => window.zoeyDrift.review(action.server),
    };
    const run = action ? runs[action.kind] : undefined;
    return run === undefined ? "" : button(ACTION_TEXT[action.kind], run);
  }

  // A finding's row (the design system's FindingList): its level as a tag, what is found, its
  // next step, and its action.
  function finding(level, text, where, action) {
    const item = make("li", "z-finding");
    const body = make("div", "z-finding__body");
    body.append(make("p", "z-finding__text", text));
    if (where) body.append(make("p", "z-finding__where", where));
    const [word, tone] = LEVEL[level] || [level, ""];
    item.append(tag(word, tone), body);
    if (action) item.append(make("div", "z-finding__action"));
    if (action) item.lastChild.append(action);
    return item;
  }

  function renderFindings(list, findings) {
    list.replaceChildren();
    for (const found of findings) {
      list.append(finding(found.level, SECTION[found.section] +
        (found.name_shown === null ? "" : " " + found.name_shown) + ": " + found.text_shown +
        (found.advisory ? " (from stored metadata)." : "."), found.todo,
        actionControl(found.action)));
    }
  }

  async function showCredentials() {
    await visit("credentials", async () => {
      const health = await api("GET", "/api/health");
      const oauth = await api("GET", "/api/oauth");
      const list = $("credential-list");
      list.replaceChildren();
      for (const credential of health.credentials) {
        const entry = oauth.credentials.find((one) => one.credential === credential.name);
        const [word, tone] = credential.level === "error" || credential.level === "warning" ?
          LEVEL[credential.level] : ["OK", "z-tag--ok"];
        const item = row(credential.name_shown + " (" + credential.kind + ")", "Used by " +
          (credential.routes.join(", ") || "no route") + "." +
          (entry === undefined ? "" : " " + entry.text_shown), [tag(word, tone)],
        entry !== undefined && entry.connect !== null ? [button(entry.connect === "test" ?
          "Test it" : "Connect", () => connect(entry.credential, false), "z-btn--primary")] : []);
        const findings = make("ul", "z-findings z-findings--compact");
        renderFindings(findings, credential.findings);
        if (credential.findings.length) item.firstChild.append(findings);
        list.append(item);
      }
    });
  }

  // H.1: start a sign-in this session owns; for client_credentials, the start is a test fetch.
  async function connect(name, rebind) {
    clearError();
    closeConnect();
    let started;
    try {
      started = await api(
        "POST", fill("/api/oauth/{credential}/start", { credential: name }), { rebind: rebind }
      );
    } catch (error) {
      const moved = error instanceof Refused && error.reason === "binding_changed";
      return moved ? openConnect(name, null, error) : afterFailure(error);
    }
    if (started.flow === undefined) {
      await showCredentials();
      $("status").textContent = "The client credentials work: " + started.text_shown;
      return;
    }
    openConnect(name, started, null);
  }

  // The link opens in a new tab with no opener, its address set only if it is https (C.4).
  function openConnect(name, started, refused) {
    connecting = { credential: name, flow: started && started.flow,
      callback: started && started.callback };
    $("connect-steps").hidden = started === null;
    $("connect-rebind").hidden = started !== null;
    connectError(refused === null ? "" : refused.message);
    if (started === null) {
      renderSummary("connect-summary", [["Bound until now", refused.answer.old_shown],
        ["The policy now binds it to", refused.answer.new_shown]]);
    } else {
      const change = started.binding_change_shown;
      renderSummary("connect-summary", [
        ["Connect", started.name_shown],
        ["Scopes asked for", started.requested_scopes_shown.join(" ") || "none"],
        ["Scopes expected", started.expected_scopes_shown.join(" ") || "none"],
        ["Its tokens go to", started.binding_shown],
      ].concat(change === null ? [] : [["Bound until now", change.old]]));
      const https = new URL(started.authorize_url).protocol === "https:";
      $("connect-link").hidden = !https;
      $("connect-link").href = https ? started.authorize_url : "";
      $("connect-replaced").textContent = started.replaced === null ? "" :
        "This replaced a sign-in pending in " +
        (started.replaced === "cli" ? "zoeymcp login." : "the portal.");
      $("connect-redirect").textContent = started.redirect_uri_shown;
      $("connect-by").textContent = $("connect-by-callback").textContent = when(started.expires);
      $("connect-paste-text").hidden = started.callback !== null;
      $("connect-callback-text").hidden = started.callback === null;
    }
    $("connect").showModal();
  }

  // The paste is the oauth.complete action's data: the vault checks it before any prompt.
  function checkPaste() {
    const held = connecting;
    connectError("");
    const pasted = $("connect-paste").value.trim();
    return prepareConnect({ credential: held.credential, flow: held.flow, redirect_url: pasted });
  }

  // oauth.complete with a paste, or with returned: true once the callback holds the code. When
  // the callback already holds what was pasted, the vault says so: confirm that one instead.
  async function prepareConnect(data) {
    let prepared;
    try {
      prepared = await api("POST", "/api/actions", { kind: "oauth.complete", data: data });
    } catch (error) {
      if (error.reason === "flow_returned") {
        return prepareConnect({ credential: data.credential, flow: data.flow, returned: true });
      }
      if (signedOut(error) || !$("connect").open) {
        closeConnect();
        return afterFailure(error);
      }
      return connectError(carried(textOf(error), error.answer && error.answer.description_shown));
    }
    closeConnect();
    openConfirm(prepared, afterConnected, "Exchanging the code with the provider...", data);
  }

  // H.6: while the dialog of a login that can take the callback is open and the tab visible, ask
  // every 2 s, and at once when the tab is shown again, until the provider has sent it back, it
  // failed or it is gone. The callback's own tab runs no script.
  async function poll() {
    const held = connecting;
    if (held === null || !held.callback || held.asking || document.visibilityState !== "visible") {
      return;
    }
    held.asking = true;
    try {
      const status = await api("GET", fill("/api/oauth/flows/{flow}", { flow: held.flow }));
      if (status.stage !== "pending" && connecting === held) {
        held.callback = null;
        if (status.stage === "returned") {
          await prepareConnect({ credential: held.credential, flow: held.flow, returned: true });
        } else {
          connectError(carried(status.failure.text_shown, status.failure.description_shown));
        }
      }
    } catch (error) {
      held.callback = null; // the login is gone: say why, and stop asking
      return signedOut(error) ? afterFailure(error) : connectError(textOf(error));
    } finally {
      held.asking = false;
    }
  }

  async function cancelConnect() {
    const held = connecting;
    closeConnect();
    if (held !== null && held.flow !== null) {
      // A refusal other than a signed-out one means the sign-in had already ended.
      await api("DELETE", fill("/api/oauth/flows/{flow}", { flow: held.flow })).catch(
        (error) => signedOut(error) && afterFailure(error));
    }
  }

  function closeConnect() {
    connecting = null; // and the poll stops
    $("connect-paste").value = "";
    if ($("connect").open) {
      $("connect").close();
    }
  }

  async function afterConnected(result) {
    closeConfirm();
    await showCredentials();
    $("status").textContent = "Connected " + result.name_shown + ": " + result.text_shown;
    await window.zoeyReview.connected(result.credential); // a server row's Connect reviews it
  }

  async function afterReset() {
    closeConfirm();
    await showCredentials();
    $("status").textContent = "Failures cleared: the next request that needs a token tries once.";
  }

  // --- login and setup (E, F.2) ---------------------------------------------------------------

  async function signIn() {
    clearError();
    try {
      const begun = await api("POST", "/api/login/begin", {});
      const credential = await zoeyWebAuthn.get(begun.options);
      const minted = await api("POST", "/api/login/finish",
        { ceremony: begun.ceremony, credential: credential });
      sessionStorage.setItem(TOKEN, minted.token);
      await enter();
    } catch (error) {
      fail(textOf(error));
    }
  }

  async function redeem() {
    clearError();
    try {
      const minted = await api("POST", "/api/setup/redeem", { code: $("setup-code").value });
      sessionStorage.setItem(TOKEN, minted.token);
      $("setup-code").value = "";
      $("setup-reset").hidden = !minted.reset;
      step("setup-name-step");
    } catch (error) {
      fail(textOf(error));
    }
  }

  async function enrol() {
    clearError();
    try {
      const begun = await api("POST", "/api/passkeys/enrol/begin", { name: $("setup-name").value });
      const credential = await zoeyWebAuthn.create(begun.options);
      const done = await api("POST", "/api/passkeys/enrol/finish",
        { ceremony: begun.ceremony, credential: credential });
      // The setup session ended with its enrolment: sign in with the new passkey next (E.1).
      sessionStorage.removeItem(TOKEN);
      $("setup-fingerprint").textContent = done.passkey.fingerprint;
      step("setup-done-step");
    } catch (error) {
      if (signedOut(error)) {
        step("setup-code-step");
      }
      fail(textOf(error));
    }
  }

  // --- sessions (F.2) -------------------------------------------------------------------------

  async function showSessions() {
    await visit("sessions", async () => {
      const answer = await api("GET", "/api/sessions");
      const list = $("session-list");
      list.replaceChildren();
      for (const session of answer.sessions) {
        const by = session.credential === null ? "a setup code" : "passkey " + session.credential;
        list.append(row(session.fingerprint, session.origin + ", signed in with " + by + " at " +
          when(session.created) + ", last used " + when(session.last_seen) + ".",
        session.this ? [tag("This browser", "z-tag--current")] : []));
      }
    });
  }

  async function endOthers() {
    clearError();
    try {
      const answer = await api("POST", "/api/sessions/end-others", {});
      await showSessions();
      $("status").textContent = "Ended " + answer.ended + " other session(s).";
    } catch (error) {
      afterFailure(error);
    }
  }

  async function signOut() {
    clearError();
    try {
      await api("POST", "/api/logout", {});
    } catch (error) {
      if (!signedOut(error)) {
        fail(textOf(error));
      }
    }
    sessionStorage.clear();
    showLogin();
  }

  function afterFailure(error) {
    if (signedOut(error)) {
      closeConfirm();
      showLogin();
    }
    fail(textOf(error));
  }

  // --- passkeys (D.5) -------------------------------------------------------------------------

  // A row's button: secondary and small unless ``kind`` says otherwise.
  function button(label, handler, kind) {
    const element = make("button", "z-btn z-btn--small " + (kind || "z-btn--secondary"), label);
    element.type = "button";
    guard(element, handler);
    return element;
  }

  function tag(text, tone) {
    return make("span", "z-tag " + (tone || ""), text);
  }

  // A list row (the design system's ItemList): its title and tags, its facts, its buttons.
  function row(title, meta, tags, actions) {
    const item = make("li", "z-list__item");
    const body = make("div", "z-list__body");
    const head = make("span", "z-list__title", title);
    head.append(...(tags || []));
    body.append(head, make("span", "z-list__meta", meta));
    item.append(body);
    if (actions && actions.length) item.append(make("div", "z-list__actions"));
    if (actions && actions.length) item.lastChild.append(...actions);
    return item;
  }

  async function showPasskeys() {
    await visit("passkeys", async () => {
      const answer = await api("GET", "/api/passkeys");
      closeRename(); // home again, before the row it may be in goes
      const list = $("passkey-list");
      list.replaceChildren();
      for (const passkey of answer.passkeys) {
        const transports = passkey.transports.length ? ", " + passkey.transports.join(" ") : "";
        const item = row(passkey.name_shown, "Fingerprint " + passkey.fingerprint + "; works on " +
          passkey.rp_id + ", " + passkey.alg + transports + "; enrolled " + VIA[passkey.via] +
          " on " + passkey.origin + " at " + when(passkey.created) + "; last used " +
          (passkey.last_used === null ? "never" :
            new Date(passkey.last_used * 1000).toLocaleDateString()) + ".",
        [tag(passkey.synced ? "Synced" : "Device-bound")].concat(
          passkey.this ? [tag("This session", "z-tag--current")] : []), [
          button("Rename", () => openRename(passkey, item)),
          button("Remove", () => prepare("passkey.remove", { credential: passkey.fingerprint },
            afterRemove), "z-btn--danger"),
        ]);
        list.append(item);
      }
    });
  }

  // The rename form opens in the passkey's own row (the design system's RowEditor).
  function openRename(passkey, item) {
    closeRename();
    renaming = passkey.fingerprint;
    $("rename-which").textContent = "Rename " + passkey.name_shown + " (" + passkey.fingerprint + ")";
    $("rename-name").value = "";
    item.classList.add("z-list__item--editing");
    item.append($("rename"));
    $("rename").hidden = false;
    $("rename-name").focus();
  }

  function closeRename() {
    renaming = null;
    const editing = $("rename").closest("li");
    if (editing) editing.classList.remove("z-list__item--editing");
    $("passkey-list").after($("rename"));
    $("rename").hidden = true;
  }

  function prepareRename() {
    prepare("passkey.rename", { credential: renaming, name: $("rename-name").value }, afterRename);
  }

  function prepareEnrol() {
    prepare("passkey.enrol", { name: $("passkey-name").value }, afterEnrolConfirmed);
  }

  async function afterRename() {
    closeConfirm();
    await showPasskeys();
    $("status").textContent = "Passkey renamed.";
  }

  async function afterRemove(result) {
    closeConfirm();
    if (result.signed_out) {
      // This session was made with the passkey removed, so it ended with it (F.2).
      sessionStorage.removeItem(TOKEN);
      showLogin();
      $("status").textContent = "Passkey removed. This session used it, so sign in again.";
      return;
    }
    await showPasskeys();
    $("status").textContent =
      "Passkey removed; " + result.sessions_ended + " session(s) ended with it.";
  }

  // passkey.enrol's run begins an enrolment: the new passkey is created from a second click,
  // so each passkey prompt opens from a click of its own.
  function afterEnrolConfirmed(result) {
    creating = result;
    $("confirm-expires").textContent =
      "Confirmed. Now create the new passkey with the authenticator it will live on.";
    $("confirm-create").hidden = false;
  }

  async function createPasskey() {
    const begun = creating;
    if (begun === null) {
      return;
    }
    confirmError("");
    try {
      const credential = await zoeyWebAuthn.create(begun.options);
      creating = null; // the finish spends the ceremony, whatever it answers
      $("confirm-create").hidden = true;
      const done = await api("POST", "/api/passkeys/enrol/finish",
        { ceremony: begun.ceremony, credential: credential });
      closeConfirm();
      $("passkey-name").value = "";
      await showPasskeys();
      $("status").textContent =
        "Passkey enrolled. Its fingerprint is " + done.passkey.fingerprint + ".";
    } catch (error) {
      if (signedOut(error)) {
        return afterFailure(error);
      }
      confirmError(textOf(error));
    }
  }

  // --- secrets (G): names and metadata only; a value is entered, never shown ------------------

  // From a health action, the name its finding is about goes in the name field.
  async function showSecrets(name) {
    if (typeof name === "string") {
      $("secret-name").value = name;
    }
    await visit("secrets", async () => {
      const answer = await api("GET", "/api/secrets");
      const list = $("secret-list");
      list.replaceChildren();
      for (const secret of answer.secrets) {
        list.append(row(secret.name_shown, secret.binding_shown + "; set " + secret.created +
          ", last replaced " + secret.updated + ", under key " + secret.key_id +
          (secret.live_slot ? "; the vault keeps a credential's live token here" : "") +
          (secret.health_shown === null ? "" : "; health: " + secret.health_shown) + ".", [],
        secret.live_slot ? [] : [
          button("Replace", () => replaceSecret(secret)),
          button("Delete",
            () => prepare("secret.delete", { name: secret.name }, afterSecretDeleted),
            "z-btn--danger"),
        ]));
      }
      if (answer.secrets.length === 0) {
        list.append(make("li", "z-list__empty", "No secrets are stored yet."));
      }
    });
  }

  function replaceSecret(secret) {
    $("secret-name").value = secret.name;
    $("secret-value").value = "";
    $("secret-origins").value = "";
    $("secret-value").focus();
  }

  // The origins field, as a list, or nothing when it is empty (JSON leaves undefined out).
  function originsGiven() {
    const words = $("secret-origins").value.split(/[\s,]+/).filter((word) => word !== "");
    return words.length ? words : undefined;
  }

  // The value goes into the prepare's body, and the field is emptied as soon as that request
  // is made: whatever the vault answers, the page no longer holds it (G).
  async function prepareSecret() {
    const sent = prepare(
      "secret.put",
      { name: $("secret-name").value, value: $("secret-value").value, origins: originsGiven() },
      afterSecretSet
    );
    $("secret-value").value = "";
    await sent;
  }

  async function afterSecretSet(result) {
    closeConfirm();
    $("secret-name").value = "";
    $("secret-origins").value = "";
    await showSecrets();
    const secret = result.secret;
    $("status").textContent =
      secret === null ? "Secret stored." : "Secret stored, " + secret.binding_shown + ".";
  }

  async function afterSecretDeleted() {
    closeConfirm();
    await showSecrets();
    $("status").textContent = "Secret deleted.";
  }

  // --- the ledger (J.5) and the policy (L): the vault words every line ------------------------

  // Each item's text, with the lines the vault made for it below (the stylesheet keeps the line
  // breaks), and its button, if any.
  function renderLines(list, items, control) {
    list.replaceChildren();
    for (const item of items) {
      const entry = make("li", "z-log__entry",
        [item.text_shown].concat(item.lines_shown || []).join("\n"));
      entry.append(control ? control(item) : "");
      list.append(entry);
    }
  }

  // The live chain's newest rows, or an archived chain's (its name), or the rows below a seq.
  async function showLedger(archive, before) {
    const query = new URLSearchParams(typeof archive === "string" ? { archive: archive } : {});
    if (before !== undefined) {
      query.set("before", before);
    }
    await visit("ledger", async () => {
      const page = await api("GET", "/api/ledger" + (String(query) && "?" + query));
      $("ledger-state").textContent =
        (page.archive === null ? "" : "Archived chain " + page.archive + ". ") + page.state_shown;
      $("ledger-restart").hidden = !page.restartable;
      $("ledger-older").hidden = page.next === null;
      older = { archive: page.archive === null ? undefined : page.archive, before: page.next };
      renderLines($("ledger-rows"), page.rows);
      renderLines($("ledger-orphans"), page.orphans);
      renderLines($("ledger-vault-only"), page.vault_only);
      renderLines($("ledger-archives"), page.archives,
        (epoch) => epoch.dropped ? "" : button("Show its rows", () => showLedger(epoch.name)));
    });
  }

  async function afterRestart() {
    closeConfirm();
    await showLedger();
    $("status").textContent = "Chain restarted: the gateway's next report starts a new one.";
  }

  async function showPolicy() {
    await visit("policy", async () => {
      const answer = await api("GET", "/api/policy");
      $("policy-source").textContent = answer.source_shown;
      $("policy-hidden").textContent = answer.hidden.length === 0 ? "" :
        "Shown only as set, never their values: " + answer.hidden.join(", ") + ".";
      $("policy-text").textContent = JSON.stringify(answer.policy, null, 2);
    });
  }

  // --- step-up (F.4) --------------------------------------------------------------------------

  // Prepare: the vault checks everything now and answers what it will do, before any prompt.
  async function prepare(kind, data, done) {
    clearError();
    try {
      openConfirm(await api("POST", "/api/actions", { kind: kind, data: data }), done, "");
    } catch (error) {
      afterFailure(error);
    }
  }

  // ``working`` is what the dialog says while a slow confirm runs (an exchange: up to 76 s);
  // ``data`` is a connect's, for when the callback took its sign-in meanwhile.
  function openConfirm(prepared, done, working, data) {
    pending = { action: prepared.action, options: prepared.options, done: done, working: working,
      data: data };
    creating = null;
    renderSummary("confirm-summary", prepared.summary);
    renderSummary("confirm-now", []);
    $("confirm-now-label").hidden = true;
    $("confirm-expires").textContent = "Confirm by " + when(prepared.expires) + ".";
    confirmError("");
    $("confirm-passkey").hidden = false;
    $("confirm-create").hidden = true;
    $("confirm").showModal();
  }

  function renderSummary(id, summary) {
    const list = $(id);
    list.replaceChildren();
    for (const pair of summary) {
      const term = document.createElement("dt");
      term.textContent = pair[0];
      const value = document.createElement("dd");
      value.textContent = pair[1];
      list.append(term, value);
    }
  }

  // Confirm: the assertion is bound to this action, session and origin, and the vault runs
  // what it held, after checking that nothing it showed has changed.
  async function confirmAction() {
    const held = pending;
    if (held === null) {
      return;
    }
    confirmError("");
    let credential;
    try {
      credential = await zoeyWebAuthn.get(held.options);
    } catch (error) {
      confirmError(textOf(error)); // still held: confirm again, or cancel
      return;
    }
    pending = null; // the confirm spends the action, whatever it answers
    $("confirm-passkey").hidden = true;
    if (held.working) {
      $("confirm-expires").textContent = held.working;
    }
    try {
      const result = await api(
        "POST",
        fill("/api/actions/{action}/confirm", { action: held.action }),
        { credential: credential }
      );
      await held.done(result);
    } catch (error) {
      if (signedOut(error)) {
        return afterFailure(error);
      }
      if (error.reason === "flow_returned" && held.data) {
        closeConfirm();
        return prepareConnect(held.data); // the vault answers it with the returned code's
      }
      if (error instanceof Refused && error.reason === "changed" && error.answer) {
        renderSummary("confirm-now", error.answer.now);
        $("confirm-now-label").hidden = false;
      }
      confirmError(textOf(error));
    }
  }

  async function cancelAction() {
    const held = pending;
    closeConfirm();
    if (held === null) {
      return;
    }
    await api("DELETE", fill("/api/actions/{action}", { action: held.action })).catch(afterFailure);
  }

  function closeConfirm() {
    pending = null;
    creating = null;
    if ($("confirm").open) {
      $("confirm").close();
    }
  }

  // --- start (K.2: the checks, in order, before any page) -------------------------------------

  function blocked() {
    const host = location.hostname;
    if (/^[0-9.]+$/.test(host) || host.indexOf(":") !== -1 || host.charAt(0) === "[") {
      return "ip_literal";
    }
    if (!window.isSecureContext) {
      return "insecure";
    }
    return zoeyWebAuthn.missing();
  }

  // Every button's click: while its handler runs, the button is disabled and a second click
  // does nothing, so a double click never sends a request twice. The handler is called within
  // the click itself, so a passkey prompt it opens still has the click's user activation.
  function guard(element, handler) {
    let busy = false;
    element.addEventListener("click", async function (event) {
      if (busy) {
        return;
      }
      busy = true;
      element.disabled = true;
      element.ariaBusy = "true";
      try {
        await handler(event);
      } finally {
        busy = false;
        element.disabled = false;
        element.ariaBusy = null;
      }
    });
  }

  function on(id, handler) {
    guard($(id), handler);
  }

  function start() {
    const problem = blocked();
    if (problem !== null) {
      $("blocked-text").textContent = BROWSER_TEXT[problem];
      show("blocked");
      return;
    }
    for (const link of document.querySelectorAll("a[data-doc]")) {
      link.href = DOCS + link.dataset.doc;
    }
    on("login-passkey", signIn);
    on("login-setup", function () {
      clearError();
      show("setup");
      step("setup-code-step");
    });
    on("setup-back", function () {
      clearError();
      showLogin();
    });
    on("setup-redeem", redeem);
    on("setup-enrol", enrol);
    on("setup-login", signIn);
    on("nav-home", enter);
    on("bar-health", enter);
    on("nav-credentials", showCredentials);
    on("nav-sessions", showSessions);
    on("nav-passkeys", showPasskeys);
    on("nav-secrets", showSecrets);
    on("nav-ledger", showLedger);
    on("nav-policy", showPolicy);
    on("ledger-older", () => showLedger(older.archive, older.before));
    on("ledger-restart", () => prepare("ledger.restart", {}, afterRestart));
    on("end-others", endOthers);
    on("passkey-enrol", prepareEnrol);
    on("rename-prepare", prepareRename);
    on("rename-close", closeRename);
    on("secret-prepare", prepareSecret);
    on("confirm-passkey", confirmAction);
    on("confirm-create", createPasskey);
    on("confirm-cancel", cancelAction);
    on("connect-check", checkPaste);
    on("connect-close", cancelConnect);
    on("connect-rebind", () => connect(connecting.credential, true));
    // Escape closes a dialog: the held action, or the pending sign-in, is dropped too.
    for (const [id, close] of [["confirm", cancelAction], ["connect", cancelConnect]]) {
      $(id).addEventListener("cancel", function (event) {
        event.preventDefault();
        close();
      });
    }
    on("sign-out", signOut);
    setInterval(poll, 2000);
    document.addEventListener("visibilitychange", poll);
    enter();
  }

  // What review.js shares (M7 K.4): the fetch wrapper, the step-up, Connect and the builders.
  window.zoeyPortal = Object.freeze({ api, fill, visit, fail, textOf, afterFailure, button, on,
    prepare, closeConfirm, renderSummary, connect, when });
  start();
})();
