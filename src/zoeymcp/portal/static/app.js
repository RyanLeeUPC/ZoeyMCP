// The portal's page (M5 design K). It holds no decision: every rule is the vault's, and every
// text the vault sends is shown as it is, through textContent. It words only what the browser
// itself refuses. Every change is a fetch() with POST or DELETE and the session's header half,
// the one thing kept in sessionStorage (F.2). Passkey prompts open only from click handlers.
// A full session changes things only through actions (F.4): prepare, show the vault's summary,
// then confirm with a passkey.
"use strict";

(function () {
  const TOKEN = "session";
  const HEADER = "X-ZoeyMCP-Session";
  const PAGES = ["blocked", "login", "setup", "home", "sessions", "passkeys"];
  const SETUP_STEPS = ["setup-code-step", "setup-name-step", "setup-done-step"];

  // What the browser refuses, worded here (M.2); the vault words every other refusal.
  const BROWSER_TEXT = {
    ip_literal:
      "Passkeys don't work on IP addresses. Open the portal at the name listed in " +
      "admin.origins, such as localhost with its port.",
    insecure:
      "This page isn't a secure context, so the browser won't use passkeys here. Use " +
      "localhost, or https with a certificate this browser trusts.",
    no_webauthn:
      "This browser doesn't support passkeys. Use a current Chrome, Edge, Firefox or Safari.",
    no_get_public_key:
      "This browser can't hand the vault a new passkey's key. Update it, or use another browser.",
    NotAllowedError:
      "The passkey prompt was cancelled or timed out, or no passkey for this address was " +
      "chosen. Try again.",
    InvalidStateError:
      "This authenticator already holds a passkey enrolled here. Use another authenticator, or " +
      "a setup code issued with --reset to replace it.",
    SecurityError:
      "The browser refused a passkey on this address. Open the portal at an address listed in " +
      "admin.origins.",
    NotSupportedError:
      "This authenticator supports none of the vault's key types (ES256, Ed25519, RS256).",
    network: "The vault didn't answer. Check that it is running, then try again.",
  };
  const PROMPT_ERRORS = [
    "NotAllowedError",
    "InvalidStateError",
    "SecurityError",
    "NotSupportedError",
  ];
  const VIA = {
    setup_code: "with a setup code",
    setup_code_reset: "with a reset setup code",
    portal: "from a signed-in session",
  };

  let pending = null; // the action being confirmed: its ID, step-up options and what follows
  let creating = null; // a confirmed passkey.enrol's ceremony, until the passkey is created
  let renaming = null; // the fingerprint the rename form is for

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
    return template.replace(/\{([a-z]+)\}/g, function (match, name) {
      return encodeURIComponent(values[name]);
    });
  }

  // --- the API --------------------------------------------------------------------------------

  async function api(method, path, body) {
    const headers = {};
    const saved = sessionStorage.getItem(TOKEN);
    if (saved !== null) {
      headers[HEADER] = saved;
    }
    const init = {
      method: method,
      headers: headers,
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
    };
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
    let answer = null;
    try {
      answer = await response.json();
    } catch (error) {
      answer = null;
    }
    if (response.ok) {
      return answer;
    }
    const reason = answer && typeof answer.reason === "string" ? answer.reason : "";
    const text =
      answer && typeof answer.error === "string"
        ? answer.error
        : "The vault refused that (HTTP " + response.status + ").";
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
    for (const id of PAGES) {
      $(id).hidden = id !== page;
    }
    $("status").textContent = "";
  }

  function step(id) {
    for (const other of SETUP_STEPS) {
      $(other).hidden = other !== id;
    }
  }

  function fail(text) {
    $("error").textContent = text;
    $("error").hidden = false;
  }

  function clearError() {
    $("error").textContent = "";
    $("error").hidden = true;
  }

  function when(seconds) {
    return new Date(seconds * 1000).toLocaleString();
  }

  function renderBar(session) {
    $("bar").hidden = session.scope !== "full";
    $("bar-origin").textContent = session.origin;
    const name = session.credential_name_shown;
    $("bar-passkey").textContent =
      session.credential === null ? "" : "Passkey " + (name === null ? "" : name + " ") +
        "(" + session.credential + ")";
    $("bar-ends").textContent =
      "Session ends by " + when(session.expires_at) + ", or after 15 idle minutes";
  }

  function renderBanners(banners) {
    const list = $("banners");
    list.replaceChildren();
    for (const banner of banners) {
      const item = document.createElement("li");
      item.textContent = banner.text;
      item.className = "banner";
      list.append(item);
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
    show("home");
  }

  // --- login and setup (E, F.2) ---------------------------------------------------------------

  async function signIn() {
    clearError();
    try {
      const begun = await api("POST", "/api/login/begin", {});
      const credential = await zoeyWebAuthn.get(begun.options);
      const minted = await api("POST", "/api/login/finish", {
        ceremony: begun.ceremony,
        credential: credential,
      });
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
      const done = await api("POST", "/api/passkeys/enrol/finish", {
        ceremony: begun.ceremony,
        credential: credential,
      });
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
    clearError();
    try {
      const answer = await api("GET", "/api/sessions");
      const list = $("session-list");
      list.replaceChildren();
      for (const session of answer.sessions) {
        const item = document.createElement("li");
        const by = session.credential === null ? "a setup code" : "passkey " + session.credential;
        item.textContent =
          session.fingerprint + (session.this ? " (this browser)" : "") + ": " + session.origin +
          ", signed in with " + by + " at " + when(session.created) + ", last used " +
          when(session.last_seen);
        list.append(item);
      }
      show("sessions");
    } catch (error) {
      afterFailure(error);
    }
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

  function day(seconds) {
    return new Date(seconds * 1000).toLocaleDateString();
  }

  function button(label, handler) {
    const element = document.createElement("button");
    element.type = "button";
    element.textContent = label;
    guard(element, handler);
    return element;
  }

  async function showPasskeys() {
    clearError();
    try {
      const answer = await api("GET", "/api/passkeys");
      const list = $("passkey-list");
      list.replaceChildren();
      for (const passkey of answer.passkeys) {
        const item = document.createElement("li");
        const text = document.createElement("span");
        const transports = passkey.transports.length ? ", " + passkey.transports.join(" ") : "";
        text.textContent =
          passkey.name_shown + " (" + passkey.fingerprint + ")" +
          (passkey.this ? ", signed in this session" : "") + ": works on " + passkey.rp_id +
          ", " + passkey.alg + ", " + (passkey.synced ? "synced" : "device-bound") + transports +
          "; enrolled " + VIA[passkey.via] + " on " + passkey.origin + " at " +
          when(passkey.created) + "; last used " +
          (passkey.last_used === null ? "never" : day(passkey.last_used)) + ".";
        item.append(
          text,
          button("Rename", function () {
            openRename(passkey);
          }),
          button("Remove", function () {
            prepare("passkey.remove", { credential: passkey.fingerprint }, afterRemove);
          })
        );
        list.append(item);
      }
      closeRename();
      show("passkeys");
    } catch (error) {
      afterFailure(error);
    }
  }

  function openRename(passkey) {
    renaming = passkey.fingerprint;
    $("rename-which").textContent = "Rename " + passkey.name_shown + " (" + passkey.fingerprint + ")";
    $("rename-name").value = "";
    $("rename").hidden = false;
  }

  function closeRename() {
    renaming = null;
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
      const done = await api("POST", "/api/passkeys/enrol/finish", {
        ceremony: begun.ceremony,
        credential: credential,
      });
      closeConfirm();
      $("passkey-name").value = "";
      await showPasskeys();
      $("status").textContent =
        "Passkey enrolled. Its fingerprint is " + done.passkey.fingerprint + ".";
    } catch (error) {
      if (signedOut(error)) {
        afterFailure(error);
        return;
      }
      confirmError(textOf(error));
    }
  }

  // --- step-up (F.4) --------------------------------------------------------------------------

  // Prepare: the vault checks everything now and answers what it will do, before any prompt.
  async function prepare(kind, data, done) {
    clearError();
    try {
      const prepared = await api("POST", "/api/actions", { kind: kind, data: data });
      pending = { action: prepared.action, options: prepared.options, done: done };
      creating = null;
      renderSummary("confirm-summary", prepared.summary);
      renderSummary("confirm-now", []);
      $("confirm-now-label").hidden = true;
      $("confirm-expires").textContent = "Confirm by " + when(prepared.expires) + ".";
      confirmError("");
      $("confirm-passkey").hidden = false;
      $("confirm-create").hidden = true;
      $("confirm").showModal();
    } catch (error) {
      afterFailure(error);
    }
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

  function confirmError(text) {
    $("confirm-error").textContent = text;
    $("confirm-error").hidden = text === "";
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
    try {
      const result = await api(
        "POST",
        fill("/api/actions/{action}/confirm", { action: held.action }),
        { credential: credential }
      );
      await held.done(result);
    } catch (error) {
      if (signedOut(error)) {
        afterFailure(error);
        return;
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
    try {
      await api("DELETE", fill("/api/actions/{action}", { action: held.action }));
    } catch (error) {
      afterFailure(error);
    }
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
      try {
        await handler(event);
      } finally {
        busy = false;
        element.disabled = false;
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
    on("nav-sessions", showSessions);
    on("nav-passkeys", showPasskeys);
    on("end-others", endOthers);
    on("passkey-enrol", prepareEnrol);
    on("rename-prepare", prepareRename);
    on("rename-close", closeRename);
    on("confirm-passkey", confirmAction);
    on("confirm-create", createPasskey);
    on("confirm-cancel", cancelAction);
    // Escape closes the dialog: the held action is dropped too.
    $("confirm").addEventListener("cancel", function (event) {
      event.preventDefault();
      cancelAction();
    });
    on("sign-out", signOut);
    enter();
  }

  start();
})();
