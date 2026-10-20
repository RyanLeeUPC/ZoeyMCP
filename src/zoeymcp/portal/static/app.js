// The portal's page (M5 design K). It holds no decision: every rule is the vault's, and every
// text the vault sends is shown as it is, through textContent. It words only what the browser
// itself refuses. Every change is a fetch() with POST or DELETE and the session's header half,
// the one thing kept in sessionStorage (F.2). Passkey prompts open only from click handlers.
"use strict";

(function () {
  const TOKEN = "session";
  const HEADER = "X-ZoeyMCP-Session";
  const PAGES = ["blocked", "login", "setup", "home", "sessions"];
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

  function $(id) {
    return document.getElementById(id);
  }

  class Refused extends Error {
    constructor(text, reason, status) {
      super(text);
      this.reason = reason;
      this.status = status;
    }
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
    throw new Refused(text, reason, response.status);
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
      showLogin();
    }
    fail(textOf(error));
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

  function on(id, handler) {
    $(id).addEventListener("click", handler);
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
    on("end-others", endOthers);
    on("sign-out", signOut);
    enter();
  }

  start();
})();
