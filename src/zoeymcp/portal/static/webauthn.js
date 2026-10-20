// The passkey ceremonies, as the vault builds them (M5 design D.1). The vault sends the options
// with binary fields in base64url; this turns those into ArrayBuffers, calls the browser, and
// posts back the raw fields, base64url-encoded, parsing none of them. Every check is the vault's.
"use strict";

(function () {
  function fromBase64url(text) {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "===".slice((base64.length + 3) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function toBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function descriptors(list) {
    return list.map(function (descriptor) {
      return Object.assign({}, descriptor, { id: fromBase64url(descriptor.id) });
    });
  }

  // What the browser needs before any ceremony (K.2); each failure is shown by the page.
  function missing() {
    if (!window.PublicKeyCredential) {
      return "no_webauthn";
    }
    if (!("getPublicKey" in AuthenticatorAttestationResponse.prototype)) {
      return "no_get_public_key";
    }
    return null;
  }

  // navigator.credentials.create(), from a click handler only. Answers the registration fields.
  async function create(options) {
    const publicKey = Object.assign({}, options, {
      challenge: fromBase64url(options.challenge),
      user: Object.assign({}, options.user, { id: fromBase64url(options.user.id) }),
      excludeCredentials: descriptors(options.excludeCredentials),
    });
    const credential = await navigator.credentials.create({ publicKey: publicKey });
    const response = credential.response;
    const key = response.getPublicKey();
    return {
      id: toBase64url(credential.rawId),
      client_data_json: toBase64url(response.clientDataJSON),
      authenticator_data: toBase64url(response.getAuthenticatorData()),
      public_key: key === null ? null : toBase64url(key),
      public_key_algorithm: response.getPublicKeyAlgorithm(),
      transports: typeof response.getTransports === "function" ? response.getTransports() : [],
    };
  }

  // navigator.credentials.get(), from a click handler only. Answers the assertion fields.
  async function get(options) {
    const publicKey = Object.assign({}, options, {
      challenge: fromBase64url(options.challenge),
      allowCredentials: descriptors(options.allowCredentials),
    });
    const credential = await navigator.credentials.get({ publicKey: publicKey });
    const response = credential.response;
    const handle = response.userHandle;
    return {
      id: toBase64url(credential.rawId),
      client_data_json: toBase64url(response.clientDataJSON),
      authenticator_data: toBase64url(response.authenticatorData),
      signature: toBase64url(response.signature),
      user_handle: handle === null || handle === undefined ? null : toBase64url(handle),
    };
  }

  window.zoeyWebAuthn = Object.freeze({ missing: missing, create: create, get: get });
})();
