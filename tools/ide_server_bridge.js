/* ide_server_bridge.js -- injected by tools/gen_ide_assets.py directly before
 * </body> in the VENDORED PicoScript WebIDE (../picoscript/docs/index.html,
 * built by that repo's gen_site.py). This file is the ONLY place that wires
 * the real, upstream WebIDE to a running picoweb instance -- the vendored
 * HTML/CSS/JS above it is never hand-edited, so upstream regenerates
 * (`python3 ../picoscript/gen_site.py`) always drop in cleanly.
 *
 * Responsibilities (see AGENTS/README "Hosted PicoScript IDE"):
 *   1. Load /ide/config and point the WebIDE's own "live server" concept at
 *      this picoweb instance's /wal/ API by default (hosted mode is LIVE,
 *      not the upstream localStorage simulator).
 *   2. Wrap the upstream `liveFetch()` so every live-mode request carries
 *      credentials + X-PW-Auth + a JSON content-type default, matching the
 *      auth contract every other picoweb write path already uses.
 *   3. Replace `schemaPushLive()` with a version that translates the WebIDE's
 *      simple {fields:[{name,type,...}]} schema model into picoweal_validate.c's
 *      server-native CSV/assignment-map shape (fields/required/nullable/
 *      readonly/types/max_lengths/joins/...), instead of the upstream
 *      "no translation needed" assumption (which only holds for a bespoke
 *      native engine, not picoweb).
 *   4. Add a compact PicoSTS login/logout/status control into the portal's
 *      existing topbar (Authorization Code + PKCE, reusing /wal/auth/*).
 *   5. Add Deploy controls (save source, deploy bytecode, publish static)
 *      into the WebIDE's existing Compile & Run/Step/Reset controls row.
 *   6. Add a first-class "PicoWAL" portal tab. Its same-origin iframe fills
 *      the main portal view and suppresses duplicate chrome; authentication
 *      and navigation remain owned by this one shell.
 *
 * Everything here is defensive: if a hook the upstream page is expected to
 * expose (liveFetch, liveServerSet, schemaPushLive, filesStatus, getSrc,
 * ACTIVE_FILE, DBG, showView, ...) is missing (e.g. after an unrelated
 * upstream refactor), the corresponding feature degrades to a no-op/alert
 * instead of throwing and breaking the rest of the page. */
(function () {
  "use strict";

  var PWB = { config: null, authed: false, principal: null };
  window.PicoWebBridge = PWB;

  /* ---------- small DOM helpers ---------- */
  function byId(id) { return document.getElementById(id); }
  function mk(tag, cls, text) {
    var el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  /* ---------- 1. config ---------- */
  function loadConfig() {
    return fetch("config", { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("config fetch failed: " + r.status); return r.json(); })
      .then(function (c) { PWB.config = c; return c; })
      .catch(function (e) { PWB.configError = e.message; return null; });
  }

  /* ---------- 2. live server: hosted mode defaults to same-origin /wal ----------
   * The upstream WebIDE already speaks exactly the shape picoweb exposes
   * (liveFetch('/list/'+pid), liveFetch('/'+pid), liveFetch('/schema/'+pid))
   * -- it just needs liveServerUrl() to resolve to this instance's --wal
   * route instead of an operator-typed arbitrary URL. The offline
   * localStorage simulator remains available as an explicit opt-in toggle
   * (see buildOfflineToggle below), never the hosted default. */
  var SIM_KEY = "picoweb.bridge.offlineSimulator";
  function simulatorForced() {
    try { return window.localStorage.getItem(SIM_KEY) === "1"; } catch (e) { return false; }
  }
  function setSimulatorForced(on) {
    try {
      if (on) window.localStorage.setItem(SIM_KEY, "1");
      else window.localStorage.removeItem(SIM_KEY);
    } catch (e) { /* ignore */ }
  }
  function applyLiveServer() {
    if (typeof window.liveServerSet !== "function") return;
    if (simulatorForced()) { window.liveServerSet(""); return; }
    var wal = (PWB.config && PWB.config.wal_prefix) || "/wal/";
    window.liveServerSet(wal.replace(/\/+$/, ""));
  }

  /* ---------- 3. liveFetch: credentials + X-PW-Auth + JSON headers ---------- */
  function installLiveFetch() {
    window.liveFetch = function (path, opts) {
      opts = opts || {};
      var headers = { "X-PW-Auth": "1" };
      var hasBody = opts.body !== undefined && opts.body !== null;
      if (hasBody) {
        var bodyIsJsonish = typeof opts.body === "string" && /^\s*[{\[]/.test(opts.body);
        headers["Content-Type"] = bodyIsJsonish ? "application/json" : "text/plain";
      }
      var k;
      for (k in (opts.headers || {})) headers[k] = opts.headers[k];
      var merged = {};
      for (k in opts) merged[k] = opts[k];
      merged.headers = headers;
      merged.credentials = "include";
      return fetch((typeof liveServerUrl === "function" ? liveServerUrl() : "") + path, merged);
    };
  }

  /* ---------- 4. schemaPushLive: translate to picowal_validate.c's shape ----------
   * Upstream field model: {fields:[{name,type,required,nullable,readonly,
   * maxLength,label,placeholder,lookupPack,lookupLabel,...}]} (the extra
   * per-field keys beyond name/type are only ever present if a field was
   * hand-authored via the "{ } JSON" modal -- the visual designer only ever
   * sets name/type -- so we read them opportunistically and preserve
   * anything else on the top-level document verbatim). Server-native shape
   * (see src/picowal_validate.c): fields/required/nullable/readonly/children
   * are comma-CSV; types/max_lengths/lookup_labels/field_labels/
   * field_placeholders are ';'-separated field=value assignments; joins is
   * a comma list of targetPack=fkField tokens. */
  var WEBIDE_TYPE_TO_SERVER = {
    "int": "number", "str": "string", "bool": "bool",
    "uint8": "uint8", "uint16": "uint16", "uint32": "uint32",
    "int16": "int16", "int32": "int32",
    "utf8": "utf8", "latin1": "ascii", "blob": "blob"
  };
  function serverTypeFor(t) {
    if (Object.prototype.hasOwnProperty.call(WEBIDE_TYPE_TO_SERVER, t)) return WEBIDE_TYPE_TO_SERVER[t];
    return t || "string"; /* already a server-native type name (e.g. hand-authored "lookup"/"decimal") */
  }
  function assignJoin(map) {
    return Object.keys(map)
      .filter(function (k) { return map[k] !== undefined && map[k] !== null && map[k] !== ""; })
      .map(function (k) { return k + "=" + map[k]; }).join(";");
  }
  PWB.transformSchemaToServerNative = function (doc) {
    var fields = (doc && Array.isArray(doc.fields)) ? doc.fields : [];
    var out = {};
    /* Preserve any top-level keys the WebIDE (or a hand-edit) already put
     * here beyond the plain field list, e.g. module/children/list_columns
     * if a previous save round-tripped through the PicoWAL workspace. */
    Object.keys(doc || {}).forEach(function (k) { if (k !== "fields") out[k] = doc[k]; });

    out.fields = fields.map(function (f) { return f.name; }).join(",");
    var required = fields.filter(function (f) { return f.required; }).map(function (f) { return f.name; });
    if (required.length) out.required = required.join(","); else delete out.required;
    var nullable = fields.filter(function (f) { return f.nullable; }).map(function (f) { return f.name; });
    if (nullable.length) out.nullable = nullable.join(","); else delete out.nullable;
    var readonly = fields.filter(function (f) { return f.readonly; }).map(function (f) { return f.name; });
    if (readonly.length) out.readonly = readonly.join(","); else delete out.readonly;
    var email = fields.filter(function (f) { return f.email; }).map(function (f) { return f.name; });
    if (email.length) out.email = email.join(","); else delete out.email;

    var types = {}; fields.forEach(function (f) { types[f.name] = serverTypeFor(f.type); });
    out.types = assignJoin(types) || undefined; if (!out.types) delete out.types;

    var maxLengths = {}; fields.forEach(function (f) { if (f.maxLength) maxLengths[f.name] = f.maxLength; });
    var maxLenStr = assignJoin(maxLengths); if (maxLenStr) out.max_lengths = maxLenStr; else delete out.max_lengths;

    var regex = {}; fields.forEach(function (f) { if (f.regex) regex[f.name] = f.regex; });
    var regexStr = assignJoin(regex); if (regexStr) out.regex = regexStr; else delete out.regex;

    var transitions = {}; fields.forEach(function (f) { if (f.transitions) transitions[f.name] = f.transitions; });
    var transStr = assignJoin(transitions); if (transStr) out.transitions = transStr; else delete out.transitions;

    var lookupLabels = {};
    fields.forEach(function (f) { if (f.lookupLabel) lookupLabels[f.name] = f.lookupLabel; });
    var llStr = assignJoin(lookupLabels); if (llStr) out.lookup_labels = llStr; else delete out.lookup_labels;

    /* joins: "targetPack=fkField,..." -- either an explicit f.join={pack,field}
     * (rich hand-authored metadata) or f.lookupPack (the field itself is the
     * FK, common case for a "lookup" typed field). */
    var joinTokens = [];
    fields.forEach(function (f) {
      if (f.join && f.join.pack !== undefined && f.join.pack !== null && f.join.pack !== "") {
        joinTokens.push(f.join.pack + "=" + (f.join.field || f.name));
      } else if (f.lookupPack !== undefined && f.lookupPack !== null && f.lookupPack !== "") {
        joinTokens.push(f.lookupPack + "=" + f.name);
      } else if (f.type === "lookup" && f.targetPack !== undefined && f.targetPack !== null && f.targetPack !== "") {
        joinTokens.push(f.targetPack + "=" + f.name);
      }
    });
    if (joinTokens.length) out.joins = joinTokens.join(","); else delete out.joins;

    return out;
  };

  function installSchemaPushLive() {
    if (typeof window.schemaPushLive !== "function") return; /* upstream changed shape -- degrade silently */
    window.schemaPushLive = function () {
      var url = (typeof liveServerUrl === "function") ? liveServerUrl() : "";
      if (!url) {
        if (typeof alert === "function") alert("No live server configured -- disable the offline simulator toggle first.");
        return;
      }
      var m = /^schemas\/(.+)\.schema\.json$/.exec(window.ACTIVE_FILE || "");
      if (!m) { if (typeof alert === "function") alert("Save this as schemas/<pack>.schema.json first."); return; }
      var doc;
      try { doc = JSON.parse(typeof getSrc === "function" ? getSrc() : "{}"); }
      catch (e) { if (typeof alert === "function") alert("invalid schema JSON: " + e.message); return; }
      var pid = (typeof packNameToId === "function") ? packNameToId(m[1]) : 0;
      var serverDoc = PWB.transformSchemaToServerNative(doc);
      liveFetch("/schema/" + pid, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(serverDoc)
      }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        if (typeof filesStatus === "function") {
          filesStatus("Pushed schema for \"" + m[1] + "\" to live server (pack " + pid + ", server-native format)");
        }
      }).catch(function (e) {
        if (typeof filesStatus === "function") filesStatus("Push failed: " + e.message, true);
      });
    };
  }

  /* ---------- offline simulator toggle (explicit opt-in only) ---------- */
  function buildOfflineToggle() {
    var bar = byId("liveServerBar");
    if (!bar || byId("pwbridge-sim-toggle")) return;
    var label = mk("label", "small", "");
    label.style.cssText = "display:inline-flex;align-items:center;gap:4px;margin-left:8px;cursor:pointer";
    var cb = document.createElement("input");
    cb.type = "checkbox";
    cb.id = "pwbridge-sim-toggle";
    cb.checked = simulatorForced();
    cb.addEventListener("change", function () {
      setSimulatorForced(cb.checked);
      applyLiveServer();
      if (typeof liveServerRenderStatus === "function") liveServerRenderStatus();
    });
    label.appendChild(cb);
    label.appendChild(document.createTextNode(" offline simulator (default is live picowal)"));
    bar.appendChild(label);
  }

  /* ---------- 5. PicoSTS login/logout/status in the portal topbar ---------- */
  function b64urlFromBytes(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function randomString(len) {
    var arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return b64urlFromBytes(arr);
  }
  function sha256(str) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(str)).then(function (buf) { return new Uint8Array(buf); });
  }
  function currentUrlNoQuery() { return location.origin + location.pathname; }

  var authWidget = null;
  function buildAuthWidget() {
    var topbar = document.querySelector(".topbar");
    if (!topbar || byId("pwbridge-auth")) return;
    var wrap = mk("div", "pwbridge-auth");
    wrap.id = "pwbridge-auth";
    wrap.style.cssText = "display:flex;align-items:center;gap:8px;margin-left:10px;font-size:12px;color:var(--muted)";
    var status = mk("span", "", "not signed in");
    status.id = "pwbridge-principal";
    var loginBtn = mk("button", "ghost", "Login");
    loginBtn.id = "pwbridge-btn-login";
    var logoutBtn = mk("button", "ghost", "Logout");
    logoutBtn.id = "pwbridge-btn-logout";
    logoutBtn.style.display = "none";
    wrap.appendChild(status); wrap.appendChild(loginBtn); wrap.appendChild(logoutBtn);
    topbar.appendChild(wrap);
    authWidget = { status: status, loginBtn: loginBtn, logoutBtn: logoutBtn };

    loginBtn.addEventListener("click", function () {
      var c = PWB.config;
      if (!c || !c.picosts_enabled) { alert("PicoSTS is not configured on this picoweb instance."); return; }
      var verifier = randomString(64);
      var state = randomString(24);
      sessionStorage.setItem("picoide_pkce_verifier", verifier);
      sessionStorage.setItem("picoide_pkce_state", state);
      sha256(verifier).then(function (digest) {
        var challenge = b64urlFromBytes(digest);
        var u = new URL(c.picosts_issuer + "/authorize");
        u.searchParams.set("response_type", "code");
        u.searchParams.set("client_id", c.picosts_client_id);
        u.searchParams.set("redirect_uri", currentUrlNoQuery());
        u.searchParams.set("scope", "openid");
        u.searchParams.set("code_challenge", challenge);
        u.searchParams.set("code_challenge_method", "S256");
        u.searchParams.set("state", state);
        location.href = u.toString();
      });
    });
    logoutBtn.addEventListener("click", function () {
      var c = PWB.config;
      if (!c) return;
      fetch(c.wal_prefix + "auth/logout", { method: "POST", credentials: "include", headers: { "X-PW-Auth": "1" } })
        .then(refreshMe);
    });
  }

  function refreshMe() {
    var c = PWB.config;
    if (!c || !authWidget) return Promise.resolve();
    return fetch(c.wal_prefix + "auth/me", { credentials: "include", headers: { "X-PW-Auth": "1" } })
      .then(function (r) {
        if (r.ok) {
          return r.json().then(function (j) {
            PWB.authed = true; PWB.principal = j.principal;
            authWidget.status.textContent = "signed in as " + j.principal;
            authWidget.loginBtn.style.display = "none";
            authWidget.logoutBtn.style.display = "";
            notifyPicowalAuth();
          });
        }
        PWB.authed = false; PWB.principal = null;
        authWidget.status.textContent = "not signed in";
        authWidget.loginBtn.style.display = "";
        authWidget.logoutBtn.style.display = "none";
        notifyPicowalAuth();
      }).catch(function () { /* transient network error -- keep last known state */ });
  }

  function exchangeCodeForToken(code) {
    var c = PWB.config;
    var verifier = sessionStorage.getItem("picoide_pkce_verifier");
    var body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", currentUrlNoQuery());
    body.set("client_id", c.picosts_client_id);
    body.set("code_verifier", verifier);
    return fetch(c.picosts_issuer + "/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }).then(function (r) {
      if (!r.ok) throw new Error("token exchange failed: " + r.status);
      return r.json();
    }).then(function (tok) {
      return fetch(c.wal_prefix + "auth/login", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-PW-Auth": "1" },
        body: JSON.stringify({ provider: "picosts", access_token: tok.access_token })
      });
    }).then(function (r) {
      if (!r.ok) throw new Error("picoweb login failed: " + r.status);
      history.replaceState(null, "", currentUrlNoQuery());
      return refreshMe();
    });
  }

  /* ---------- 6. deploy controls in the WebIDE's controls row ---------- */
  function packWordsLE(words) {
    var buf = new ArrayBuffer(words.length * 4);
    var view = new DataView(buf);
    for (var i = 0; i < words.length; i++) view.setUint32(i * 4, words[i] >>> 0, true);
    return new Uint8Array(buf);
  }
  function report(msg, isErr) {
    if (typeof filesStatus === "function") filesStatus(msg, isErr);
    else if (isErr) alert(msg); else if (typeof console !== "undefined") console.log(msg);
  }
  function pwbridgeSaveSource() {
    var c = PWB.config;
    if (!c) return;
    var pack = prompt("Save active source to picowal pack (raw card store):", window.localStorage.getItem("pwbridge.lastPack") || "0");
    if (pack === null) return;
    var record = prompt("record id:", window.localStorage.getItem("pwbridge.lastRecord") || "0");
    if (record === null) return;
    try { window.localStorage.setItem("pwbridge.lastPack", pack); window.localStorage.setItem("pwbridge.lastRecord", record); } catch (e) { /* ignore */ }
    fetch(c.ide_prefix + "card/" + pack + "/" + record, {
      method: "PUT", credentials: "include", headers: { "X-PW-Auth": "1" }, body: typeof getSrc === "function" ? getSrc() : ""
    }).then(function (r) { report(r.ok ? ("saved source to card " + pack + "/" + record + " (" + r.status + ")") : ("save failed (" + r.status + ")"), !r.ok); })
      .catch(function (e) { report(e.message, true); });
  }
  function pwbridgeLoadSource() {
    var c = PWB.config;
    if (!c) return;
    var pack = prompt("Load source from picowal pack:", window.localStorage.getItem("pwbridge.lastPack") || "0");
    if (pack === null) return;
    var record = prompt("record id:", window.localStorage.getItem("pwbridge.lastRecord") || "0");
    if (record === null) return;
    fetch(c.ide_prefix + "card/" + pack + "/" + record, { credentials: "include", headers: { "X-PW-Auth": "1" } })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); })
      .then(function (t) { if (typeof setSrc === "function") setSrc(t); report("loaded source from card " + pack + "/" + record); })
      .catch(function (e) { report(e.message, true); });
  }
  function pwbridgeDeployBytecode() {
    var c = PWB.config;
    if (!c) return;
    var words = window.DBG && window.DBG.words;
    if (!words || !words.length) { report("Compile first -- no bytecode to deploy", true); return; }
    fetch(c.code_prefix, { method: "PUT", credentials: "include", headers: { "X-PW-Auth": "1" }, body: packWordsLE(words) })
      .then(function (r) { report(r.ok ? ("deployed " + words.length + " words to " + c.code_prefix + " (" + r.status + ")") : ("deploy failed (" + r.status + ")"), !r.ok); })
      .catch(function (e) { report(e.message, true); });
  }
  function pwbridgePublishStatic() {
    var c = PWB.config;
    if (!c) return;
    var name = window.ACTIVE_FILE || "";
    var kind = (typeof fileKind === "function") ? fileKind(name) : "";
    if (kind !== "static") { report("Open/select a static file (Files sidebar) before publishing", true); return; }
    var record = prompt("Publish \"" + name + "\" to static record:", "0");
    if (record === null) return;
    var url = c.static_prefix + encodeURIComponent(record) + "/" + encodeURIComponent(name);
    fetch(url, { method: "PUT", credentials: "include", headers: { "X-PW-Auth": "1" }, body: typeof getSrc === "function" ? getSrc() : "" })
      .then(function (r) { report(r.ok ? ("published to " + url + " (" + r.status + ")") : ("publish failed (" + r.status + ")"), !r.ok); })
      .catch(function (e) { report(e.message, true); });
  }
  function buildDeployControls() {
    var controls = document.querySelector("#view-play .controls");
    if (!controls || byId("pwbridge-btn-save-source")) return;
    var sep = mk("span", "", "");
    sep.style.cssText = "width:1px;align-self:stretch;background:#2c313f;margin:0 4px";
    controls.appendChild(sep);
    var saveBtn = mk("button", "ghost", "Save Source");
    saveBtn.id = "pwbridge-btn-save-source";
    saveBtn.title = "PUT the active source to authenticated {ide_prefix}card/{pack}/{record}";
    saveBtn.addEventListener("click", pwbridgeSaveSource);
    var loadBtn = mk("button", "ghost", "Load Source");
    loadBtn.title = "GET the active source from authenticated {ide_prefix}card/{pack}/{record}";
    loadBtn.addEventListener("click", pwbridgeLoadSource);
    var deployBtn = mk("button", "act", "Deploy Bytecode");
    deployBtn.id = "pwbridge-btn-deploy";
    deployBtn.title = "PUT the last compiled bytecode to the configured --picowal-code-prefix";
    deployBtn.addEventListener("click", pwbridgeDeployBytecode);
    var pubBtn = mk("button", "ghost", "Publish Static");
    pubBtn.title = "PUT the active static file to the configured --picowal-static-prefix";
    pubBtn.addEventListener("click", pwbridgePublishStatic);
    [saveBtn, loadBtn, deployBtn, pubBtn].forEach(function (b) { controls.appendChild(b); });
  }

  /* ---------- 7. full-width PicoWAL tab inside the portal shell ---------- */
  var baseShowView = window.showView;
  function ensurePicowalView() {
    if (byId("view-picowal")) return;
    var main = document.querySelector(".main");
    if (!main) return;
    var view = mk("div", "view");
    view.id = "view-picowal";
    view.style.cssText = "padding:0;overflow:hidden";
    var iframe = document.createElement("iframe");
    iframe.id = "picowalFrame";
    iframe.title = "PicoWAL workspace";
    iframe.src = "picowal.html?embedded=1";
    iframe.style.cssText = "width:100%;height:100%;border:0;display:block;background:#16213e";
    iframe.addEventListener("load", notifyPicowalAuth);
    view.appendChild(iframe);
    main.appendChild(view);
  }
  function notifyPicowalAuth() {
    var frame = byId("picowalFrame");
    if (!frame || !frame.contentWindow) return;
    frame.contentWindow.postMessage({
      type: "picoweb-auth-state",
      authed: !!PWB.authed,
      principal: PWB.principal || null
    }, location.origin);
  }
  function installUnifiedShowView() {
    window.showView = function (v) {
      var tabBtn = byId("pwbridge-tab-picowal");
      if (v === "picowal") {
        ensurePicowalView();
        document.querySelectorAll(".view").forEach(function (e) { e.classList.remove("active"); });
        byId("view-picowal").classList.add("active");
        document.querySelectorAll(".tabs .tab").forEach(function (b) { b.classList.remove("active"); });
        if (tabBtn) tabBtn.classList.add("active");
        var triggers = byId("flyoutTriggers");
        if (triggers) triggers.style.display = "none";
        notifyPicowalAuth();
        return;
      }
      if (typeof baseShowView === "function") baseShowView(v);
      if (tabBtn) tabBtn.classList.remove("active");
    };
  }
  function buildPicowalTab() {
    var tabs = document.querySelector(".tabs");
    if (!tabs || byId("pwbridge-tab-picowal")) return;
    var btn = mk("button", "tab", "PicoWAL");
    btn.id = "pwbridge-tab-picowal";
    btn.title = "Open the full PicoWAL workspace";
    btn.addEventListener("click", function () { window.showView("picowal"); });
    tabs.appendChild(btn);
  }
  function labelAndOpenCodeEditor() {
    var tabs = document.querySelectorAll(".tabs .tab");
    for (var i = 0; i < tabs.length; i++) {
      if ((tabs[i].textContent || "").trim() === "WebIDE") {
        tabs[i].textContent = "Code Editor";
        tabs[i].title = "PicoScript code editor, compiler and debugger";
        break;
      }
    }
    if (typeof baseShowView === "function") baseShowView("play");
  }

  /* Showcase isn't vendored locally (only docs/index.html is, per
   * gen_ide_assets.py) -- point the existing tab at the real hosted portal
   * instead of leaving a dead relative link. */
  function fixShowcaseLink() {
    var links = document.querySelectorAll(".tabs a.tab");
    for (var i = 0; i < links.length; i++) {
      var a = links[i];
      if (/showcase\.html$/.test(a.getAttribute("href") || "")) {
        a.setAttribute("href", "https://willeastbury.github.io/picoscript/showcase.html");
        a.setAttribute("target", "_blank");
        a.setAttribute("rel", "noopener");
      }
    }
  }

  /* ---------- boot ---------- */
  function handleOAuthRedirect() {
    var qs = new URLSearchParams(location.search);
    var code = qs.get("code"), state = qs.get("state");
    if (!code || !state) return Promise.resolve();
    var expected = sessionStorage.getItem("picoide_pkce_state");
    if (state !== expected) return Promise.resolve();
    return exchangeCodeForToken(code).catch(function (e) { report("login failed: " + e.message, true); });
  }

  loadConfig().then(function (c) {
    installLiveFetch();
    installSchemaPushLive();
    applyLiveServer();
    buildOfflineToggle();
    buildAuthWidget();
    buildDeployControls();
    installUnifiedShowView();
    buildPicowalTab();
    labelAndOpenCodeEditor();
    fixShowcaseLink();
    if (c && !c.picosts_enabled && authWidget) authWidget.loginBtn.disabled = true;
    return handleOAuthRedirect().then(refreshMe);
  });
})();
