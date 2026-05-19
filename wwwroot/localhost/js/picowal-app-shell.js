(function () {
  "use strict";

  const configForm = document.getElementById("pw-app-config");
  const packInput = document.getElementById("pw-app-pack");
  const shellSection = document.getElementById("pw-app-shell");
  const titleEl = document.getElementById("pw-app-title");
  const navEl = document.getElementById("pw-app-nav");
  const mainEl = document.getElementById("pw-app-main");
  const outputEl = document.getElementById("pw-app-output");
  const authProviderEl = document.getElementById("pw-auth-provider");
  const authTokenEl = document.getElementById("pw-auth-token");
  const authLoginBtn = document.getElementById("pw-auth-login");
  const authLogoutBtn = document.getElementById("pw-auth-logout");
  const authStatusEl = document.getElementById("pw-auth-status");
  const saveConfigBtn = document.getElementById("pw-save-config");
  const loadConfigBtn = document.getElementById("pw-load-config");
  const historyConfigBtn = document.getElementById("pw-show-config-history");

  const state = {
    pack: null,
    spec: null,
    schema: null,
    app: null,
    fields: [],
    required: new Set(),
    types: {},
    labels: {},
    placeholders: {},
    joinsByField: {},
    listColumns: [],
    pages: [],
    pageSize: 25,
    actions: []
  };

  function printOutput(status, payload) {
    let text = payload;
    if (typeof payload !== "string") {
      try {
        text = JSON.stringify(payload, null, 2);
      } catch (_) {
        text = String(payload);
      }
    }
    outputEl.textContent = `Status: ${status}\n\n${text}`;
  }

  function parseCsv(value) {
    if (!value || typeof value !== "string") return [];
    return value.split(",").map((s) => s.trim()).filter(Boolean);
  }

  function parseAssignMap(value) {
    if (!value || typeof value !== "string") return {};
    const out = {};
    for (const part of value.split(";")) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const eq = trimmed.indexOf("=");
      const colon = trimmed.indexOf(":");
      let sep = -1;
      if (eq >= 0 && colon >= 0) sep = Math.min(eq, colon);
      else sep = eq >= 0 ? eq : colon;
      if (sep < 1) continue;
      const key = trimmed.slice(0, sep).trim();
      const val = trimmed.slice(sep + 1).trim();
      if (key && val) out[key] = val;
    }
    return out;
  }

  function parseJoinFieldMap(value) {
    const map = {};
    if (!value || typeof value !== "string") return map;
    for (const part of value.split(",")) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const sep = trimmed.includes("=") ? "=" : (trimmed.includes(":") ? ":" : "");
      if (!sep) continue;
      const bits = trimmed.split(sep);
      if (bits.length < 2) continue;
      const pack = bits[0].trim();
      const field = bits[1].trim();
      if (pack && field) map[field] = pack;
    }
    return map;
  }

  function isEmailLike(value) {
    if (typeof value !== "string") return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  }

  function validatePayloadAgainstSchema(payload, originalRecord) {
    const required = parseCsv(state.schema.required);
    for (const field of required) {
      const value = payload[field];
      if (value === undefined || value === null || (typeof value === "string" && value.trim() === "")) {
        return `Missing required field: ${field}`;
      }
    }

    for (const field of Object.keys(state.types)) {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const decl = state.types[field];
      const nullable = decl.endsWith("?");
      const base = nullable ? decl.slice(0, -1) : decl;
      const value = payload[field];
      if (value === null && nullable) continue;
      if (base === "string" && typeof value !== "string") return `Type mismatch for ${field}: expected string`;
      if ((base === "number" || base === "integer") && typeof value !== "number") return `Type mismatch for ${field}: expected number`;
      if ((base === "bool" || base === "boolean") && typeof value !== "boolean") return `Type mismatch for ${field}: expected boolean`;
      if (base === "object" && (typeof value !== "object" || Array.isArray(value) || value === null)) return `Type mismatch for ${field}: expected object`;
      if (base === "array" && !Array.isArray(value)) return `Type mismatch for ${field}: expected array`;
    }

    const emailFields = parseCsv(state.schema.email);
    for (const field of emailFields) {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const value = payload[field];
      if (value === null || value === undefined || value === "") continue;
      if (!isEmailLike(String(value))) return `Email validation failed for ${field}`;
    }

    const regexRules = parseAssignMap(state.schema.regex);
    for (const field of Object.keys(regexRules)) {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const value = payload[field];
      if (value === null || value === undefined) continue;
      let re;
      try {
        re = new RegExp(regexRules[field]);
      } catch (_) {
        return `Invalid regex rule for ${field}`;
      }
      if (!re.test(String(value))) return `Regex validation failed for ${field}`;
    }

    const transitionRules = parseAssignMap(state.schema.transitions);
    for (const field of Object.keys(transitionRules)) {
      if (!originalRecord || !Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const from = originalRecord[field];
      const to = payload[field];
      if (from === undefined || from === null || to === undefined || to === null) continue;
      if (String(from) === String(to)) continue;
      const allowed = String(transitionRules[field]).split("|").map((x) => x.trim()).filter(Boolean);
      const token = `${String(from)}>${String(to)}`;
      if (!allowed.includes(token)) return `Transition not allowed for ${field}: ${token}`;
    }
    return "";
  }

  async function validateJoinIntegrity(payload) {
    for (const field of Object.keys(state.joinsByField)) {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const value = payload[field];
      if (value === null || value === undefined || value === "") continue;
      const targetPack = state.joinsByField[field];
      const res = await fetchJson(`/wal/${targetPack}/${encodeURIComponent(String(value))}`, { method: "GET" });
      if (!res.ok) return `Lookup value not found for ${field} (pack ${targetPack}, record ${value})`;
    }
    return "";
  }

  function setAuthStatus(text) {
    if (authStatusEl) authStatusEl.textContent = `Status: ${text}`;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function configStoreKey(pack) {
    return `pw-appcfg:${window.location.host}:${pack}`;
  }

  function readConfigStore(pack) {
    try {
      const raw = localStorage.getItem(configStoreKey(pack));
      if (!raw) return { versions: [] };
      const parsed = JSON.parse(raw);
      if (!parsed || !Array.isArray(parsed.versions)) return { versions: [] };
      return parsed;
    } catch (_) {
      return { versions: [] };
    }
  }

  function writeConfigStore(pack, store) {
    localStorage.setItem(configStoreKey(pack), JSON.stringify(store));
  }

  function latestSavedConfig(pack) {
    const store = readConfigStore(pack);
    if (!store.versions.length) return null;
    return store.versions[store.versions.length - 1];
  }

  async function fetchJson(path, options) {
    const merged = Object.assign(
      { headers: { Accept: "application/json", "X-PW-Auth": "1" } },
      options || {}
    );
    merged.headers = Object.assign({ Accept: "application/json", "X-PW-Auth": "1" }, merged.headers || {});
    merged.credentials = "include";
    const res = await fetch(path, merged);
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch (_) {
      json = null;
    }
    return { ok: res.ok, status: res.status, json, text };
  }

  function wireAuthUi() {
    if (!authLoginBtn || !authLogoutBtn || !authProviderEl || !authTokenEl) return;
    authLoginBtn.addEventListener("click", async () => {
      const provider = authProviderEl.value;
      const accessToken = (authTokenEl.value || "").trim();
      if (!accessToken) {
        setAuthStatus("missing access token");
        return;
      }
      const res = await fetchJson("/wal/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, access_token: accessToken })
      });
      if (res.ok) setAuthStatus("logged in");
      else setAuthStatus(`login failed (${res.status})`);
      printOutput(res.status, res.json || res.text || "(empty body)");
    });

    authLogoutBtn.addEventListener("click", async () => {
      const res = await fetchJson("/wal/auth/logout", { method: "POST" });
      if (res.ok) setAuthStatus("logged out");
      else setAuthStatus(`logout failed (${res.status})`);
      printOutput(res.status, res.json || res.text || "(empty body)");
    });
  }

  function wireConfigPersistenceUi() {
    if (!saveConfigBtn || !loadConfigBtn || !historyConfigBtn) return;
    saveConfigBtn.addEventListener("click", () => {
      if (!state.spec || state.pack === null) {
        printOutput("n/a", "Load an app first.");
        return;
      }
      const store = readConfigStore(state.pack);
      const nextVersion = store.versions.length ? (store.versions[store.versions.length - 1].version + 1) : 1;
      store.versions.push({
        version: nextVersion,
        saved_at: new Date().toISOString(),
        app: state.app || {}
      });
      writeConfigStore(state.pack, store);
      printOutput(200, { message: "saved app config", pack: state.pack, version: nextVersion });
    });

    loadConfigBtn.addEventListener("click", () => {
      if (!state.spec || state.pack === null) {
        printOutput("n/a", "Load an app first.");
        return;
      }
      const latest = latestSavedConfig(state.pack);
      if (!latest) {
        printOutput(404, { message: "no saved config for this host+pack" });
        return;
      }
      state.app = Object.assign({}, state.app, latest.app || {});
      state.labels = parseAssignMap(state.app.field_labels || state.schema.field_labels);
      state.placeholders = parseAssignMap(state.app.field_placeholders || state.schema.field_placeholders);
      state.listColumns = parseCsv(state.app.list_columns || state.schema.list_columns);
      state.pages = parseCsv(state.app.pages);
      if (state.pages.length === 0) state.pages = ["list", "create", "edit", "detail"];
      state.pageSize = Number(state.app.page_size || 25);
      if (!Number.isFinite(state.pageSize) || state.pageSize < 1) state.pageSize = 25;
      titleEl.textContent = state.app.title || state.spec.entity || `pack-${state.pack}`;
      renderNav();
      renderRoute().catch((e) => printOutput("n/a", e.message || "Route render failed."));
      printOutput(200, { message: "loaded saved config", pack: state.pack, version: latest.version, saved_at: latest.saved_at });
    });

    historyConfigBtn.addEventListener("click", () => {
      if (state.pack === null) {
        printOutput("n/a", "Load an app first.");
        return;
      }
      const store = readConfigStore(state.pack);
      const list = store.versions.map((v) => ({ version: v.version, saved_at: v.saved_at }));
      printOutput(200, { pack: state.pack, host: window.location.host, versions: list });
    });
  }

  function storageKeyFor(kind) {
    return `pw-${kind}:${window.location.host}:${state.pack}`;
  }

  function loadStoredText(kind, fallbackText) {
    try {
      return localStorage.getItem(storageKeyFor(kind)) || fallbackText;
    } catch (_) {
      return fallbackText;
    }
  }

  function saveStoredText(kind, value) {
    try {
      localStorage.setItem(storageKeyFor(kind), value);
    } catch (_) {
      // ignore storage failures
    }
  }

  function fieldType(field) {
    const decl = (state.types[field] || (field.endsWith("_id") ? "number" : "string")).replace(/\?$/, "");
    return decl;
  }

  function renderEntityForm(initialData) {
    const form = document.createElement("form");
    form.className = "pw-generated-form";
    for (const field of state.fields) {
      const wrap = document.createElement("div");
      wrap.className = "pw-field";

      const label = document.createElement("label");
      label.setAttribute("for", `pw-app-${field}`);
      label.textContent = state.labels[field] || field;
      wrap.appendChild(label);

      const type = fieldType(field);
      let input;
      if (type === "object" || type === "array") {
        input = document.createElement("textarea");
        input.rows = 4;
      } else {
        input = document.createElement("input");
        if (type === "number" || type === "integer") input.type = "number";
        else if (type === "boolean" || type === "bool") input.type = "checkbox";
        else input.type = "text";
      }

      input.id = `pw-app-${field}`;
      input.name = field;
      input.dataset.typeDecl = state.types[field] || (field.endsWith("_id") ? "number" : "string");
      if (state.placeholders[field] && input.type !== "checkbox") input.placeholder = state.placeholders[field];
      if (state.required.has(field) && input.type !== "checkbox") input.required = true;

      if (initialData && Object.prototype.hasOwnProperty.call(initialData, field)) {
        const val = initialData[field];
        if (input.type === "checkbox") input.checked = !!val;
        else if (type === "object" || type === "array") input.value = JSON.stringify(val, null, 2);
        else if (val !== null && val !== undefined) input.value = String(val);
      }

      wrap.appendChild(input);
      form.appendChild(wrap);
    }
    return form;
  }

  function collectPayload(form) {
    const payload = {};
    const fields = form.querySelectorAll("input, textarea");
    for (const el of fields) {
      const field = el.name;
      const typeDecl = (el.dataset.typeDecl || "string").replace(/\?$/, "");
      if (el.type === "checkbox") {
        payload[field] = !!el.checked;
        continue;
      }
      const raw = (el.value || "").trim();
      if (!raw) continue;
      if (typeDecl === "number" || typeDecl === "integer") payload[field] = Number(raw);
      else if (typeDecl === "boolean" || typeDecl === "bool") payload[field] = raw.toLowerCase() === "true";
      else if (typeDecl === "object" || typeDecl === "array") payload[field] = JSON.parse(raw);
      else payload[field] = raw;
    }
    return payload;
  }

  function renderListTable(records, cols, filterText, sortKey, page) {
    const norm = (filterText || "").toLowerCase();
    const filtered = records.filter((item) => {
      if (!norm) return true;
      for (const col of cols) {
        const v = item.data ? item.data[col] : undefined;
        if (v === undefined || v === null) continue;
        if (String(v).toLowerCase().includes(norm)) return true;
      }
      return String(item.record).includes(norm);
    });

    const sorted = filtered.slice();
    if (sortKey) {
      const desc = sortKey.startsWith("-");
      const key = desc ? sortKey.slice(1) : sortKey;
      sorted.sort((a, b) => {
        const av = key === "record" ? a.record : (a.data ? a.data[key] : undefined);
        const bv = key === "record" ? b.record : (b.data ? b.data[key] : undefined);
        const as = av === undefined || av === null ? "" : String(av);
        const bs = bv === undefined || bv === null ? "" : String(bv);
        if (as === bs) return 0;
        return (as > bs ? 1 : -1) * (desc ? -1 : 1);
      });
    }

    const pageSize = state.pageSize > 0 ? state.pageSize : 25;
    const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
    const pageSafe = Math.min(Math.max(page, 1), totalPages);
    const start = (pageSafe - 1) * pageSize;
    const current = sorted.slice(start, start + pageSize);

    let html = `<h4>List (${sorted.length})</h4>`;
    html += '<table class="pw-table"><thead><tr><th>record</th>';
    for (const col of cols) html += `<th>${escapeHtml(state.labels[col] || col)}</th>`;
    html += "<th>Actions</th></tr></thead><tbody>";
    for (const item of current) {
      html += `<tr><td>${item.record}</td>`;
      for (const col of cols) {
        const val = item.data ? item.data[col] : undefined;
        const joinPack = state.joinsByField[col];
        if (joinPack && val !== undefined && val !== null && String(val).length > 0) {
          html += `<td><a href="/app.html?pack=${encodeURIComponent(joinPack)}#/detail/${encodeURIComponent(String(val))}">${escapeHtml(val)}</a> <small>(pack ${escapeHtml(joinPack)})</small></td>`;
        } else {
          html += `<td>${escapeHtml(val === undefined ? "" : val)}</td>`;
        }
      }
      html += `<td><a href="#/detail/${item.record}">detail</a> | <a href="#/edit/${item.record}">edit</a></td></tr>`;
    }
    html += "</tbody></table>";
    html += `<div class="pw-list-pager"><button id="pw-prev-page" type="button"${pageSafe <= 1 ? " disabled" : ""}>Prev</button> <span>Page ${pageSafe} / ${totalPages}</span> <button id="pw-next-page" type="button"${pageSafe >= totalPages ? " disabled" : ""}>Next</button></div>`;
    mainEl.querySelector("#pw-list-table").innerHTML = html;

    const prevBtn = mainEl.querySelector("#pw-prev-page");
    const nextBtn = mainEl.querySelector("#pw-next-page");
    if (prevBtn) prevBtn.addEventListener("click", () => renderListTable(records, cols, filterText, sortKey, pageSafe - 1));
    if (nextBtn) nextBtn.addEventListener("click", () => renderListTable(records, cols, filterText, sortKey, pageSafe + 1));
  }

  async function renderListPage() {
    const cols = state.listColumns.length ? state.listColumns : state.fields;
    const res = await fetchJson(`/wal/list/${state.pack}`, { method: "GET" });
    if (!res.ok || !res.json || !Array.isArray(res.json.records)) {
      printOutput(res.status, res.json || res.text);
      mainEl.innerHTML = "<p>Failed to load list data.</p>";
      return;
    }

    mainEl.innerHTML = `
      <div class="pw-list-tools">
        <label for="pw-filter">Filter</label>
        <input id="pw-filter" type="text" placeholder="filter rows">
        <label for="pw-sort">Sort</label>
        <select id="pw-sort"></select>
      </div>
      <div id="pw-list-table"></div>
    `;

    const sortEl = mainEl.querySelector("#pw-sort");
    const sortOptions = ["record", ...cols];
    for (const key of sortOptions) {
      const asc = document.createElement("option");
      asc.value = key;
      asc.textContent = `${state.labels[key] || key} (asc)`;
      sortEl.appendChild(asc);
      const desc = document.createElement("option");
      desc.value = `-${key}`;
      desc.textContent = `${state.labels[key] || key} (desc)`;
      sortEl.appendChild(desc);
    }

    const filterEl = mainEl.querySelector("#pw-filter");
    const rerender = () => renderListTable(res.json.records, cols, filterEl.value, sortEl.value, 1);
    filterEl.addEventListener("input", rerender);
    sortEl.addEventListener("change", rerender);
    rerender();
    printOutput(res.status, res.json);
  }

  async function renderCreatePage() {
    mainEl.innerHTML = "<h4>Create</h4>";
    const form = renderEntityForm(null);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Create";
    btn.addEventListener("click", async () => {
      try {
        const payload = collectPayload(form);
        const validationError = validatePayloadAgainstSchema(payload, null);
        if (validationError) {
          printOutput("n/a", validationError);
          return;
        }
        const joinError = await validateJoinIntegrity(payload);
        if (joinError) {
          printOutput("n/a", joinError);
          return;
        }
        const res = await fetchJson(`/wal/${state.pack}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        printOutput(res.status, res.json || res.text || "(empty body)");
      } catch (e) {
        printOutput("n/a", e.message || "Failed to submit create request.");
      }
    });
    form.appendChild(btn);
    mainEl.appendChild(form);
  }

  async function loadRecord(recordId) {
    const res = await fetchJson(`/wal/${state.pack}/${recordId}`, { method: "GET" });
    if (!res.ok) {
      printOutput(res.status, res.json || res.text);
      return null;
    }
    printOutput(res.status, res.json || res.text);
    return res.json;
  }

  async function renderEditPage(recordId) {
    const data = await loadRecord(recordId);
    if (!data || typeof data !== "object") {
      mainEl.innerHTML = `<p>Record ${escapeHtml(recordId)} not found.</p>`;
      return;
    }
    mainEl.innerHTML = `<h4>Edit #${escapeHtml(recordId)}</h4>`;
    const form = renderEntityForm(data);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Save";
    btn.addEventListener("click", async () => {
      try {
        const payload = collectPayload(form);
        const validationError = validatePayloadAgainstSchema(payload, data);
        if (validationError) {
          printOutput("n/a", validationError);
          return;
        }
        const joinError = await validateJoinIntegrity(payload);
        if (joinError) {
          printOutput("n/a", joinError);
          return;
        }
        const res = await fetchJson(`/wal/${state.pack}/${recordId}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        printOutput(res.status, res.json || res.text || "(empty body)");
      } catch (e) {
        printOutput("n/a", e.message || "Failed to submit edit request.");
      }
    });
    form.appendChild(btn);
    mainEl.appendChild(form);
  }

  async function renderDetailPage(recordId) {
    const data = await loadRecord(recordId);
    if (!data || typeof data !== "object") {
      mainEl.innerHTML = `<p>Record ${escapeHtml(recordId)} not found.</p>`;
      return;
    }
    mainEl.innerHTML = `<h4>Detail #${escapeHtml(recordId)}</h4><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  }

  async function renderReportBuilderPage() {
    const defaultQuery = `S:${(state.listColumns.length ? state.listColumns : state.fields).join(",")}\nF:${state.pack}`;
    const saved = loadStoredText("report-query", defaultQuery);
    mainEl.innerHTML = `
      <h4>Report builder</h4>
      <label for="pw-report-title">Title</label>
      <input id="pw-report-title" type="text" placeholder="Report title">
      <label for="pw-report-query">Query</label>
      <textarea id="pw-report-query" rows="8"></textarea>
      <button id="pw-run-report" type="button">Run report</button>
    `;
    const titleEl = mainEl.querySelector("#pw-report-title");
    const queryEl = mainEl.querySelector("#pw-report-query");
    queryEl.value = saved;
    const runBtn = mainEl.querySelector("#pw-run-report");
    runBtn.addEventListener("click", async () => {
      const query = (queryEl.value || "").trim();
      const title = (titleEl.value || "").trim();
      if (!query) {
        printOutput("n/a", "Report query is required.");
        return;
      }
      saveStoredText("report-query", query);
      const payload = title ? { title, query } : { query };
      const res = await fetchJson("/wal/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      printOutput(res.status, res.json || res.text || "(empty body)");
    });
  }

  async function renderDashboardBuilderPage() {
    const defaultDash = `T:Overview\nS:${(state.listColumns.length ? state.listColumns : state.fields).join(",")}\nF:${state.pack}`;
    const saved = loadStoredText("dashboard-spec", defaultDash);
    mainEl.innerHTML = `
      <h4>Dashboard builder</h4>
      <p>Use <code>---</code> between panels and optional <code>T:</code> title line.</p>
      <label for="pw-dashboard-spec">Dashboard spec</label>
      <textarea id="pw-dashboard-spec" rows="10"></textarea>
      <button id="pw-run-dashboard" type="button">Run dashboard</button>
    `;
    const specEl = mainEl.querySelector("#pw-dashboard-spec");
    specEl.value = saved;
    const runBtn = mainEl.querySelector("#pw-run-dashboard");
    runBtn.addEventListener("click", async () => {
      const spec = (specEl.value || "").trim();
      if (!spec) {
        printOutput("n/a", "Dashboard spec is required.");
        return;
      }
      saveStoredText("dashboard-spec", spec);
      const res = await fetchJson("/wal/dashboard", {
        method: "POST",
        headers: { "Content-Type": "text/plain; charset=utf-8" },
        body: spec
      });
      printOutput(res.status, res.json || res.text || "(empty body)");
    });
  }

  function routeFromHash() {
    const raw = (window.location.hash || "").replace(/^#/, "");
    if (!raw) return { page: state.pages[0] || "list", record: "" };
    const parts = raw.split("/").filter(Boolean);
    const page = parts[0] || "list";
    const record = parts[1] || "";
    return { page, record };
  }

  function renderNav() {
    navEl.innerHTML = "";
    for (const page of state.pages) {
      const a = document.createElement("a");
      a.className = "pw-nav-link";
      a.href = `#/${page}`;
      a.textContent = page;
      navEl.appendChild(a);
    }
  }

  async function renderRoute() {
    const route = routeFromHash();
    if (route.page === "list") return renderListPage();
    if (route.page === "create") return renderCreatePage();
    if (route.page === "reports") return renderReportBuilderPage();
    if (route.page === "dashboard") return renderDashboardBuilderPage();
    if (route.page === "edit") {
      if (!route.record) {
        mainEl.innerHTML = "<p>Use #/edit/{record}.</p>";
        return;
      }
      return renderEditPage(route.record);
    }
    if (route.page === "detail") {
      if (!route.record) {
        mainEl.innerHTML = "<p>Use #/detail/{record}.</p>";
        return;
      }
      return renderDetailPage(route.record);
    }
    mainEl.innerHTML = `<p>Unknown page '${escapeHtml(route.page)}'.</p>`;
  }

  async function loadApp(pack) {
    const res = await fetchJson(`/wal/forms/${pack}`, { method: "GET" });
    if (!res.ok || !res.json || typeof res.json !== "object" || !res.json.schema) {
      printOutput(res.status, res.json || res.text);
      throw new Error("Unable to load app metadata.");
    }

    const mergedSpec = Object.assign({}, res.json);
    const persisted = latestSavedConfig(pack);
    if (persisted && persisted.app && typeof persisted.app === "object") {
      mergedSpec.app = Object.assign({}, res.json.app || {}, persisted.app);
    }

    state.pack = pack;
    state.spec = mergedSpec;
    state.schema = mergedSpec.schema || {};
    state.app = mergedSpec.app || {};
    state.fields = parseCsv(state.schema.fields);
    state.required = new Set(parseCsv(state.schema.required));
    state.types = parseAssignMap(state.schema.types);
    state.labels = parseAssignMap(state.app.field_labels || state.schema.field_labels);
    state.placeholders = parseAssignMap(state.app.field_placeholders || state.schema.field_placeholders);
    state.joinsByField = parseJoinFieldMap(state.schema.joins);
    state.listColumns = parseCsv(state.app.list_columns || state.schema.list_columns);
    state.actions = parseCsv(state.app.actions);
    state.pages = parseCsv(state.app.pages);
    state.pageSize = Number(state.app.page_size || 25);
    if (!Number.isFinite(state.pageSize) || state.pageSize < 1) state.pageSize = 25;
    if (state.pages.length === 0) state.pages = ["list", "create", "edit", "detail"];
    if (state.actions.includes("report") && !state.pages.includes("reports")) state.pages.push("reports");
    if (state.actions.includes("dashboard") && !state.pages.includes("dashboard")) state.pages.push("dashboard");

    titleEl.textContent = state.app.title || mergedSpec.entity || `pack-${pack}`;
    shellSection.hidden = false;
    renderNav();
    printOutput(res.status, mergedSpec);

    if (!window.location.hash) window.location.hash = `/${state.pages[0]}`;
    await renderRoute();
  }

  configForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const pack = Number(packInput.value);
    if (!Number.isInteger(pack) || pack < 0 || pack > 1023) {
      printOutput("n/a", "Pack must be an integer from 0 to 1023.");
      return;
    }
    try {
      await loadApp(pack);
    } catch (_) {
      // Error is printed already.
    }
  });

  window.addEventListener("hashchange", () => {
    if (!state.spec) return;
    renderRoute().catch((e) => printOutput("n/a", e.message || "Route render failed."));
  });

  const qsPack = new URLSearchParams(window.location.search).get("pack");
  if (qsPack && /^\d+$/.test(qsPack)) {
    packInput.value = qsPack;
    loadApp(Number(qsPack)).catch(() => {
      // Error surfaced by loadApp.
    });
  }

  wireAuthUi();
  wireConfigPersistenceUi();
})();
