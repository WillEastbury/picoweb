(function () {
  "use strict";

  const configForm = document.getElementById("pw-config-form");
  const packInput = document.getElementById("pw-pack");
  const formSection = document.getElementById("pw-form-section");
  const dataForm = document.getElementById("pw-data-form");
  const titleEl = document.getElementById("pw-form-title");
  const methodEl = document.getElementById("pw-method");
  const recordEl = document.getElementById("pw-record");
  const submitBtn = document.getElementById("pw-submit-btn");
  const outputEl = document.getElementById("pw-output");
  const authProviderEl = document.getElementById("pw-auth-provider");
  const authTokenEl = document.getElementById("pw-auth-token");
  const authLoginBtn = document.getElementById("pw-auth-login");
  const authLogoutBtn = document.getElementById("pw-auth-logout");
  const authStatusEl = document.getElementById("pw-auth-status");

  let currentPack = null;
  let currentSchema = null;

  function printOutput(status, payload) {
    let body = payload;
    if (typeof payload !== "string") {
      try {
        body = JSON.stringify(payload, null, 2);
      } catch (_) {
        body = String(payload);
      }
    }
    outputEl.textContent = `Status: ${status}\n\n${body}`;
  }

  function parseCsv(value) {
    if (!value || typeof value !== "string") return [];
    return value
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  function parseAssignMap(value) {
    if (!value || typeof value !== "string") return {};
    const out = {};
    const parts = value.split(";");
    for (const part of parts) {
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
      const targetPack = bits[0].trim();
      const field = bits[1].trim();
      if (field && targetPack) map[field] = targetPack;
    }
    return map;
  }

  function isEmailLike(value) {
    if (typeof value !== "string") return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  }

  function validatePayloadAgainstSchema(payload, schema, originalRecord) {
    const required = parseCsv(schema.required);
    for (const field of required) {
      const value = payload[field];
      if (value === undefined || value === null || (typeof value === "string" && value.trim() === "")) {
        return `Missing required field: ${field}`;
      }
    }

    const types = parseAssignMap(schema.types);
    for (const field of Object.keys(types)) {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const typeDecl = types[field];
      const nullable = typeDecl.endsWith("?");
      const base = nullable ? typeDecl.slice(0, -1) : typeDecl;
      const value = payload[field];
      if (value === null && nullable) continue;
      if (base === "string" && typeof value !== "string") return `Type mismatch for ${field}: expected string`;
      if ((base === "number" || base === "integer") && typeof value !== "number") return `Type mismatch for ${field}: expected number`;
      if ((base === "bool" || base === "boolean") && typeof value !== "boolean") return `Type mismatch for ${field}: expected boolean`;
      if (base === "object" && (typeof value !== "object" || Array.isArray(value) || value === null)) return `Type mismatch for ${field}: expected object`;
      if (base === "array" && !Array.isArray(value)) return `Type mismatch for ${field}: expected array`;
    }

    const emailFields = parseCsv(schema.email);
    for (const field of emailFields) {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const value = payload[field];
      if (value === null || value === undefined || value === "") continue;
      if (!isEmailLike(String(value))) return `Email validation failed for ${field}`;
    }

    const regexRules = parseAssignMap(schema.regex);
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

    const transitionRules = parseAssignMap(schema.transitions);
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

  async function validateJoinIntegrity(payload, schema) {
    const joins = parseJoinFieldMap(schema.joins);
    for (const field of Object.keys(joins)) {
      if (!Object.prototype.hasOwnProperty.call(payload, field)) continue;
      const value = payload[field];
      if (value === null || value === undefined || value === "") continue;
      const targetPack = joins[field];
      const res = await authFetch(`/wal/${targetPack}/${encodeURIComponent(String(value))}`, { method: "GET" });
      if (!res.ok) return `Lookup value not found for ${field} (pack ${targetPack}, record ${value})`;
    }
    return "";
  }

  async function authFetch(path, options) {
    const merged = Object.assign({}, options || {});
    merged.headers = Object.assign({ Accept: "application/json", "X-PW-Auth": "1" }, merged.headers || {});
    merged.credentials = "include";
    return fetch(path, merged);
  }

  function setAuthStatus(text) {
    if (authStatusEl) authStatusEl.textContent = `Status: ${text}`;
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
      try {
        const res = await authFetch("/wal/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ provider, access_token: accessToken })
        });
        if (res.ok) setAuthStatus("logged in");
        else setAuthStatus(`login failed (${res.status})`);
      } catch (e) {
        setAuthStatus(e.message || "login failed");
      }
    });

    authLogoutBtn.addEventListener("click", async () => {
      try {
        const res = await authFetch("/wal/auth/logout", { method: "POST" });
        if (res.ok) setAuthStatus("logged out");
        else setAuthStatus(`logout failed (${res.status})`);
      } catch (e) {
        setAuthStatus(e.message || "logout failed");
      }
    });
  }

  function controlForType(fieldName, typeDecl, isRequired, displayLabel, placeholder) {
    const baseType = (typeDecl || "string").replace(/\?$/, "");
    const id = `pw-field-${fieldName}`;
    const wrap = document.createElement("div");
    wrap.className = "pw-field";

    const label = document.createElement("label");
    label.setAttribute("for", id);
    label.textContent = displayLabel || fieldName;
    wrap.appendChild(label);

    let input;
    if (baseType === "object" || baseType === "array") {
      input = document.createElement("textarea");
      input.rows = 4;
      input.placeholder = baseType === "array" ? "[]" : "{}";
    } else {
      input = document.createElement("input");
      if (baseType === "number" || baseType === "integer") {
        input.type = "number";
      } else if (baseType === "boolean" || baseType === "bool") {
        input.type = "checkbox";
      } else {
        input.type = "text";
      }
    }

    input.id = id;
    input.name = fieldName;
    input.dataset.typeDecl = typeDecl || "string";
    if (placeholder && input.type !== "checkbox") input.placeholder = placeholder;
    if (input.type !== "checkbox" && isRequired) input.required = true;
    wrap.appendChild(input);

    return wrap;
  }

  function buildFormFromSchema(formSpec) {
    const schema = formSpec.schema || {};
    const app = formSpec.app || {};
    const entity = formSpec.entity || `pack-${formSpec.pack}`;
    const fields = parseCsv(schema.fields);
    const required = new Set(parseCsv(schema.required));
    const types = parseAssignMap(schema.types);
    const joins = parseAssignMap(schema.joins);
    const labels = parseAssignMap(app.field_labels || schema.field_labels);
    const placeholders = parseAssignMap(app.field_placeholders || schema.field_placeholders);

    dataForm.innerHTML = "";
    if (fields.length === 0) {
      throw new Error("Schema has no fields.");
    }

    for (const field of fields) {
      const typeDecl = types[field] || (field.endsWith("_id") ? "number" : "string");
      const node = controlForType(
        field,
        typeDecl,
        required.has(field),
        labels[field] || field,
        placeholders[field] || ""
      );
      if (joins[field]) {
        const hint = document.createElement("small");
        hint.className = "pw-hint";
        hint.textContent = `lookup pack ${joins[field]}`;
        node.appendChild(hint);
      }
      dataForm.appendChild(node);
    }

    const title = app.title || entity;
    titleEl.textContent = `Form: ${title} (pack ${formSpec.pack})`;
    formSection.hidden = false;
    currentSchema = schema;
    currentPack = formSpec.pack;
  }

  async function loadForm(pack) {
    const res = await authFetch(`/wal/forms/${pack}`, {
      method: "GET",
    });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (_) {
      // Keep text response for output.
    }

    if (!res.ok) {
      printOutput(res.status, json || text);
      throw new Error("Unable to load form metadata.");
    }
    if (!json || typeof json !== "object" || !json.schema) {
      throw new Error("Unexpected /wal/forms response.");
    }
    buildFormFromSchema(json);
    printOutput(res.status, json);
  }

  function buildPayload() {
    const payload = {};
    const elements = dataForm.querySelectorAll("input, textarea");
    for (const el of elements) {
      const key = el.name;
      const typeDecl = (el.dataset.typeDecl || "string").replace(/\?$/, "");
      if (el.type === "checkbox") {
        payload[key] = !!el.checked;
        continue;
      }
      const raw = (el.value || "").trim();
      if (raw.length === 0) continue;

      if (typeDecl === "number" || typeDecl === "integer") {
        payload[key] = Number(raw);
      } else if (typeDecl === "object" || typeDecl === "array") {
        payload[key] = JSON.parse(raw);
      } else if (typeDecl === "boolean" || typeDecl === "bool") {
        payload[key] = raw.toLowerCase() === "true";
      } else {
        payload[key] = raw;
      }
    }
    return payload;
  }

  async function submitMutation() {
    if (!currentSchema || currentPack === null) {
      printOutput("n/a", "Load a form first.");
      return;
    }

    const method = methodEl.value;
    const record = (recordEl.value || "").trim();
    if ((method === "PUT" || method === "DELETE") && !record) {
      printOutput("n/a", "Record is required for PUT and DELETE.");
      return;
    }

    let path = `/wal/${currentPack}`;
    if (record) path += `/${record}`;

    const options = {
      method,
      headers: { "Accept": "application/json", "X-PW-Auth": "1" }
    };

    if (method !== "DELETE") {
      let payload;
      try {
        payload = buildPayload();
      } catch (e) {
        printOutput("n/a", e.message || "Invalid JSON in object/array field.");
        return;
      }
      let originalRecord = null;
      if (method === "PUT" && record) {
        const prevRes = await authFetch(`/wal/${currentPack}/${encodeURIComponent(record)}`, { method: "GET" });
        if (prevRes.ok) {
          try {
            originalRecord = await prevRes.json();
          } catch (_) {
            originalRecord = null;
          }
        }
      }
      const validationError = validatePayloadAgainstSchema(payload, currentSchema || {}, originalRecord);
      if (validationError) {
        printOutput("n/a", validationError);
        return;
      }
      const joinError = await validateJoinIntegrity(payload, currentSchema || {});
      if (joinError) {
        printOutput("n/a", joinError);
        return;
      }
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(payload);
    }

    const res = await authFetch(path, options);
    const text = await res.text();
    let body = text;
    try {
      body = text ? JSON.parse(text) : "";
    } catch (_) {
      // non-json response body
    }
    printOutput(res.status, body || "(empty body)");
  }

  configForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const pack = Number(packInput.value);
    if (!Number.isInteger(pack) || pack < 0 || pack > 1023) {
      printOutput("n/a", "Pack must be an integer from 0 to 1023.");
      return;
    }
    try {
      await loadForm(pack);
    } catch (_) {
      // Already surfaced in output.
    }
  });

  submitBtn.addEventListener("click", async () => {
    try {
      await submitMutation();
    } catch (e) {
      printOutput("n/a", e.message || "Request failed.");
    }
  });

  wireAuthUi();
})();
