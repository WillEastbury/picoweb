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

  function controlForType(fieldName, typeDecl, isRequired) {
    const baseType = (typeDecl || "string").replace(/\?$/, "");
    const id = `pw-field-${fieldName}`;
    const wrap = document.createElement("div");
    wrap.className = "pw-field";

    const label = document.createElement("label");
    label.setAttribute("for", id);
    label.textContent = fieldName;
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
    if (input.type !== "checkbox" && isRequired) input.required = true;
    wrap.appendChild(input);

    return wrap;
  }

  function buildFormFromSchema(formSpec) {
    const schema = formSpec.schema || {};
    const entity = formSpec.entity || `pack-${formSpec.pack}`;
    const fields = parseCsv(schema.fields);
    const required = new Set(parseCsv(schema.required));
    const types = parseAssignMap(schema.types);
    const joins = parseAssignMap(schema.joins);

    dataForm.innerHTML = "";
    if (fields.length === 0) {
      throw new Error("Schema has no fields.");
    }

    for (const field of fields) {
      const typeDecl = types[field] || (field.endsWith("_id") ? "number" : "string");
      const node = controlForType(field, typeDecl, required.has(field));
      if (joins[field]) {
        const hint = document.createElement("small");
        hint.className = "pw-hint";
        hint.textContent = `lookup pack ${joins[field]}`;
        node.appendChild(hint);
      }
      dataForm.appendChild(node);
    }

    titleEl.textContent = `Form: ${entity} (pack ${formSpec.pack})`;
    formSection.hidden = false;
    currentSchema = schema;
    currentPack = formSpec.pack;
  }

  async function loadForm(pack) {
    const res = await fetch(`/wal/forms/${pack}`, {
      method: "GET",
      headers: { "Accept": "application/json", "X-PW-Auth": "1" }
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
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(payload);
    }

    const res = await fetch(path, options);
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
})();
