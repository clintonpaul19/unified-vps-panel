function node(value) {
  if (value instanceof Node) return value;
  if (value === null || value === undefined || value === false) return document.createTextNode("");
  return document.createTextNode(String(value));
}

export function h(tag, attrs = {}, ...children) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") element.className = value;
    else if (key === "text") element.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") {
      element.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === "dataset" && value) {
      for (const [dataKey, dataValue] of Object.entries(value)) element.dataset[dataKey] = dataValue;
    } else if (key === "style" && typeof value === "object") {
      Object.assign(element.style, value);
    } else {
      element.setAttribute(key, value === true ? "" : String(value));
    }
  }
  for (const child of children.flat(Infinity)) element.appendChild(node(child));
  return element;
}

export function clear(element) {
  element.replaceChildren();
  return element;
}

export function button({ label, variant = "secondary", size = "md", type = "button", onClick, disabled = false, icon = "", ariaLabel = "" } = {}) {
  const tone = variant === "primary" ? "primary" : variant === "danger" ? "danger" : variant === "ghost" ? "ghost" : "";
  const className = "btn" + (tone ? " btn-" + tone : "") + (size === "sm" ? " btn-sm" : "");
  return h(
    "button",
    {
      type,
      class: className,
      disabled,
      "aria-label": ariaLabel || undefined,
      onClick,
    },
    icon ? h("span", { "aria-hidden": "true" }, icon) : "",
    label,
  );
}

export function iconButton({ label, icon, onClick, variant = "secondary", disabled = false }) {
  return h("button", {
    type: "button",
    class: "btn btn-icon" + (variant === "danger" ? " btn-danger" : variant === "ghost" ? " btn-ghost" : ""),
    "aria-label": label,
    title: label,
    disabled,
    onClick,
  }, h("span", { "aria-hidden": "true" }, icon));
}

export function input({ id, label, type = "text", value = "", placeholder = "", required = false, autocomplete = "", minlength, maxlength, hint = "" } = {}) {
  const inputEl = h("input", {
    id,
    class: "input",
    type,
    value,
    placeholder,
    required,
    autocomplete: autocomplete || undefined,
    minlength,
    maxlength,
  });
  return field({ id, label, control: inputEl, hint });
}

export function select({ id, label, options = [], value = "", hint = "" } = {}) {
  const selectEl = h("select", { id, class: "select" });
  for (const option of options) {
    selectEl.appendChild(h("option", { value: option.value, selected: option.value === value }, option.label));
  }
  return field({ id, label, control: selectEl, hint });
}

export function field({ id, label, control, hint = "" } = {}) {
  if (id && !control.getAttribute("id")) control.id = id;
  if (id) control.setAttribute("aria-describedby", hint ? id + "-hint" : "");
  return h(
    "div",
    { class: "field" },
    h("label", { for: id || control.id || undefined }, label),
    control,
    hint ? h("div", { class: "field-hint", id: id + "-hint" }, hint) : "",
  );
}

export function card({ title = "", subtitle = "", actions = null, children = [] } = {}) {
  const header = h(
    "div",
    { class: "card-header" },
    h("div", {}, h("h2", { class: "card-title" }, title), subtitle ? h("p", { class: "card-subtitle" }, subtitle) : ""),
    actions,
  );
  return h("section", { class: "surface card" }, title || subtitle || actions ? header : "", children);
}

export function statCard({ label, value = "—", meta = "" } = {}) {
  return h(
    "section",
    { class: "surface card stat-card", "aria-label": label },
    h("div", { class: "stat-label" }, label),
    h("div", { class: "stat-value" }, value),
    meta ? h("div", { class: "stat-meta" }, meta) : "",
  );
}

export function statusBadge(value) {
  const normalized = String(value || "unknown").toLowerCase();
  return h(
    "span",
    { class: "status status-" + normalized },
    h("span", { class: "status-dot", "aria-hidden": "true" }),
    normalized.replaceAll("_", " "),
  );
}

export function skeleton({ className = "skeleton-row" } = {}) {
  return h("div", { class: "skeleton " + className, role: "presentation" });
}

export function skeletonGrid(count = 4, className = "skeleton-block") {
  return Array.from({ length: count }, () => skeleton({ className }));
}

export function alert({ tone = "danger", title = "", message = "" } = {}) {
  return h(
    "div",
    { class: "alert alert-" + tone, role: tone === "danger" ? "alert" : "status" },
    h("div", {}, title ? h("strong", {}, title + " ") : "", message),
  );
}

export function emptyState({ icon = "—", title, message, action = null } = {}) {
  return h(
    "div",
    { class: "empty" },
    h("div", { class: "empty-icon", "aria-hidden": "true" }, icon),
    h("h3", { class: "empty-title" }, title),
    h("p", { class: "empty-message" }, message),
    action,
  );
}

export function loadingInline(label = "Loading") {
  return h("span", { class: "loading-inline", role: "status" }, h("span", { class: "spinner", "aria-hidden": "true" }), label);
}

export function createDialog({ title, description = "", content, onClose }) {
  const titleId = "dialog-title-" + crypto.randomUUID();
  const descriptionId = description ? "dialog-desc-" + crypto.randomUUID() : "";
  const backdrop = h("div", { class: "modal-root", role: "presentation" });
  const dialog = h(
    "div",
    {
      class: "modal",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": titleId,
      "aria-describedby": descriptionId || undefined,
      tabindex: "-1",
    },
  );
  const closeButton = iconButton({ label: "Close dialog", icon: "×", onClick: () => close() });
  const header = h(
    "div",
    { class: "modal-header" },
    h("div", {}, h("h2", { class: "modal-title", id: titleId }, title), description ? h("p", { class: "modal-description", id: descriptionId }, description) : ""),
    closeButton,
  );
  dialog.append(header, h("div", { class: "modal-body" }, content));
  backdrop.appendChild(dialog);
  let previousFocus = null;

  function focusables() {
    return [...dialog.querySelectorAll("button, input, select, textarea, a[href], [tabindex]:not([tabindex='-1'])")]
      .filter((el) => !el.disabled && el.offsetParent !== null);
  }

  function keydown(event) {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key !== "Tab") return;
    const list = focusables();
    if (!list.length) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = list[0];
    const last = list[list.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function open() {
    previousFocus = document.activeElement;
    document.body.classList.add("modal-open");
    document.body.appendChild(backdrop);
    dialog.addEventListener("keydown", keydown);
    queueMicrotask(() => (focusables()[0] || dialog).focus());
  }

  function close() {
    dialog.removeEventListener("keydown", keydown);
    backdrop.remove();
    document.body.classList.remove("modal-open");
    previousFocus?.focus?.();
    onClose?.();
  }

  return { root: backdrop, dialog, open, close };
}

export function tokenBox({ token, warning = "Store this value securely. It is only shown here and will not be retrievable later." }) {
  const value = h("code", { class: "token-value", tabindex: "0" }, token);
  const copy = button({
    label: "Copy token",
    size: "sm",
    onClick: async (event) => {
      const btn = event.currentTarget;
      try {
        await navigator.clipboard.writeText(token);
        btn.textContent = "Copied";
      } catch {
        btn.textContent = "Copy failed";
      }
      setTimeout(() => (btn.textContent = "Copy token"), 1400);
    },
  });
  return h("div", { class: "token-box" }, h("strong", {}, "One-time credential"), value, h("div", { class: "field-hint" }, warning), h("div", { class: "form-actions" }, copy));
}

export function toastStack() {
  const root = h("div", { class: "toast-stack", "aria-live": "polite", "aria-atomic": "false" });
  document.body.appendChild(root);

  function push({ title = "Notification", message = "", tone = "default", timeout = 4500 } = {}) {
    const item = h(
      "div",
      { class: "toast", role: tone === "error" ? "alert" : "status" },
      h("div", { class: "toast-title" }, title),
      message ? h("div", { class: "toast-message" }, message) : "",
    );
    root.appendChild(item);
    setTimeout(() => item.remove(), timeout);
  }

  return { push, root };
}