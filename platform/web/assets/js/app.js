import { api, list, setUnauthorizedHandler } from "./api.js";
import { createStore } from "./state.js";
import { alert, button, createDialog, h, toastStack, tokenBox } from "./components.js";
import {
  formatDate,
  formatDuration,
  loadAverage,
  metricPercent,
  uptime,
} from "./format.js";
import {
  auditView,
  loginView,
  overviewView,
  registerServerForm,
  serverDetailView,
  serversView,
  shell,
} from "./views.js";

const root = document.getElementById("app-root");
const toasts = toastStack();
const ORG_KEY = "uvps.active_org";
const serviceOptions = [
  "ssh",
  "nginx",
  "haproxy",
  "xray",
  "hysteria-server",
  "unified-vps-panel",
  "unified-vps-wstunnel-ssh",
  "unified-vps-ws-payload-ssh",
];

const store = createStore({
  auth: "checking",
  me: null,
  organizations: [],
  activeOrgId: "",
  route: parseRoute(),
  servers: [],
  serversCursor: "",
  serversLoading: false,
  serversError: "",
  events: [],
  eventsCursor: "",
  eventsLoading: false,
  eventsError: "",
  server: null,
  commands: [],
  commandsCursor: "",
  detailLoading: false,
  detailError: "",
});

let renderQueued = false;
let routeRequestId = 0;
let loginBusy = false;
let refreshTimer = 0;

function parseRoute() {
  const raw = location.hash.replace(/^#/, "") || "/overview";
  const match = raw.match(/^\/servers\/([^/]+)$/);
  if (match) return { name: "server", id: decodeURIComponent(match[1]) };
  if (raw === "/servers") return { name: "servers" };
  if (raw === "/audit") return { name: "audit" };
  return { name: "overview" };
}

function safeStorageGet(key) {
  try {
    return localStorage.getItem(key) || "";
  } catch {
    return "";
  }
}

function safeStorageSet(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Non-critical preference; private browsing can reject storage.
  }
}

function safeStorageRemove(key) {
  try {
    localStorage.removeItem(key);
  } catch {
    // Non-critical preference.
  }
}

function orgHeaders() {
  return store.get().activeOrgId
    ? { "X-Organization-ID": store.get().activeOrgId }
    : {};
}

function setAuthAnonymous() {
  const current = store.get();
  if (current.auth === "anonymous") return;
  store.update({
    auth: "anonymous",
    authError: "",
    me: null,
    organizations: [],
    activeOrgId: "",
    server: null,
    servers: [],
    events: [],
    commands: [],
  });
  stopRefresh();
  queueRender();
}

function queueRender() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    render();
  });
}

function render() {
  const state = store.get();
  if (state.auth === "checking") {
    root.replaceChildren(
      h("main", { class: "auth-shell" }, h("section", { class: "surface auth-card", "aria-busy": "true" }, h("div", { class: "skeleton skeleton-text" }), h("div", { class: "skeleton skeleton-block", style: { marginTop: "12px" } }))),
    );
    return;
  }
  if (state.auth !== "authenticated") {
    root.replaceChildren(
      loginView({
        error: state.authError || "",
        busy: state.auth === "signing-in",
        onSubmit: handleLogin,
      }),
    );
    return;
  }

  const route = state.route;
  const activeRoute = route.name === "server" ? "servers" : route.name;
  let title = route.name === "overview" ? "Overview" : route.name === "servers" ? "Servers" : route.name === "audit" ? "Audit log" : (state.server?.name || "Server");
  let content;

  if (route.name === "overview") {
    content = overviewView({
      servers: state.servers,
      events: state.events,
      loading: state.serversLoading || state.eventsLoading,
      error: state.serversError || state.eventsError,
      onRefresh: () => loadOverview(true),
      onOpenServer: (id) => (location.hash = "#/servers/" + encodeURIComponent(id)),
      onRegister: openRegisterDialog,
    });
  } else if (route.name === "servers") {
    content = serversView({
      servers: state.servers,
      loading: state.serversLoading,
      error: state.serversError,
      nextCursor: state.serversCursor,
      onNext: () => loadServers({ append: true }),
      onOpenServer: (id) => (location.hash = "#/servers/" + encodeURIComponent(id)),
      onRegister: openRegisterDialog,
      onRefresh: () => loadServers({ reset: true }),
    });
  } else if (route.name === "audit") {
    content = auditView({
      events: state.events,
      loading: state.eventsLoading,
      error: state.eventsError,
      nextCursor: state.eventsCursor,
      onNext: () => loadEvents({ append: true }),
      onRefresh: () => loadEvents({ reset: true }),
    });
  } else {
    content = serverDetailView({
      server: state.server,
      commands: state.commands,
      commandCursor: state.commandsCursor,
      loading: state.detailLoading,
      error: state.detailError,
      onBack: () => (location.hash = "#/servers"),
      onRefresh: () => loadServerDetail(route.id),
      onHealthReport: () => queueCommand(route.id, "health.report", {}),
      onRestartService: () => openRestartDialog(route.id),
      onRotateToken: () => openRotateTokenDialog(route.id),
      onCancelCommand: (id) => cancelCommand(route.id, id),
      onMoreCommands: () => loadCommands(route.id, { append: true }),
    });
  }

  root.replaceChildren(
    shell({
      pageTitle: title,
      activeRoute,
      me: state.me,
      organizations: state.organizations,
      activeOrgId: state.activeOrgId,
      content,
      onLogout: handleLogout,
      onOrganizationChange: handleOrganizationChange,
    }),
  );

}

async function bootstrapSession() {
  try {
    const me = await api.get("/v1/me");
    const organizations = await api.get("/v1/organizations");
    if (!organizations.length) throw new Error("Your account has no organization membership.");

    const savedOrg = safeStorageGet(ORG_KEY);
    const activeOrgId = organizations.some((org) => org.id === savedOrg) ? savedOrg : organizations[0].id;

    store.update({
      auth: "authenticated",
      me,
      organizations,
      activeOrgId,
      authError: "",
    });
    safeStorageSet(ORG_KEY, activeOrgId);
    await loadCurrentRoute();
  } catch (error) {
    if (error.status === 401) {
      setAuthAnonymous();
    } else {
      store.update({
        auth: "anonymous",
        authError: error.message || "Unable to reach the control plane.",
      });
      queueRender();
    }
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const email = form.querySelector("#login-email")?.value?.trim();
  const password = form.querySelector("#login-password")?.value || "";
  if (loginBusy) return;
  loginBusy = true;
  const submitButton = form.querySelector("button[type='submit']");
  if (submitButton) submitButton.disabled = true;

  try {
    await api.post("/v1/auth/login", { email, password });
    const me = await api.get("/v1/me");
    const organizations = await api.get("/v1/organizations");
    if (!organizations.length) throw new Error("The account has no organization membership.");
    const savedOrg = safeStorageGet(ORG_KEY);
    const activeOrgId = organizations.some((org) => org.id === savedOrg) ? savedOrg : organizations[0].id;
    store.update({ auth: "authenticated", me, organizations, activeOrgId, authError: "" });
    safeStorageSet(ORG_KEY, activeOrgId);
    startRefresh();
    history.replaceState(null, "", location.pathname + location.search + "#/overview");
    store.update({ route: { name: "overview" } });
    await loadCurrentRoute();
    toasts.push({ title: "Signed in", message: "Control-plane session established." });
  } catch (error) {
    store.update({ auth: "anonymous", authError: error.message });
    queueRender();
  } finally {
    loginBusy = false;
    if (submitButton) submitButton.disabled = false;
  }
}

async function handleLogout() {
  try {
    await api.post("/v1/auth/logout");
  } catch {
    // Local session state still needs to be cleared when the network is unavailable.
  }
  setAuthAnonymous();
  safeStorageRemove(ORG_KEY);
}

async function handleOrganizationChange(orgId) {
  if (!store.get().organizations.some((org) => org.id === orgId)) return;
  store.update({
    activeOrgId: orgId,
    servers: [],
    events: [],
    commands: [],
    server: null,
    serversCursor: "",
    eventsCursor: "",
    commandsCursor: "",
    route: { name: "overview" },
    serversError: "",
    eventsError: "",
  });
  safeStorageSet(ORG_KEY, orgId);
  history.replaceState(null, "", location.pathname + location.search + "#/overview");
  await loadOverview(false);
}

async function loadCurrentRoute() {
  const route = store.get().route;
  if (route.name === "overview") return loadOverview(false);
  if (route.name === "servers") return loadServers({ reset: true });
  if (route.name === "audit") return loadEvents({ reset: true });
  return loadServerDetail(route.id);
}

async function loadOverview(force = false) {
  const current = store.get();
  if (current.serversLoading && !force) return;
  const requestId = ++routeRequestId;
  store.update({ serversLoading: true, eventsLoading: true, serversError: "", eventsError: "" });
  queueRender();

  const [serverResult, eventResult] = await Promise.allSettled([
    list("/v1/servers", { limit: 8, headers: orgHeaders(), params: { include_metrics: "true" } }),
    list("/v1/events", { limit: 6, headers: orgHeaders() }),
  ]);

  if (requestId !== routeRequestId || store.get().route.name !== "overview") return;

  const patch = { serversLoading: false, eventsLoading: false };
  if (serverResult.status === "fulfilled") {
    patch.servers = serverResult.value.items;
    patch.serversCursor = serverResult.value.nextCursor;
  } else {
    patch.serversError = serverResult.reason?.message || "Unable to load servers.";
  }
  if (eventResult.status === "fulfilled") {
    patch.events = eventResult.value.items;
    patch.eventsCursor = eventResult.value.nextCursor;
  } else {
    patch.eventsError = eventResult.reason?.message || "Unable to load events.";
  }
  store.update(patch);
  queueRender();
}

async function loadServers({ append = false, reset = false } = {}) {
  const state = store.get();
  if (state.serversLoading) return;
  const cursor = reset ? "" : state.serversCursor;
  if (append && !cursor) return;

  const requestId = ++routeRequestId;
  store.update({
    serversLoading: true,
    serversError: "",
    ...(reset ? { servers: [], serversCursor: "" } : {}),
  });
  queueRender();

  try {
    const result = await list("/v1/servers", {
      limit: 40,
      cursor,
      headers: orgHeaders(),
      params: { include_metrics: "true" },
    });
    if (requestId !== routeRequestId || store.get().route.name !== "servers") return;
    store.update({
      servers: append ? store.get().servers.concat(result.items) : result.items,
      serversCursor: result.nextCursor,
      serversLoading: false,
    });
  } catch (error) {
    if (requestId !== routeRequestId || store.get().route.name !== "servers") return;
    store.update({ serversLoading: false, serversError: error.message });
  }
  queueRender();
}

async function loadEvents({ append = false, reset = false } = {}) {
  const state = store.get();
  if (state.eventsLoading) return;
  const cursor = reset ? "" : state.eventsCursor;
  if (append && !cursor) return;

  const requestId = ++routeRequestId;
  store.update({
    eventsLoading: true,
    eventsError: "",
    ...(reset ? { events: [], eventsCursor: "" } : {}),
  });
  queueRender();

  try {
    const result = await list("/v1/events", {
      limit: 50,
      cursor,
      headers: orgHeaders(),
    });
    if (requestId !== routeRequestId || store.get().route.name !== "audit") return;
    store.update({
      events: append ? store.get().events.concat(result.items) : result.items,
      eventsCursor: result.nextCursor,
      eventsLoading: false,
    });
  } catch (error) {
    if (requestId !== routeRequestId || store.get().route.name !== "audit") return;
    store.update({ eventsLoading: false, eventsError: error.message });
  }
  queueRender();
}

async function loadCommands(serverId, { append = false } = {}) {
  const state = store.get();
  if (state.detailLoading) return;
  const cursor = append ? state.commandsCursor : "";
  if (append && !cursor) return;

  try {
    const result = await list("/v1/servers/" + encodeURIComponent(serverId) + "/commands", {
      limit: 30,
      cursor,
      headers: orgHeaders(),
    });
    if (store.get().route.name !== "server" || store.get().route.id !== serverId) return;
    store.update({
      commands: append ? store.get().commands.concat(result.items) : result.items,
      commandsCursor: result.nextCursor,
    });
    queueRender();
  } catch (error) {
    toasts.push({ title: "Commands unavailable", message: error.message, tone: "error" });
  }
}

async function loadServerDetail(serverId) {
  const requestId = ++routeRequestId;
  store.update({
    detailLoading: true,
    detailError: "",
    server: null,
    commands: [],
    commandsCursor: "",
  });
  queueRender();

  try {
    const [server, commandResult] = await Promise.all([
      api.get("/v1/servers/" + encodeURIComponent(serverId), { headers: orgHeaders() }),
      list("/v1/servers/" + encodeURIComponent(serverId) + "/commands", { limit: 30, headers: orgHeaders() }),
    ]);
    if (requestId !== routeRequestId || store.get().route.id !== serverId) return;
    store.update({
      server,
      commands: commandResult.items,
      commandsCursor: commandResult.nextCursor,
      detailLoading: false,
    });
  } catch (error) {
    if (requestId !== routeRequestId || store.get().route.id !== serverId) return;
    store.update({ detailLoading: false, detailError: error.message });
  }
  queueRender();
}

async function queueCommand(serverId, commandType, payload) {
  try {
    const command = await api.post(
      "/v1/servers/" + encodeURIComponent(serverId) + "/commands",
      {
        command_type: commandType,
        payload,
        idempotency_key: crypto.randomUUID(),
      },
      { headers: orgHeaders() },
    );
    toasts.push({ title: "Command queued", message: commandType + " was accepted by the control plane." });
    await loadServerDetail(serverId);
  } catch (error) {
    toasts.push({ title: "Command failed", message: error.message, tone: "error" });
  }
}

async function cancelCommand(serverId, commandId) {
  try {
    await api.post(
      "/v1/servers/" + encodeURIComponent(serverId) + "/commands/" + encodeURIComponent(commandId) + "/cancel",
      undefined,
      { headers: orgHeaders() },
    );
    toasts.push({ title: "Command cancelled", message: "The queued command was cancelled." });
    await loadServerDetail(serverId);
  } catch (error) {
    toasts.push({ title: "Unable to cancel", message: error.message, tone: "error" });
  }
}

function tokenDialog(title, token, description) {
  const dialog = createDialog({
    title,
    description,
    content: h("div", {}, tokenBox({ token })),
  });
  dialog.open();
}

function openRegisterDialog() {
  let busy = false;
  const content = h("div");
  const dialog = createDialog({
    title: "Register server",
    description: "Create a fleet record and receive a one-time node token.",
    content,
  });

  const submit = async (event) => {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const name = form.querySelector("#server-name").value.trim();
    const hostname = form.querySelector("#server-host").value.trim() || null;
    const ipv4 = form.querySelector("#server-ipv4").value.trim() || null;
    const ipv6 = form.querySelector("#server-ipv6").value.trim() || null;
    busy = true;
    form.querySelector("button[type=submit]").disabled = true;
    try {
      const result = await api.post("/v1/servers", { name, hostname, public_ipv4: ipv4, public_ipv6: ipv6 }, { headers: orgHeaders() });
      dialog.close();
      tokenDialog(
        "Server token",
        result.node_token,
        "Copy the token into the node-agent environment. It is returned once and is never stored in plaintext.",
      );
      toasts.push({ title: "Server registered", message: "The server is now available in the fleet." });
      if (store.get().route.name === "overview") await loadOverview(true);
      else if (store.get().route.name === "servers") await loadServers({ reset: true });
    } catch (error) {
      busy = false;
      form.querySelector("button[type=submit]").disabled = false;
      const existing = form.querySelector("[role=alert]");
      if (existing) existing.remove();
      form.insertBefore(alert({ tone: "danger", title: "Registration failed", message: error.message }), form.firstChild);
    }
  };

  const form = registerServerForm({
    onSubmit: submit,
    onCancel: () => dialog.close(),
  });
  content.appendChild(form);
  dialog.open();
}

function openRestartDialog(serverId) {
  const select = h("select", { id: "restart-service", class: "select", autofocus: "" });
  for (const service of serviceOptions) select.appendChild(h("option", { value: service }, service));
  const content = h(
    "div",
    { class: "stack-sm" },
    h("div", { class: "field" }, h("label", { for: "restart-service" }, "Service"), select),
    alert({
      tone: "warning",
      title: "Privileged action",
      message: "The node agent will restart only this allowlisted systemd service. No arbitrary shell command is sent.",
    }),
  );
  const dialog = createDialog({
    title: "Restart service",
    description: "Queue a controlled maintenance command.",
    content,
  });
  const action = button({
    label: "Queue restart",
    variant: "danger",
    onClick: async () => {
      action.disabled = true;
      await queueCommand(serverId, "service.restart", { service: select.value });
      dialog.close();
    },
  });
  dialog.dialog.querySelector(".modal-body").appendChild(h("div", { class: "form-actions", style: { marginTop: "14px" } }, action));
  dialog.open();
}

function openRotateTokenDialog(serverId) {
  const content = h(
    "div",
    { class: "stack-sm" },
    alert({
      tone: "warning",
      title: "Rotate this node credential?",
      message: "The current token will be revoked immediately. The node agent must be updated with the new token before it can reconnect.",
    }),
  );
  const dialog = createDialog({
    title: "Rotate node token",
    description: "Issue a new credential for the outbound agent.",
    content,
  });
  const action = button({
    label: "Rotate token",
    variant: "danger",
    onClick: async () => {
      action.disabled = true;
      try {
        const result = await api.post(
          "/v1/servers/" + encodeURIComponent(serverId) + "/tokens",
          undefined,
          { headers: orgHeaders() },
        );
        dialog.close();
        tokenDialog(
          "New node token",
          result.node_token,
          "The previous token is revoked. Store this value securely and update the node agent.",
        );
        toasts.push({ title: "Token rotated", message: "The previous node token is no longer valid." });
      } catch (error) {
        action.disabled = false;
        const body = dialog.dialog.querySelector(".modal-body");
        body.appendChild(alert({ tone: "danger", title: "Rotation failed", message: error.message }));
      }
    },
  });
  dialog.dialog.querySelector(".modal-body").appendChild(h("div", { class: "form-actions", style: { marginTop: "14px" } }, action));
  dialog.open();
}

function showConnectionBanner() {
  let banner = document.getElementById("connection-banner");
  if (!banner) {
    banner = h(
      "div",
      { id: "connection-banner", class: "banner", role: "status", "aria-live": "polite" },
      h("span", {}, "Connection unavailable. Changes will resume when connectivity returns."),
    );
    document.body.prepend(banner);
  }
  banner.classList.toggle("is-visible", navigator.onLine === false);
}

function startRefresh() {
  stopRefresh();
  refreshTimer = window.setInterval(() => {
    if (document.hidden || store.get().auth !== "authenticated") return;
    const route = store.get().route;
    if (route.name === "overview") loadOverview(true);
    else if (route.name === "server" && store.get().server) loadServerDetail(route.id);
  }, 30000);
}

function stopRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = 0;
  }
}

window.addEventListener("hashchange", async () => {
  store.update({ route: parseRoute() });
  routeRequestId += 1;
  queueRender();
  if (store.get().auth === "authenticated") await loadCurrentRoute();
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) return;
  if (store.get().auth === "authenticated") loadCurrentRoute();
});

window.addEventListener("online", showConnectionBanner);
window.addEventListener("offline", showConnectionBanner);

setUnauthorizedHandler(setAuthAnonymous);
render();
showConnectionBanner();
bootstrapSession();