import {
  h,
  button,
  card,
  statCard,
  statusBadge,
  skeleton,
  emptyState,
  alert,
} from "./components.js";
import {
  displayAddress,
  formatDate,
  formatDuration,
  loadAverage,
  metricPercent,
  relativeTime,
  statusClass,
  uptime,
} from "./format.js";

function navLink(href, label, icon, active) {
  return h(
    "a",
    {
      class: "nav-link",
      href,
      "aria-current": active ? "page" : undefined,
    },
    h("span", { class: "nav-icon", "aria-hidden": "true" }, icon),
    h("span", {}, label),
  );
}

export function shell({
  pageTitle,
  activeRoute,
  me,
  organizations,
  activeOrgId,
  content,
  onLogout,
  onOrganizationChange,
}) {
  const mobileToggle = button({
    label: "Open navigation",
    variant: "ghost",
    onClick: () => {
      document.getElementById("sidebar")?.classList.add("is-open");
      document.getElementById("navBackdrop")?.classList.add("is-visible");
      mobileToggle.setAttribute("aria-expanded", "true");
    },
    icon: "☰",
    ariaLabel: "Open navigation",
  });
  mobileToggle.className += " mobile-nav-toggle";
  mobileToggle.setAttribute("aria-expanded", "false");

  const sidebar = h(
    "aside",
    { class: "sidebar", id: "sidebar", "aria-label": "Primary navigation" },
    h(
      "a",
      { class: "brand", href: "#/overview" },
      h("span", { class: "brand-mark", "aria-hidden": "true" }, "U"),
      h("span", {}, h("div", { class: "brand-title" }, "Unified VPS"), h("div", { class: "brand-subtitle" }, "Control plane")),
    ),
    h(
      "nav",
      { class: "nav", "aria-label": "Primary" },
      navLink("#/overview", "Overview", "◈", activeRoute === "overview"),
      navLink("#/servers", "Servers", "▣", activeRoute === "servers"),
      navLink("#/audit", "Audit log", "≡", activeRoute === "audit"),
    ),
    h(
      "div",
      { class: "sidebar-footer" },
      h(
        "div",
        { class: "account-meta" },
        h("strong", {}, me?.email || "Signed in"),
        h("span", {}, "Control-plane account"),
      ),
      button({ label: "Sign out", variant: "ghost", onClick: onLogout, size: "sm" }),
    ),
  );

  const backdrop = h("button", {
    id: "navBackdrop",
    class: "backdrop",
    type: "button",
    "aria-label": "Close navigation",
    onClick: () => closeNav(),
  });

  function closeNav() {
    sidebar.classList.remove("is-open");
    backdrop.classList.remove("is-visible");
    mobileToggle.setAttribute("aria-expanded", "false");
  }

  sidebar.addEventListener("click", (event) => {
    if (event.target.closest("a")) closeNav();
  });

  const orgControl = organizations.length > 1
    ? (() => {
        const select = h("select", {
          class: "select",
          "aria-label": "Organization",
          onChange: (event) => onOrganizationChange(event.target.value),
        });
        for (const org of organizations) {
          select.appendChild(h("option", { value: org.id, selected: org.id === activeOrgId }, org.name));
        }
        return h("div", { class: "org-select-wrap" }, select);
      })()
    : "";

  const topbar = h(
    "header",
    { class: "topbar" },
    h("div", { class: "topbar-left" }, mobileToggle, h("div", { class: "page-heading" }, h("div", { class: "eyebrow" }, "Unified VPS"), h("h1", {}, pageTitle))),
    h("div", { class: "topbar-right" }, orgControl),
  );

  return h(
    "div",
    { class: "app-shell" },
    sidebar,
    backdrop,
    h("section", { class: "workspace" }, topbar, h("main", { class: "content", id: "main-content", tabindex: "-1" }, content)),
  );
}

export function loginView({ error = "", busy = false, onSubmit }) {
  const email = h("input", {
    id: "login-email",
    class: "input",
    type: "email",
    autocomplete: "email",
    required: "",
    placeholder: "you@example.com",
  });
  const password = h("input", {
    id: "login-password",
    class: "input",
    type: "password",
    autocomplete: "current-password",
    minlength: "8",
    maxlength: "128",
    required: "",
    placeholder: "Password",
  });
  const form = h(
    "form",
    { class: "auth-form", onSubmit },
    h("div", { class: "field" }, h("label", { for: "login-email" }, "Email"), email),
    h("div", { class: "field" }, h("label", { for: "login-password" }, "Password"), password),
    error ? alert({ tone: "danger", title: "Sign in failed", message: error }) : "",
    button({ label: busy ? "Signing in…" : "Sign in", variant: "primary", type: "submit", disabled: busy }),
  );

  return h(
    "main",
    { class: "auth-shell" },
    h(
      "section",
      { class: "surface auth-card", "aria-labelledby": "login-title" },
      h("div", { class: "auth-brand" }, h("div", { class: "brand", style: { padding: "0" } }, h("span", { class: "brand-mark", "aria-hidden": "true" }, "U"), h("span", { class: "brand-title" }, "Unified VPS"))),
      h("h1", { id: "login-title" }, "Sign in"),
      h("p", { class: "sub" }, "Manage your VPS fleet from the control plane."),
      form,
    ),
  );
}

function renderServerCard(server, onOpen) {
  return h(
    "article",
    { class: "surface card server-card" },
    h(
      "div",
      { class: "server-card-top" },
      h(
        "div",
        { style: { minWidth: "0" } },
        h("h3", { class: "server-name" }, server.name),
        h("div", { class: "server-address" }, displayAddress(server)),
      ),
      statusBadge(server.status),
    ),
    h(
      "div",
      { class: "server-metrics" },
      h("div", { class: "metric" }, h("span", {}, "Memory"), h("strong", {}, metricPercent(server))),
      h("div", { class: "metric" }, h("span", {}, "Load"), h("strong", {}, loadAverage(server))),
      h("div", { class: "metric" }, h("span", {}, "Uptime"), h("strong", {}, uptime(server))),
      h("div", { class: "metric" }, h("span", {}, "Agent"), h("strong", {}, server.agent_version || "—")),
    ),
    h(
      "div",
      { class: "form-actions", style: { justifyContent: "flex-start" } },
      button({ label: "View server", size: "sm", variant: "secondary", onClick: () => onOpen(server.id) }),
    ),
  );
}

function renderServerSkeletons() {
  return h("div", { class: "grid grid-servers", "aria-busy": "true" }, Array.from({ length: 4 }, () => h("section", { class: "surface card stack-sm" }, skeleton({ className: "skeleton-text" }), skeleton({ className: "skeleton-text" }), skeleton({ className: "skeleton-block" }))));
}

function renderEventList(events) {
  if (!events.length) {
    return emptyState({ icon: "≡", title: "No activity yet", message: "Operational and security events will appear here as the control plane is used." });
  }
  return h(
    "div",
    { class: "list" },
    events.map((event) =>
      h(
        "div",
        { class: "list-row" },
        h("div", { class: "list-main" }, h("div", { class: "list-title" }, event.event_type), h("div", { class: "list-sub" }, event.server_id ? "Server " + event.server_id.slice(0, 8) : "Organization event")),
        h("div", { class: "list-sub" }, relativeTime(event.created_at)),
      ),
    ),
  );
}

export function overviewView({ servers, events, loading, error, onRefresh, onOpenServer, onRegister }) {
  const online = servers.filter((s) => s.status === "online").length;
  const degraded = servers.filter((s) => s.status === "degraded").length;
  const offline = servers.filter((s) => s.status === "offline").length;

  const stats = h(
    "div",
    { class: "grid grid-stats" },
    statCard({ label: "Total servers", value: loading ? "…" : String(servers.length), meta: "Fleet inventory" }),
    statCard({ label: "Online", value: loading ? "…" : String(online), meta: "Healthy heartbeats" }),
    statCard({ label: "Attention", value: loading ? "…" : String(degraded), meta: "Degraded nodes" }),
    statCard({ label: "Offline", value: loading ? "…" : String(offline), meta: "Needs investigation" }),
  );

  let serversContent;
  if (loading) serversContent = renderServerSkeletons();
  else if (error) serversContent = alert({ tone: "danger", title: "Servers unavailable", message: error });
  else if (!servers.length) {
    serversContent = emptyState({
      icon: "▣",
      title: "No servers registered",
      message: "Register your first VPS to start receiving agent heartbeats.",
      action: button({ label: "Register server", variant: "primary", onClick: onRegister }),
    });
  } else {
    serversContent = h("div", { class: "grid grid-servers" }, servers.slice(0, 8).map((server) => renderServerCard(server, onOpenServer)));
  }

  const recentEvents = card({
    title: "Recent activity",
    subtitle: "Latest audit events for the active organization.",
    actions: button({ label: "Audit log", size: "sm", onClick: () => (location.hash = "#/audit") }),
    children: [renderEventList(events)],
  });

  return h(
    "div",
    { class: "stack" },
    h(
      "div",
      { class: "section-header" },
      h("div", {}, h("p", { class: "eyebrow" }, "Fleet health"), h("h2", { class: "section-title" }, "Overview")),
      h("div", { class: "inline" }, button({ label: "Refresh", size: "sm", onClick: onRefresh, icon: "↻" }), button({ label: "Register server", variant: "primary", size: "sm", onClick: onRegister, icon: "+" })),
    ),
    stats,
    h(
      "div",
      { class: "grid grid-main" },
      card({ title: "Servers", subtitle: "Your latest VPS inventory.", actions: button({ label: "View all", size: "sm", onClick: () => (location.hash = "#/servers") }), children: [serversContent] }),
      recentEvents,
    ),
  );
}

export function serversView({ servers, loading, error, nextCursor, onNext, onOpenServer, onRegister, onRefresh }) {
  let content;
  if (loading) {
    content = h("div", { class: "grid grid-servers", "aria-busy": "true" }, Array.from({ length: 8 }, () => h("section", { class: "surface card stack-sm" }, skeleton({ className: "skeleton-text" }), skeleton({ className: "skeleton-block" }), skeleton({ className: "skeleton-text" }))));
  } else if (error) {
    content = alert({ tone: "danger", title: "Could not load servers", message: error });
  } else if (!servers.length) {
    content = emptyState({ icon: "▣", title: "No servers", message: "Register a VPS to populate your fleet.", action: button({ label: "Register server", variant: "primary", onClick: onRegister }) });
  } else {
    content = h("div", { class: "grid grid-servers" }, servers.map((server) => renderServerCard(server, onOpenServer)));
  }

  return h(
    "div",
    { class: "stack" },
    h(
      "div",
      { class: "section-header" },
      h("div", {}, h("p", { class: "eyebrow" }, "Fleet inventory"), h("h2", { class: "section-title" }, "Servers")),
      h("div", { class: "inline" }, button({ label: "Refresh", size: "sm", onClick: onRefresh, icon: "↻" }), button({ label: "Register server", variant: "primary", size: "sm", onClick: onRegister, icon: "+" })),
    ),
    content,
    nextCursor
      ? h("div", { class: "pagination" }, h("span", { class: "field-hint" }, "Showing " + servers.length + " servers"), button({ label: "Load more", size: "sm", onClick: onNext }))
      : "",
  );
}

function kv(label, value) {
  return h("div", { class: "kv" }, h("div", { class: "kv-label" }, label), h("div", { class: "kv-value" }, value || "—"));
}

function commandRow(command, onCancel) {
  const canCancel = command.status === "queued" || command.status === "sent";
  return h(
    "tr",
    {},
    h("td", {}, h("code", { class: "code" }, command.command_type)),
    h("td", {}, statusBadge(command.status)),
    h("td", {}, relativeTime(command.created_at)),
    h("td", {}, command.attempt_count),
    h("td", {}, command.error ? h("span", { title: command.error }, command.error) : "—"),
    h("td", {}, canCancel ? button({ label: "Cancel", size: "sm", variant: "danger", onClick: () => onCancel(command.id) }) : ""),
  );
}

export function serverDetailView({
  server,
  commands,
  commandCursor,
  loading,
  error,
  onBack,
  onRefresh,
  onHealthReport,
  onRestartService,
  onRotateToken,
  onCancelCommand,
  onMoreCommands,
}) {
  if (loading) {
    return h("div", { class: "stack", "aria-busy": "true" }, h("section", { class: "surface card stack-sm" }, skeleton({ className: "skeleton-text" }), skeleton({ className: "skeleton-block" }), skeleton({ className: "skeleton-block" })));
  }

  if (error || !server) {
    return h(
      "div",
      { class: "stack" },
      button({ label: "Back to servers", variant: "ghost", size: "sm", onClick: onBack, icon: "←" }),
      alert({ tone: "danger", title: "Server unavailable", message: error || "The server could not be loaded." }),
    );
  }

  const metrics = server.metrics || {};
  const commandTable = commands.length
    ? h(
        "div",
        { class: "table-wrap" },
        h(
          "table",
          { class: "table" },
          h("caption", {}, "Recent commands"),
          h("thead", {}, h("tr", {}, h("th", {}, "Command"), h("th", {}, "Status"), h("th", {}, "Created"), h("th", {}, "Attempts"), h("th", {}, "Error"), h("th", {}, "Actions"))),
          h("tbody", {}, commands.map((command) => commandRow(command, onCancelCommand))),
        ),
      )
    : emptyState({ icon: "⌘", title: "No commands", message: "Run a health report or service restart to create an operational command." });

  return h(
    "div",
    { class: "stack" },
    h("div", { class: "inline" }, button({ label: "Back to servers", variant: "ghost", size: "sm", onClick: onBack, icon: "←" })),
    h(
      "div",
      { class: "grid detail-grid" },
      h(
        "section",
        { class: "surface card detail-hero" },
        h(
          "div",
          { class: "detail-title-row" },
          h("div", {}, h("p", { class: "eyebrow" }, "Server"), h("h2", { class: "section-title" }, server.name), h("p", { class: "card-subtitle" }, displayAddress(server))),
          statusBadge(server.status),
        ),
        h(
          "div",
          { class: "form-actions", style: { justifyContent: "flex-start" } },
          button({ label: "Health report", size: "sm", variant: "primary", onClick: onHealthReport }),
          button({ label: "Restart service", size: "sm", onClick: onRestartService }),
          button({ label: "Rotate node token", size: "sm", variant: "danger", onClick: onRotateToken }),
          button({ label: "Refresh", size: "sm", onClick: onRefresh, icon: "↻" }),
        ),
        h(
          "div",
          { class: "kv-grid" },
          kv("Hostname", server.hostname),
          kv("IPv4", server.public_ipv4),
          kv("IPv6", server.public_ipv6),
          kv("Agent version", server.agent_version),
          kv("Last heartbeat", formatDate(server.last_seen_at)),
          kv("Load average", loadAverage(server)),
          kv("Memory", metricPercent(server)),
          kv("Uptime", uptime(server)),
          kv("Operating system", metrics.os),
          kv("Python", metrics.python),
          kv("Reported uptime", formatDuration(metrics.uptime_seconds)),
          kv("Server ID", server.id),
        ),
      ),
      card({
        title: "Command queue",
        subtitle: "Typed operations executed by the outbound node agent.",
        children: [commandTable, commandCursor ? h("div", { class: "pagination" }, h("span", { class: "field-hint" }, "Older commands available"), button({ label: "Load more", size: "sm", onClick: onMoreCommands })) : ""],
      }),
    ),
  );
}

export function auditView({ events, loading, error, nextCursor, onNext, onRefresh }) {
  let body;
  if (loading) {
    body = h("div", { class: "stack-sm", "aria-busy": "true" }, Array.from({ length: 7 }, () => skeleton({ className: "skeleton-row" })));
  } else if (error) {
    body = alert({ tone: "danger", title: "Could not load audit log", message: error });
  } else if (!events.length) {
    body = emptyState({ icon: "≡", title: "No audit events", message: "Activity will appear here after the first control-plane action." });
  } else {
    body = h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        { class: "table" },
        h("caption", {}, "Organization audit log"),
        h("thead", {}, h("tr", {}, h("th", {}, "Event"), h("th", {}, "Server"), h("th", {}, "Metadata"), h("th", {}, "Time"))),
        h(
          "tbody",
          {},
          events.map((event) =>
            h(
              "tr",
              {},
              h("td", {}, h("strong", {}, event.event_type)),
              h("td", {}, event.server_id ? event.server_id.slice(0, 8) : "Organization"),
              h("td", {}, h("code", { class: "code" }, JSON.stringify(event.metadata || {}))),
              h("td", {}, h("span", { title: formatDate(event.created_at) }, relativeTime(event.created_at))),
            ),
          ),
        ),
      ),
    );
  }

  return h(
    "div",
    { class: "stack" },
    h(
      "div",
      { class: "section-header" },
      h("div", {}, h("p", { class: "eyebrow" }, "Security and operations"), h("h2", { class: "section-title" }, "Audit log")),
      button({ label: "Refresh", size: "sm", onClick: onRefresh, icon: "↻" }),
    ),
    card({ title: "Recent events", subtitle: "Cursor-paginated and scoped to the active organization.", children: [body, nextCursor ? h("div", { class: "pagination" }, button({ label: "Load more", size: "sm", onClick: onNext })) : ""] }),
  );
}

export function registerServerForm({ onSubmit, busy = false }) {
  const name = h("input", { id: "server-name", class: "input", maxlength: "120", required: "", placeholder: "Production edge 01", autocomplete: "off" });
  const hostname = h("input", { id: "server-host", class: "input", maxlength: "255", placeholder: "node.example.com", autocomplete: "off" });
  const ipv4 = h("input", { id: "server-ipv4", class: "input", placeholder: "203.0.113.10", autocomplete: "off" });
  const ipv6 = h("input", { id: "server-ipv6", class: "input", placeholder: "2001:db8::10", autocomplete: "off" });

  const form = h(
    "form",
    { class: "form-grid", onSubmit },
    h("div", { class: "field field-full" }, h("label", { for: "server-name" }, "Server name"), name),
    h("div", { class: "field" }, h("label", { for: "server-host" }, "Hostname"), hostname),
    h("div", { class: "field" }, h("label", { for: "server-ipv4" }, "Public IPv4"), ipv4),
    h("div", { class: "field" }, h("label", { for: "server-ipv6" }, "Public IPv6"), ipv6),
    h("div", { class: "field field-full" }, h("div", { class: "field-hint" }, "The node agent uses the one-time token returned after registration to connect outbound to the control plane.")),
    h("div", { class: "form-actions field-full" }, button({ label: busy ? "Registering…" : "Register server", variant: "primary", type: "submit", disabled: busy }), button({ label: "Cancel", type: "button", onClick: () => onSubmit.cancel?.() })),
  );

  return form;
}

export { statusClass };