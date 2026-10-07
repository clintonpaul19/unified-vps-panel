# Unified VPS Frontend UI System

## Purpose

The control-plane web client is a small, framework-free application shell designed to remain easy to deploy while applying production frontend architecture: reusable primitives, explicit state, responsive layouts, accessible interaction patterns, resilient network handling and bounded data fetching.

The browser consumes the existing /v1 API. It does not own authorization state, server truth, command execution or node credentials.

## Architecture

    platform/web/
    ├── index.html
    └── assets/
        ├── css/
        │   └── app.css
        └── js/
            ├── api.js
            ├── state.js
            ├── format.js
            ├── components.js
            ├── views.js
            └── app.js

The layers have one-way dependencies:

    app.js
      ├── views.js
      │    ├── components.js
      │    └── format.js
      ├── api.js
      └── state.js

index.html loads app.js. app.js talks to the same-origin /v1 API. FastAPI serves /assets through StaticFiles, keeping the control-plane container self-contained.

## Component model

components.js is the public UI primitive layer. Components are DOM factories with small, explicit APIs. They do not know about servers, organizations or transport APIs.

### h(tag, attrs, children)

The low-level DOM factory.

    h("button", {
      type: "button",
      class: "btn btn-primary",
      onClick: handleSave,
      "aria-label": "Save changes",
    }, "Save");

Children are inserted with text nodes/appendChild rather than HTML interpolation, so API values are not treated as markup.

### button(props)

Props:

    label        string      required
    variant      primary | secondary | danger | ghost
    size         md | sm
    type         button | submit
    onClick      function
    disabled     boolean
    icon         string
    ariaLabel    string

Example:

    button({
      label: "Register server",
      variant: "primary",
      size: "sm",
      onClick: openRegisterDialog,
    });

### statusBadge(value)

Used for server and command state. The component renders a text label plus a visual status indicator.

### card(props)

Props:

    title        string
    subtitle     string
    actions      Node | null
    children     Node | Node[]

### statCard(props)

Props:

    label        string
    value        string
    meta         string

### emptyState(props)

Props:

    icon         string
    title        string
    message      string
    action       Node | null

### alert(props)

Props:

    tone         danger | warning
    title        string
    message      string

### createDialog(props)

Props:

    title        string
    description  string
    content      Node
    onClose      function

The dialog implements:
- role=dialog and aria-modal
- labelled/described semantics
- Escape-to-close
- Tab focus trapping
- focus restoration
- scroll locking

### tokenBox(props)

Props:

    token        string
    warning      string

This component is deliberately narrow. Node credentials are displayed only after successful registration/token rotation and are not persisted in browser storage.

## Application state

state.js exposes createStore(initial).

    const store = createStore({
      route: { name: "overview" },
      auth: "checking",
      servers: [],
    });

    store.update({ auth: "authenticated" });

    const unsubscribe = store.subscribe((state) => {
      // react to a state transition
    });

Page data is replaced or appended explicitly. This makes cursor pagination and stale-request handling easy to reason about without a large framework runtime.

## API boundary

api.js is the only browser module that owns HTTP semantics.

### api.get(path, options)

    const server = await api.get(
      "/v1/servers/" + encodeURIComponent(serverId),
      { headers: { "X-Organization-ID": activeOrgId } },
    );

### api.post(path, body, options)

    await api.post(
      "/v1/servers/" + encodeURIComponent(serverId) + "/commands",
      {
        command_type: "health.report",
        payload: {},
        idempotency_key: crypto.randomUUID(),
      },
      { headers: { "X-Organization-ID": activeOrgId } },
    );

### list(path, options)

The list helper supports limit, opaque cursor, query parameters and AbortSignal, and returns:

    {
      items: [...],
      nextCursor: string,
      requestId: string
    }

### Error contract

Failures are normalized to ApiError:

    message
    status
    requestId

This keeps UI error handling independent from ad-hoc response parsing.

## Views

views.js owns composition, not data fetching.

Current views:

    loginView
    overviewView
    serversView
    serverDetailView
    auditView
    registerServerForm
    shell

Page responsibilities:

- Login: authentication form and failure state.
- Overview: fleet summary, top servers and latest activity.
- Servers: cursor-paginated fleet inventory.
- Server detail: full metrics, command queue and privileged typed actions.
- Audit: cursor-paginated organization activity.
- Shell: desktop/mobile navigation, account context and organization selector.

## Routing

Hash routing avoids additional server-side rewrite configuration:

    #/overview
    #/servers
    #/servers/<uuid>
    #/audit

The backend still serves / as the application entrypoint.

## Loading, empty and error states

Every data-bearing page has three explicit branches:

    loading → skeleton
    success + no rows → empty state
    failure → error alert + retry

A successful empty result is never represented by a blank page.

The dashboard also exposes a global connectivity banner and pauses refresh while the browser tab is hidden.

## Responsive behavior

Desktop uses a persistent sidebar. Tablet and mobile use an off-canvas navigation drawer. Grids collapse progressively, forms move to one column and wide tables become horizontally scrollable rather than forcing unreadable cells.

## Accessibility baseline

The system includes semantic landmarks, a skip link, visible keyboard focus, aria-current navigation, explicit form labels, live regions, modal focus management, reduced-motion support, descriptive button labels and table captions.

Status is always rendered as text in addition to the visual indicator so color is not the only signal.

## Performance model

The client stays bounded:

- overview loads at most 8 servers and 6 events
- fleet inventory loads 40 servers per page
- audit loads 50 events per page
- server detail loads 30 commands
- server detail fetches metrics only when opened
- cursor pagination avoids offset growth
- hidden tabs stop background refresh
- request generations prevent stale responses from overwriting current state
- the API backend compresses larger payloads

The frontend deliberately does not render thousands of DOM nodes at once. Larger fleets should use server-side search/filtering and virtualization when those API features are introduced.

## Security boundaries

The frontend must not:
- store node tokens in localStorage/sessionStorage
- embed bootstrap secrets
- send arbitrary shell commands
- treat client-side role checks as authorization
- trust API metadata as HTML
- invent authorization decisions that belong to the API

The control plane remains responsible for organization scoping, permissions, credential hashing, command allowlists and token revocation.

## Adding a feature

1. Define or verify the API contract.
2. Add a narrow API call in api.js when necessary.
3. Compose existing primitives in a view.
4. Put display-only transformation in format.js.
5. Keep orchestration in app.js.
6. Add loading, empty, error and success states.
7. Exercise keyboard and mobile behavior.
8. Validate JavaScript syntax and backend static serving in CI.

## Best-practice rules

Prefer composition over bespoke DOM trees. Keep API/domain logic out of reusable components. Use DOM APIs instead of HTML interpolation. Keep mutations idempotent where possible. Use cursor pagination for growing collections. Never persist short-lived secrets in browser storage. Treat accessibility as part of each component's contract.

The current implementation is intentionally dependency-free. A framework can be introduced later for complex form state, virtualized grids, rich client-side data fetching or collaborative real-time UI without changing the API boundary or the core component contracts.