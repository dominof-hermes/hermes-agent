(function () {
  "use strict";
  const SDK = window.__HERMES_PLUGIN_SDK__;
  const registry = window.__HERMES_PLUGINS__;
  if (!SDK || !registry) return;
  const React = SDK.React;
  const h = React.createElement;
  const VIEWS = ["Current", "Decisions", "Policies", "Agent Notes", "History", "Agent Access"];

  function api(path, options) {
    return SDK.fetchJSON("/api/plugins/daos_memory" + path, options);
  }

  function ErrorBox(props) {
    return h("div", { className: "dm-error", role: "alert" }, props.message || "Memory service unavailable");
  }

  function createLatestRequestChannel() {
    let generation = 0;
    let controller = null;
    return {
      start: function () {
        if (controller) controller.abort();
        generation += 1;
        controller = new AbortController();
        return { generation: generation, signal: controller.signal };
      },
      isCurrent: function (candidate) { return candidate === generation; },
      finish: function (candidate) { if (candidate === generation) controller = null; },
      invalidate: function () {
        generation += 1;
        if (controller) controller.abort();
        controller = null;
      }
    };
  }

  function handleDialogKey(event, focusableElements, onClose) {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== "Tab") return;
    if (!focusableElements.length) {
      event.preventDefault();
      return;
    }
    const first = focusableElements[0];
    const last = focusableElements[focusableElements.length - 1];
    if (!focusableElements.includes(document.activeElement)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function EventTable(props) {
    const items = props.items || [];
    const onSelect = props.onSelect;
    if (!items.length) return h("div", { className: "dm-empty" }, "No records in this bounded view.");
    return h("div", { className: "dm-table-wrap" }, h("table", { className: "dm-table" },
      h("thead", null, h("tr", null,
        h("th", null, "Topic / Product"), h("th", null, "Summary"), h("th", null, "Type / Authority"),
        h("th", null, "Status"), h("th", null, "Effective / Occurred"), h("th", null, "Actor")
      )),
      h("tbody", null, items.map(function (item) {
        function openDetail(event) { onSelect(item, event.currentTarget); }
        return h("tr", {
          key: item.id,
          className: "dm-event-row",
          role: "button",
          tabIndex: 0,
          "aria-label": "Open event detail: " + (item.title || item.id),
          onClick: openDetail,
          onKeyDown: function (event) {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              openDetail(event);
            }
          }
        },
          h("td", null, h("strong", null, item.topic), h("small", null, item.product)),
          h("td", null, h("strong", null, item.title), h("p", null, item.summary)),
          h("td", null, item.memory_type + " · " + item.authority_level),
          h("td", null, h("span", { className: "dm-status" }, item.status)),
          h("td", null,
            h("strong", null, item.effective_from ? new Date(item.effective_from).toLocaleString() : "—"),
            h("small", null, "Occurred " + (item.occurred_at ? new Date(item.occurred_at).toLocaleString() : "—"))
          ),
          h("td", null, item.actor)
        );
      }))
    ));
  }

  function EventDetail(props) {
    const item = props.item;
    const onClose = props.onClose;
    const returnFocus = props.returnFocus;
    const closeRef = React.useRef(null);
    const dialogRef = React.useRef(null);

    React.useEffect(function () {
      function handleKey(event) {
        const focusable = dialogRef.current ? Array.prototype.slice.call(dialogRef.current.querySelectorAll(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )) : [];
        handleDialogKey(event, focusable, onClose);
      }
      document.addEventListener("keydown", handleKey);
      if (closeRef.current) closeRef.current.focus();
      return function () {
        document.removeEventListener("keydown", handleKey);
        if (returnFocus && returnFocus.isConnected !== false) returnFocus.focus();
      };
    }, [onClose, returnFocus]);

    function value(raw, fallback) {
      return raw === null || raw === undefined || raw === "" ? (fallback || "—") : String(raw);
    }
    function date(raw, fallback) {
      return raw ? new Date(raw).toLocaleString() : (fallback || "—");
    }
    function field(label, raw, wide, extraClass) {
      return h("div", { className: "dm-detail-field" + (wide ? " wide" : "") + (extraClass ? " " + extraClass : "") },
        h("dt", null, label), h("dd", null, value(raw))
      );
    }

    return h("div", {
      className: "dm-drawer-backdrop",
      onMouseDown: function (event) { if (event.target === event.currentTarget) onClose(); }
    }, h("aside", {
      ref: dialogRef,
      className: "dm-drawer",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "dm-event-detail-title"
    },
      h("header", { className: "dm-drawer-header" }, h("div", null,
        h("span", { className: "dm-kicker" }, "Read-only event detail"),
        h("h2", { id: "dm-event-detail-title" }, value(item.title, "Memory Event"))
      ), h("button", { ref: closeRef, onClick: onClose, "aria-label": "Close event detail" }, "Close")),
      h("dl", { className: "dm-detail-grid" },
        field("Event ID", item.id, true, "mono"),
        field("Product", item.product), field("Topic", item.topic),
        field("Title", item.title, true),
        field("Summary", item.summary, true),
        h("div", { className: "dm-detail-field wide dm-detail-content" },
          h("dt", null, "Full Content"), h("dd", null, value(item.content))
        ),
        field("Memory Type", item.memory_type), field("Event Type", item.event_type),
        field("Status", item.status), field("Authority Level", item.authority_level),
        field("Actor", item.actor), field("Actor Role", item.actor_role),
        field("Source Interface", item.source_interface), field("Source Ref", item.source_ref, true),
        field("Occurred At", date(item.occurred_at)),
        field("Stored At", date(item.created_at)),
        field("Effective From", date(item.effective_from)),
        field("Effective To", date(item.effective_to)),
        field("Source Session At", date(item.source_session_at)),
        field("Updated At", date(item.updated_at, "— (immutable event)")),
        field("Supersedes", item.supersedes_id, true, "mono"),
        field("Related Event", item.related_event_id || item.related_event, true, "mono")
      )
    ));
  }

  function PolicyTable(props) {
    const items = props.items || [];
    if (!items.length) return h("div", { className: "dm-empty" }, "No active policies.");
    return h("div", { className: "dm-cards" }, items.map(function (item) {
      return h("article", { className: "dm-card", key: item.id },
        h("span", { className: "dm-kicker" }, item.category), h("h3", null, item.title), h("p", null, item.content)
      );
    }));
  }

  function AgentAccess(props) {
    const items = props.items || [];
    const onRotate = props.onRotate;
    const onRevoke = props.onRevoke;
    const secret = props.secret;
    return h(React.Fragment, null,
      secret && h("section", { className: "dm-secret", role: "status" },
        h("strong", null, "Bootstrap key — shown once"),
        h("code", null, secret.bootstrap_key),
        h("p", null, "Expires: " + new Date(secret.expires_at).toLocaleString() + " · max uses: " + secret.max_uses),
        h("button", { onClick: function () { navigator.clipboard.writeText(secret.bootstrap_key); } }, "Copy")
      ),
      h("div", { className: "dm-table-wrap" }, h("table", { className: "dm-table" },
        h("thead", null, h("tr", null, h("th", null, "Agent"), h("th", null, "Status"), h("th", null, "Last Access"), h("th", null, "Action"))),
        h("tbody", null, items.map(function (agent) {
          return h("tr", { key: agent.agent_id },
            h("td", null, agent.agent_id), h("td", null, h("span", { className: "dm-status" }, agent.status)),
            h("td", null, agent.last_access_at ? new Date(agent.last_access_at).toLocaleString() : "Never"),
            h("td", { className: "dm-actions" },
              h("button", { onClick: function () { onRotate(agent.agent_id); } }, "Rotate"),
              h("button", { className: "danger", onClick: function () { onRevoke(agent.agent_id); } }, "Revoke")
            )
          );
        }))
      ))
    );
  }

  function MemoryPage() {
    const [view, setView] = React.useState("Current");
    const [data, setData] = React.useState({ items: [] });
    const [selectedEvent, setSelectedEvent] = React.useState(null);
    const [secret, setSecret] = React.useState(null);
    const [error, setError] = React.useState("");
    const [loading, setLoading] = React.useState(true);
    const requestChannelRef = React.useRef(null);
    const returnFocusRef = React.useRef(null);
    const viewRef = React.useRef(view);
    if (!requestChannelRef.current) requestChannelRef.current = createLatestRequestChannel();
    viewRef.current = view;

    function endpoint(selected) {
      if (selected === "Policies") return "/policies";
      if (selected === "Agent Access") return "/agents";
      const names = { "Current": "current", "Decisions": "decisions", "Agent Notes": "agent_notes", "History": "history" };
      return "/memory?view=" + names[selected] + "&limit=25";
    }

    function load(selected) {
      const request = requestChannelRef.current.start();
      setLoading(true); setError("");
      api(endpoint(selected), { signal: request.signal }).then(function (result) {
        if (!requestChannelRef.current.isCurrent(request.generation) || viewRef.current !== selected) return;
        setData(result);
      }).catch(function (caught) {
        if (!requestChannelRef.current.isCurrent(request.generation) || viewRef.current !== selected) return;
        if (caught && caught.name === "AbortError") return;
        setData({ items: [] }); setError("Memory service unavailable (fail closed).");
      }).finally(function () {
        if (!requestChannelRef.current.isCurrent(request.generation) || viewRef.current !== selected) return;
        requestChannelRef.current.finish(request.generation);
        setLoading(false);
      });
    }

    React.useEffect(function () {
      setSecret(null); setSelectedEvent(null); load(view);
      return function () { requestChannelRef.current.invalidate(); };
    }, [view]);

    function openEvent(item, returnFocus) {
      returnFocusRef.current = returnFocus;
      setSelectedEvent(item);
    }

    function rotate(agent) {
      const actionView = view;
      setError("");
      api("/agents/" + encodeURIComponent(agent) + "/rotate", { method: "POST" })
        .then(function (result) {
          if (viewRef.current !== actionView) return;
          setSecret(result); load(actionView);
        })
        .catch(function () {
          if (viewRef.current !== actionView) return;
          setSecret(null); setError("Rotation unavailable; no credential was issued.");
        });
    }

    function revoke(agent) {
      const actionView = view;
      setSecret(null); setError("");
      api("/agents/" + encodeURIComponent(agent) + "/revoke", { method: "POST" })
        .then(function () { if (viewRef.current === actionView) load(actionView); })
        .catch(function () {
          if (viewRef.current === actionView) setError("Revocation could not be verified; access is treated as unavailable.");
        });
    }

    let body;
    if (loading) body = h("div", { className: "dm-empty" }, "Loading bounded view…");
    else if (view === "Policies") body = h(PolicyTable, { items: data.items });
    else if (view === "Agent Access") body = h(AgentAccess, { items: data.items, secret: secret, onRotate: rotate, onRevoke: revoke });
    else body = h(EventTable, { items: data.items, onSelect: openEvent });

    return h("main", { className: "dm-page" },
      h("header", { className: "dm-header" }, h("div", null,
        h("span", { className: "dm-kicker" }, "DAOS ORGANIZATIONAL MEMORY"), h("h1", null, "Memory"),
        h("p", null, "Effective context first. Stored time remains distinct from occurred time.")
      ), h("button", { onClick: function () { load(view); } }, "Refresh")),
      h("nav", { className: "dm-tabs", "aria-label": "Memory views" }, VIEWS.map(function (name) {
        return h("button", { key: name, className: name === view ? "active" : "", onClick: function () { setView(name); } }, name);
      })),
      error && h(ErrorBox, { message: error }),
      body,
      selectedEvent && h(EventDetail, {
        item: selectedEvent,
        returnFocus: returnFocusRef.current,
        onClose: function () { setSelectedEvent(null); }
      })
    );
  }

  window.__DAOS_MEMORY_INTERNALS__ = {
    createLatestRequestChannel: createLatestRequestChannel,
    handleDialogKey: handleDialogKey
  };
  registry.register("daos_memory", MemoryPage);
})();
