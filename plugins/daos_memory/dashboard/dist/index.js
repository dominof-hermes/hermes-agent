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

  function EventTable(props) {
    const items = props.items || [];
    if (!items.length) return h("div", { className: "dm-empty" }, "No records in this bounded view.");
    return h("div", { className: "dm-table-wrap" }, h("table", { className: "dm-table" },
      h("thead", null, h("tr", null,
        h("th", null, "Topic / Product"), h("th", null, "Summary"), h("th", null, "Type / Authority"),
        h("th", null, "Status"), h("th", null, "Updated"), h("th", null, "Actor")
      )),
      h("tbody", null, items.map(function (item) {
        return h("tr", { key: item.id },
          h("td", null, h("strong", null, item.topic), h("small", null, item.product)),
          h("td", null, h("strong", null, item.title), h("p", null, item.summary)),
          h("td", null, item.memory_type + " · " + item.authority_level),
          h("td", null, h("span", { className: "dm-status" }, item.status)),
          h("td", null, item.created_at ? new Date(item.created_at).toLocaleString() : "—"),
          h("td", null, item.actor)
        );
      }))
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
    const [secret, setSecret] = React.useState(null);
    const [error, setError] = React.useState("");
    const [loading, setLoading] = React.useState(true);

    function endpoint(selected) {
      if (selected === "Policies") return "/policies";
      if (selected === "Agent Access") return "/agents";
      const names = { "Current": "current", "Decisions": "decisions", "Agent Notes": "agent_notes", "History": "history" };
      return "/memory?view=" + names[selected] + "&limit=25";
    }

    function load(selected) {
      setLoading(true); setError("");
      api(endpoint(selected)).then(function (result) { setData(result); })
        .catch(function () { setData({ items: [] }); setError("Memory service unavailable (fail closed)."); })
        .finally(function () { setLoading(false); });
    }

    React.useEffect(function () { setSecret(null); load(view); }, [view]);

    function rotate(agent) {
      setError("");
      api("/agents/" + encodeURIComponent(agent) + "/rotate", { method: "POST" })
        .then(function (result) { setSecret(result); load(view); })
        .catch(function () { setSecret(null); setError("Rotation unavailable; no credential was issued."); });
    }

    function revoke(agent) {
      setSecret(null); setError("");
      api("/agents/" + encodeURIComponent(agent) + "/revoke", { method: "POST" })
        .then(function () { load(view); })
        .catch(function () { setError("Revocation could not be verified; access is treated as unavailable."); });
    }

    let body;
    if (loading) body = h("div", { className: "dm-empty" }, "Loading bounded view…");
    else if (view === "Policies") body = h(PolicyTable, { items: data.items });
    else if (view === "Agent Access") body = h(AgentAccess, { items: data.items, secret: secret, onRotate: rotate, onRevoke: revoke });
    else body = h(EventTable, { items: data.items });

    return h("main", { className: "dm-page" },
      h("header", { className: "dm-header" }, h("div", null,
        h("span", { className: "dm-kicker" }, "DAOS ORGANIZATIONAL MEMORY"), h("h1", null, "Memory"),
        h("p", null, "Current first. History on demand. Authority remains explicit.")
      ), h("button", { onClick: function () { load(view); } }, "Refresh")),
      h("nav", { className: "dm-tabs", "aria-label": "Memory views" }, VIEWS.map(function (name) {
        return h("button", { key: name, className: name === view ? "active" : "", onClick: function () { setView(name); } }, name);
      })),
      error && h(ErrorBox, { message: error }),
      body
    );
  }

  registry.register("daos_memory", MemoryPage);
})();
