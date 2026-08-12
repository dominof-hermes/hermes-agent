(function () {
  "use strict";
  const SDK = window.__HERMES_PLUGIN_SDK__;
  const registry = window.__HERMES_PLUGINS__;
  if (!SDK || !registry) return;
  const React = SDK.React;
  const h = React.createElement;
  const VIEWS = ["Current", "Decisions", "Policies", "Agent Notes", "History", "Knowledge Vault", "Agent Access"];
  const EVENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  function api(path, options) {
    return SDK.fetchJSON("/api/plugins/daos_memory" + path, options);
  }

  function ErrorBox(props) {
    return h("div", { className: "dm-error", role: "alert" }, props.message || "Memory service unavailable");
  }

  function eventPath(eventId) {
    return "/memory/events/" + encodeURIComponent(eventId);
  }

  function eventIdFromPath(pathname) {
    const match = String(pathname || "").match(/^\/memory\/events\/([^/]+)\/?$/);
    if (!match) return null;
    let eventId;
    try { eventId = decodeURIComponent(match[1]); } catch (_) { return null; }
    return EVENT_ID_PATTERN.test(eventId) ? eventId : null;
  }

  function sourcePath(sourceId) {
    return "/memory/sources/" + encodeURIComponent(sourceId);
  }

  function sourceIdFromPath(pathname) {
    const match = String(pathname || "").match(/^\/memory\/sources\/([^/]+)\/?$/);
    if (!match) return null;
    let sourceId;
    try { sourceId = decodeURIComponent(match[1]); } catch (_) { return null; }
    return EVENT_ID_PATTERN.test(sourceId) ? sourceId : null;
  }

  function relationTargetFor(itemId, relation) {
    if (relation.from_event_id && relation.from_event_id !== itemId) return { kind: "event", id: relation.from_event_id };
    if (relation.to_event_id && relation.to_event_id !== itemId) return { kind: "event", id: relation.to_event_id };
    if (relation.from_source_id) return { kind: "source", id: relation.from_source_id };
    if (relation.to_source_id) return { kind: "source", id: relation.to_source_id };
    return null;
  }

  const INITIAL_EVENT_ID = eventIdFromPath(window.location && window.location.pathname);
  const INITIAL_SOURCE_ID = sourceIdFromPath(window.location && window.location.pathname);
  if (INITIAL_EVENT_ID || INITIAL_SOURCE_ID) {
    const bootstrapState = {
      dmMemoryDirect: INITIAL_EVENT_ID || INITIAL_SOURCE_ID,
      dmMemoryList: { view: "Current", scrollY: 0 }
    };
    window.history.replaceState(bootstrapState, "", "/memory");
    window.dispatchEvent(new PopStateEvent("popstate", { state: bootstrapState }));
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
        function openDetail(event) {
          if (item.item_kind === "SOURCE") props.onSourceSelect(item.id);
          else onSelect(item, event.currentTarget);
        }
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
          h("td", null, h("strong", null, item.title), h("p", null, item.summary || item.decision_content || item.content || "")),
          h("td", null, (item.item_kind || item.memory_type || item.note_type || item.source_type || "RECORD") + " · " + (item.authority_level || "—")),
          h("td", null, h("span", { className: "dm-status" }, item.status)),
          h("td", null,
            h("strong", null, item.effective_from ? new Date(item.effective_from).toLocaleString() : "—"),
            h("small", null, "Occurred " + (item.occurred_at ? new Date(item.occurred_at).toLocaleString() : "—"))
          ),
          h("td", null, item.actor || item.proposed_by || "Owner"),
          props.view === "Decisions" && item.status === "PENDING_OWNER_CONFIRM" ? h("td", { className: "dm-actions" },
            h("button", { onClick: function (event) { event.stopPropagation(); props.onDecision(item.id, "approve"); } }, "Approve"),
            h("button", { className: "danger", onClick: function (event) { event.stopPropagation(); props.onDecision(item.id, "reject"); } }, "Reject")
          ) : null
        );
      }))
    ));
  }

  function EventDetail(props) {
    const item = props.item;
    const knowledge = props.knowledge || { related_events: [], sources: [], relations: [], evidence_status: "insufficient_evidence" };
    const knowledgeStatus = props.knowledgeStatus || "loading";
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
    function date(raw, fallback) { return raw ? new Date(raw).toLocaleString() : (fallback || "—"); }
    function field(label, raw, wide, extraClass) {
      return h("div", { className: "dm-detail-field" + (wide ? " wide" : "") + (extraClass ? " " + extraClass : "") },
        h("dt", null, label), h("dd", null, value(raw))
      );
    }
    function endpoint(relation) {
      const target = relationTargetFor(item.id, relation);
      return target ? target.kind + ":" + target.id : "—";
    }

    return h("div", {
      className: "dm-drawer-backdrop",
      onMouseDown: function (event) { if (event.target === event.currentTarget) onClose(); }
    }, h("aside", {
      ref: dialogRef, className: "dm-drawer", role: "dialog", "aria-modal": "true",
      "aria-labelledby": "dm-event-detail-title"
    },
      h("header", { className: "dm-drawer-header" }, h("div", null,
        h("span", { className: "dm-kicker" }, "Read-only event detail"),
        h("h2", { id: "dm-event-detail-title" }, value(item.title, "Memory Event"))
      ), h("button", { ref: closeRef, onClick: onClose, "aria-label": "Close event detail" }, "Close")),
      h("dl", { className: "dm-detail-grid" },
        h("div", { className: "dm-detail-field wide mono" }, h("dt", null, "Event ID"),
          h("dd", null, h("a", { href: eventPath(item.id) }, value(item.id)))),
        field("Product", item.product), field("Topic", item.topic), field("Title", item.title, true),
        field("Summary", item.summary, true),
        h("div", { className: "dm-detail-field wide dm-detail-content" },
          h("dt", null, "Full Content"), h("dd", null, value(item.content))),
        field("Memory Type", item.memory_type), field("Event Type", item.event_type),
        field("Status", item.status), field("Authority Level", item.authority_level),
        field("Actor", item.actor), field("Actor Role", item.actor_role),
        field("Source Interface", item.source_interface), field("Source Ref", item.source_ref, true),
        field("Occurred At", date(item.occurred_at)), field("Stored At", date(item.created_at)),
        field("Effective From", date(item.effective_from)), field("Effective To", date(item.effective_to)),
        field("Source Session At", date(item.source_session_at)),
        field("Updated At", date(item.updated_at, "— (immutable event)")),
        field("Supersedes", item.supersedes_id, true, "mono"),
        field("Related Event", item.related_event_id || item.related_event, true, "mono")
      ),
      knowledgeStatus === "loading" ? h("section", { className: "dm-knowledge-section", "aria-live": "polite" },
        h("h3", null, "Related Knowledge"), h("p", null, "Loading provenance…")) :
      knowledgeStatus === "unavailable" ? h("section", { className: "dm-knowledge-section" },
        h("h3", null, "Related Knowledge"), h(ErrorBox, { message: "Knowledge provenance unavailable (fail closed)." })) :
      h("div", { className: "dm-knowledge-stack" },
      h("section", { className: "dm-knowledge-section" }, h("h3", null, "Related Knowledge"),
        knowledge.related_events && knowledge.related_events.length ? knowledge.related_events.map(function (related) {
          return h("a", { key: related.id, href: eventPath(related.id), onClick: function (event) {
            event.preventDefault(); props.onEventSelect(related.id);
          } }, related.memory_type + " · " + related.title);
        }) : h("p", null, "No related knowledge registered.")),
      h("section", { className: "dm-knowledge-section" }, h("h3", null, "Source Documents"),
        h("span", { className: "dm-status" }, knowledge.evidence_status || "insufficient_evidence"),
        knowledge.sources && knowledge.sources.length ? knowledge.sources.map(function (source) {
          return h("a", { key: source.id, href: sourcePath(source.id), onClick: function (event) {
            event.preventDefault(); props.onSourceSelect(source.id);
          } }, source.source_type + " · " + source.title);
        }) : h("p", null, "insufficient_evidence")),
      h("section", { className: "dm-knowledge-section" }, h("h3", null, "Relations"),
        knowledge.relations && knowledge.relations.length ? knowledge.relations.map(function (relation) {
          const target = relationTargetFor(item.id, relation);
          return h("div", { className: "dm-relation mono", key: relation.id },
            h("strong", null, relation.relation_type), target ? h("a", {
              href: target.kind === "event" ? eventPath(target.id) : sourcePath(target.id),
              onClick: function (event) {
                event.preventDefault();
                if (target.kind === "event") props.onEventSelect(target.id);
                else props.onSourceSelect(target.id);
              },
              "aria-label": relation.relation_type + " " + endpoint(relation)
            }, endpoint(relation)) : h("span", null, endpoint(relation)));
        }) : h("p", null, "No canonical relations registered.")))
    ));
  }

  function SourceDetail(props) {
    const source = props.source;
    const closeRef = React.useRef(null);
    const dialogRef = React.useRef(null);
    React.useEffect(function () {
      function handleKey(event) {
        const focusable = dialogRef.current ? Array.prototype.slice.call(dialogRef.current.querySelectorAll('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])')) : [];
        handleDialogKey(event, focusable, props.onClose);
      }
      document.addEventListener("keydown", handleKey);
      if (closeRef.current) closeRef.current.focus();
      return function () { document.removeEventListener("keydown", handleKey); };
    }, [props.onClose]);
    function show(value) { return value === null || value === undefined || value === "" ? "—" : String(value); }
    function row(label, value) { return h("div", { className: "dm-detail-field" }, h("dt", null, label), h("dd", null, show(value))); }
    return h("div", { className: "dm-drawer-backdrop", onMouseDown: function (event) { if (event.target === event.currentTarget) props.onClose(); } },
      h("aside", { ref: dialogRef, className: "dm-drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "dm-source-detail-title" },
        h("header", { className: "dm-drawer-header" }, h("div", null,
          h("span", { className: "dm-kicker" }, "Read-only raw source"),
          h("h2", { id: "dm-source-detail-title" }, show(source.title))),
          h("button", { ref: closeRef, onClick: props.onClose, "aria-label": "Close source detail" }, "Close")),
        h("dl", { className: "dm-detail-grid" },
          h("div", { className: "dm-detail-field wide mono" }, h("dt", null, "Source ID"), h("dd", null, h("a", { href: sourcePath(source.id) }, source.id))),
          row("Source Type", source.source_type), row("Source Interface", source.source_interface),
          row("Actor", source.actor), row("Participants", (source.participants || []).join(", ")),
          row("Occurred At", source.occurred_at ? new Date(source.occurred_at).toLocaleString() : "—"),
          row("Source Session At", source.source_session_at ? new Date(source.source_session_at).toLocaleString() : "—"),
          row("Repository", source.repository), row("Path", source.path), row("Commit SHA", source.commit_sha),
          row("Content Hash", source.content_hash), row("Access Scope", source.access_scope),
          row("Security Level", source.security_level), row("Redaction Status", source.redaction_status),
          h("div", { className: "dm-detail-field wide dm-detail-content" }, h("dt", null, "Raw Source Content"),
            h("dd", null, h("pre", null, show(source.content))))
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
    const busy = props.busy;
    const [copied, setCopied] = React.useState("");
    function copy(label, value) {
      navigator.clipboard.writeText(value).then(function () { setCopied(label); });
    }
    return h(React.Fragment, null,
      secret && h("section", { className: "dm-secret", role: "status" },
        h("strong", null, "Bootstrap key — shown once"),
        h("code", null, secret.bootstrap_key),
        h("p", null, "Expires: " + new Date(secret.expires_at).toLocaleString() + " · max uses: " + secret.max_uses),
        h("button", { onClick: function () { copy("key", secret.bootstrap_key); } }, "Copy Key"),
        h("button", { onClick: function () { copy("command", "hermes memory bootstrap --agent " + secret.agent_id + " --key " + secret.bootstrap_key); } }, "Copy Start Command"),
        copied && h("span", { role: "status" }, "Copied")
      ),
      h("div", { className: "dm-table-wrap" }, h("table", { className: "dm-table" },
        h("thead", null, h("tr", null, h("th", null, "Agent"), h("th", null, "Status"), h("th", null, "Last Access"), h("th", null, "Action"))),
        h("tbody", null, items.map(function (agent) {
          return h("tr", { key: agent.agent_id },
            h("td", null, agent.agent_id), h("td", null, h("span", { className: "dm-status" }, agent.status)),
            h("td", null, agent.last_access_at ? new Date(agent.last_access_at).toLocaleString() : "Never"),
            h("td", { className: "dm-actions" },
              h("button", { disabled: busy, onClick: function () { onRotate(agent.agent_id); } }, "Rotate"),
              h("button", { disabled: busy, className: "danger", onClick: function () { onRevoke(agent.agent_id); } }, "Revoke")
            )
          );
        }))
      ))
    );
  }

  function MemoryPage() {
    const initialListState = window.history.state && window.history.state.dmMemoryList;
    const [view, setView] = React.useState(initialListState && VIEWS.includes(initialListState.view) ? initialListState.view : "Current");
    const [data, setData] = React.useState({ items: [] });
    const [selectedEvent, setSelectedEvent] = React.useState(null);
    const [eventKnowledge, setEventKnowledge] = React.useState(null);
    const [eventKnowledgeStatus, setEventKnowledgeStatus] = React.useState("idle");
    const [selectedSource, setSelectedSource] = React.useState(null);
    const [secret, setSecret] = React.useState(null);
    const [error, setError] = React.useState("");
    const [loading, setLoading] = React.useState(true);
    const [actionBusy, setActionBusy] = React.useState(false);
    const requestChannelRef = React.useRef(null);
    const detailChannelRef = React.useRef(null);
    const knowledgeChannelRef = React.useRef(null);
    const sourceChannelRef = React.useRef(null);
    const actionChannelRef = React.useRef(null);
    const actionBusyRef = React.useRef(false);
    const returnFocusRef = React.useRef(null);
    const viewRef = React.useRef(view);
    if (!requestChannelRef.current) requestChannelRef.current = createLatestRequestChannel();
    if (!detailChannelRef.current) detailChannelRef.current = createLatestRequestChannel();
    if (!knowledgeChannelRef.current) knowledgeChannelRef.current = createLatestRequestChannel();
    if (!sourceChannelRef.current) sourceChannelRef.current = createLatestRequestChannel();
    if (!actionChannelRef.current) actionChannelRef.current = createLatestRequestChannel();
    viewRef.current = view;

    function endpoint(selected) {
      if (selected === "Agent Access") return "/agents";
      const names = {
        "Current": "current", "Decisions": "decisions", "Policies": "policies",
        "Agent Notes": "agent_notes", "History": "history", "Knowledge Vault": "knowledge_vault"
      };
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

    function loadKnowledge(item) {
      const request = knowledgeChannelRef.current.start();
      setEventKnowledge(null);
      setEventKnowledgeStatus("loading");
      api("/events/" + encodeURIComponent(item.id) + "/knowledge", { signal: request.signal }).then(function (result) {
        if (!knowledgeChannelRef.current.isCurrent(request.generation)) return;
        setEventKnowledge(result); setEventKnowledgeStatus("ready");
      }).catch(function (caught) {
        if (!knowledgeChannelRef.current.isCurrent(request.generation) || (caught && caught.name === "AbortError")) return;
        setEventKnowledge(null); setEventKnowledgeStatus("unavailable");
      }).finally(function () {
        if (knowledgeChannelRef.current.isCurrent(request.generation)) knowledgeChannelRef.current.finish(request.generation);
      });
    }

    function loadDirectEvent(eventId) {
      const request = detailChannelRef.current.start();
      sourceChannelRef.current.invalidate(); setSelectedSource(null); setError("");
      api("/events/" + encodeURIComponent(eventId), { signal: request.signal }).then(function (item) {
        if (!detailChannelRef.current.isCurrent(request.generation)) return;
        setSelectedEvent(item); loadKnowledge(item);
      }).catch(function (caught) {
        if (!detailChannelRef.current.isCurrent(request.generation) || (caught && caught.name === "AbortError")) return;
        setSelectedEvent(null); setEventKnowledge(null); setEventKnowledgeStatus("idle"); setError("Memory event unavailable (fail closed).");
      }).finally(function () {
        if (detailChannelRef.current.isCurrent(request.generation)) detailChannelRef.current.finish(request.generation);
      });
    }

    function loadDirectSource(sourceId) {
      const request = sourceChannelRef.current.start();
      detailChannelRef.current.invalidate(); knowledgeChannelRef.current.invalidate();
      setSelectedEvent(null); setEventKnowledge(null); setEventKnowledgeStatus("idle"); setError("");
      api("/sources/" + encodeURIComponent(sourceId), { signal: request.signal }).then(function (source) {
        if (sourceChannelRef.current.isCurrent(request.generation)) setSelectedSource(source);
      }).catch(function (caught) {
        if (!sourceChannelRef.current.isCurrent(request.generation) || (caught && caught.name === "AbortError")) return;
        setSelectedSource(null); setError("Memory source unavailable (fail closed).");
      }).finally(function () {
        if (sourceChannelRef.current.isCurrent(request.generation)) sourceChannelRef.current.finish(request.generation);
      });
    }

    React.useEffect(function () {
      setSecret(null); load(view);
      return function () {
        requestChannelRef.current.invalidate();
      };
    }, [view]);

    React.useEffect(function () {
      function restoreListState(state) {
        const listState = state && state.dmMemoryList;
        if (listState && VIEWS.includes(listState.view) && listState.view !== viewRef.current) {
          setView(listState.view);
        }
        const scrollY = listState && Number.isFinite(listState.scrollY) ? listState.scrollY : 0;
        const schedule = window.requestAnimationFrame || function (callback) { return setTimeout(callback, 0); };
        schedule(function () { window.scrollTo(0, scrollY); });
      }
      function handlePopState(event) {
        const eventId = eventIdFromPath(window.location.pathname);
        const sourceId = sourceIdFromPath(window.location.pathname);
        if (eventId) loadDirectEvent(eventId);
        else if (sourceId) loadDirectSource(sourceId);
        else {
          detailChannelRef.current.invalidate(); knowledgeChannelRef.current.invalidate(); sourceChannelRef.current.invalidate();
          setSelectedEvent(null); setEventKnowledge(null); setEventKnowledgeStatus("idle"); setSelectedSource(null);
          restoreListState(event.state);
        }
      }
      window.addEventListener("popstate", handlePopState);
      const directEventId = INITIAL_EVENT_ID || eventIdFromPath(window.location.pathname);
      const directSourceId = INITIAL_SOURCE_ID || sourceIdFromPath(window.location.pathname);
      if (directEventId) {
        if (INITIAL_EVENT_ID) window.history.replaceState(window.history.state, "", eventPath(INITIAL_EVENT_ID));
        loadDirectEvent(directEventId);
      } else if (directSourceId) {
        if (INITIAL_SOURCE_ID) window.history.replaceState(window.history.state, "", sourcePath(INITIAL_SOURCE_ID));
        loadDirectSource(directSourceId);
      }
      return function () {
        window.removeEventListener("popstate", handlePopState);
        detailChannelRef.current.invalidate(); knowledgeChannelRef.current.invalidate(); sourceChannelRef.current.invalidate();
      };
    }, []);

    function openEvent(item, returnFocus) {
      returnFocusRef.current = returnFocus;
      const listState = { view: view, scrollY: window.scrollY || 0 };
      window.history.replaceState({ dmMemoryList: listState }, "", "/memory");
      window.history.pushState({ dmMemoryDetail: true, dmMemoryList: listState }, "", eventPath(item.id));
      const normalized = Object.assign({}, item, {
        content: item.full_content || item.decision_content || item.content || item.summary,
        memory_type: item.item_kind || item.memory_type || item.note_type || "CURRENT_CONTEXT",
        event_type: item.note_type || item.item_kind || "RECORD",
        actor: item.actor || item.proposed_by || "Owner",
        created_at: item.stored_at || item.created_at
      });
      setSelectedSource(null); setSelectedEvent(normalized);
      setEventKnowledge({ related_events: [], sources: [], relations: [], evidence_status: "insufficient_evidence" });
      setEventKnowledgeStatus("ready");
    }

    function openRelatedEvent(eventId) {
      const listState = (window.history.state && window.history.state.dmMemoryList) || { view: view, scrollY: window.scrollY || 0 };
      window.history.pushState({ dmMemoryDetail: true, dmMemoryList: listState }, "", eventPath(eventId));
      loadDirectEvent(eventId);
    }

    function openSource(sourceId) {
      const listState = (window.history.state && window.history.state.dmMemoryList) || { view: view, scrollY: window.scrollY || 0 };
      window.history.pushState({ dmMemoryDetail: true, dmMemoryList: listState }, "", sourcePath(sourceId));
      loadDirectSource(sourceId);
    }

    function closeEvent() {
      const hasDetailPath = eventIdFromPath(window.location.pathname) || sourceIdFromPath(window.location.pathname);
      if (hasDetailPath && window.history.state && window.history.state.dmMemoryDetail) {
        window.history.back();
        return;
      }
      detailChannelRef.current.invalidate(); knowledgeChannelRef.current.invalidate(); sourceChannelRef.current.invalidate();
      window.history.replaceState({ dmMemoryList: { view: view, scrollY: window.scrollY || 0 } }, "", "/memory");
      setSelectedEvent(null); setEventKnowledge(null); setEventKnowledgeStatus("idle"); setSelectedSource(null);
    }

    function selectView(name) {
      detailChannelRef.current.invalidate(); knowledgeChannelRef.current.invalidate(); sourceChannelRef.current.invalidate();
      setSelectedEvent(null); setEventKnowledge(null); setEventKnowledgeStatus("idle"); setSelectedSource(null);
      window.history.replaceState({ dmMemoryList: { view: name, scrollY: 0 } }, "", "/memory");
      setView(name);
      window.scrollTo(0, 0);
    }

    function rotate(agent) {
      if (actionBusyRef.current) return;
      actionBusyRef.current = true;
      setActionBusy(true);
      const actionView = view;
      const action = actionChannelRef.current.start();
      setSecret(null); setError("");
      api("/agents/" + encodeURIComponent(agent) + "/rotate", {
        method: "POST", signal: action.signal
      }).then(function (result) {
        if (!actionChannelRef.current.isCurrent(action.generation) || viewRef.current !== actionView) return;
        setSecret(result); load(actionView);
      }).catch(function (caught) {
        if (!actionChannelRef.current.isCurrent(action.generation) || viewRef.current !== actionView) return;
        if (caught && caught.name === "AbortError") return;
        setSecret(null); setError("Rotation unavailable; no credential was issued.");
      }).finally(function () {
        if (!actionChannelRef.current.isCurrent(action.generation)) return;
        actionChannelRef.current.finish(action.generation);
        actionBusyRef.current = false;
        setActionBusy(false);
      });
    }

    function revoke(agent) {
      if (actionBusyRef.current) return;
      actionBusyRef.current = true;
      setActionBusy(true);
      const actionView = view;
      const action = actionChannelRef.current.start();
      setSecret(null); setError("");
      api("/agents/" + encodeURIComponent(agent) + "/revoke", {
        method: "POST", signal: action.signal
      }).then(function () {
        if (!actionChannelRef.current.isCurrent(action.generation) || viewRef.current !== actionView) return;
        load(actionView);
      }).catch(function (caught) {
        if (!actionChannelRef.current.isCurrent(action.generation) || viewRef.current !== actionView) return;
        if (caught && caught.name === "AbortError") return;
        setError("Revocation could not be verified; access is treated as unavailable.");
      }).finally(function () {
        if (!actionChannelRef.current.isCurrent(action.generation)) return;
        actionChannelRef.current.finish(action.generation);
        actionBusyRef.current = false;
        setActionBusy(false);
      });
    }

    function decide(decisionId, result) {
      api("/decisions/" + encodeURIComponent(decisionId) + "/" + result, { method: "POST", body: JSON.stringify({}) })
        .then(function () { load("Decisions"); })
        .catch(function () { setError("Decision update unavailable."); });
    }

    function createPolicy() {
      const title = window.prompt("Policy title");
      if (!title) return;
      const content = window.prompt("Policy content");
      if (!content) return;
      api("/policies", { method: "POST", body: JSON.stringify({ category: "GENERAL", title: title, content: content, scope: "GLOBAL", status: "ACTIVE" }) })
        .then(function () { load("Policies"); })
        .catch(function () { setError("Policy creation unavailable."); });
    }

    let body;
    if (loading) body = h("div", { className: "dm-empty" }, "Loading bounded view…");
    else if (view === "Agent Access") body = h(AgentAccess, {
      items: data.items, secret: secret, busy: actionBusy, onRotate: rotate, onRevoke: revoke
    });
    else body = h(React.Fragment, null,
      view === "Policies" && h("button", { onClick: createPolicy }, "Create Policy"),
      h(EventTable, { items: data.items, view: view, onSelect: openEvent, onSourceSelect: openSource, onDecision: decide })
    );

    return h("main", { className: "dm-page" },
      h("header", { className: "dm-header" }, h("div", null,
        h("span", { className: "dm-kicker" }, "DAOS ORGANIZATIONAL MEMORY"), h("h1", null, "Memory"),
        h("p", null, "Effective context first. Stored time remains distinct from occurred time.")
      ), h("button", { onClick: function () { load(view); } }, "Refresh")),
      h("nav", { className: "dm-tabs", "aria-label": "Memory views" }, VIEWS.map(function (name) {
        return h("button", { key: name, className: name === view ? "active" : "", onClick: function () { selectView(name); } }, name);
      })),
      error && h(ErrorBox, { message: error }),
      body,
      selectedEvent && h(EventDetail, {
        item: selectedEvent,
        knowledge: eventKnowledge,
        knowledgeStatus: eventKnowledgeStatus,
        returnFocus: returnFocusRef.current,
        onEventSelect: openRelatedEvent,
        onSourceSelect: openSource,
        onClose: closeEvent
      }),
      selectedSource && h(SourceDetail, { source: selectedSource, onClose: closeEvent })
    );
  }

  window.__DAOS_MEMORY_INTERNALS__ = {
    createLatestRequestChannel: createLatestRequestChannel,
    handleDialogKey: handleDialogKey,
    eventPath: eventPath,
    eventIdFromPath: eventIdFromPath,
    sourcePath: sourcePath,
    sourceIdFromPath: sourceIdFromPath,
    relationTargetFor: relationTargetFor,
    initialEventId: INITIAL_EVENT_ID,
    initialSourceId: INITIAL_SOURCE_ID
  };
  registry.register("daos_memory", MemoryPage);
})();
