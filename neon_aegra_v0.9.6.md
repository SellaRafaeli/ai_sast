# BOLA/IDOR review by gemini-4-neon

- Repo: https://github.com/aegra/aegra/tree/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd
- Turns: 4, thinking=high
- Tokens: in 280354 (+0 tool), out 25148, thinking 21575; cost ≈ $0.75
- Framework: FastAPI (Starlette) + SQLAlchemy Async ORM + LangGraph (AsyncPostgresSaver / AsyncPostgresStore)

Aegra enforces authentication via FastAPI router-level `require_auth` dependencies and isolates resources primarily by filtering SQLAlchemy queries with `user_id == user.identity` (plus `user_id == 'system'` for read-only assistants) and prefixing store namespaces with `['users', user.identity]`, alongside optional `@auth.on.*` hooks that allow by default. However, eight high-severity BOLA vulnerabilities break multi-tenant isolation across three root causes: (1) `services/run_preparation.py:_prepare_run` never verifies ownership of either the target `ThreadORM` or the referenced `AssistantORM` when starting runs on `POST /threads/{thread_id}/runs`, `/runs/stream`, `/runs/wait`, and stateless `/runs*`, allowing cross-user thread state read/mutation and private assistant execution/config disclosure; (2) `services/langgraph_service.py:create_run_config` and `inject_user_context` use `.setdefault()` and merge client-supplied `checkpoint` dicts into `config['configurable']`, allowing callers on both threaded and stateless run endpoints to override `thread_id`, `user_id`, and `langgraph_auth_user`; and (3) `POST /threads/{thread_id}/state` and `POST /threads/{thread_id}/history` merge an arbitrary `request.checkpoint` dict into `config['configurable']` after the `ThreadORM` ownership check, enabling callers who own any thread to read or mutate another user's LangGraph checkpoints.

| # | Score | Verdict | Method | Path | Object | Reason |
|---|---|---|---|---|---|---|
| 1 | 100 | likely | POST | `/threads/{thread_id}/runs/wait` | path.thread_id (Thread), body.assistant_id (Assistant), and body.config.configurable / body.checkpoint (thread_id, user_id, langgraph_auth_user) | Calls _prepare_run directly without invoking handle_event or checking ownership of ThreadORM or AssistantORM, allowing an attacker to mutate and execute on another user's thread (receiving its final state output directly), invoke another user's private assistant, or override thread_id/user_id/langgraph_auth_user via config.configurable or checkpoint. |
| 2 | 100 | likely | POST | `/threads/{thread_id}/runs/stream` | path.thread_id (Thread), body.assistant_id (Assistant), and body.config.configurable / body.checkpoint (thread_id, user_id, langgraph_auth_user) | Calls _prepare_run directly without even invoking handle_event, inheriting all three BOLA flaws: unscoped ThreadORM read/update and graph execution against another user's thread (streaming the victim's checkpoint state/messages directly back via SSE), unscoped AssistantORM lookup allowing execution of another user's private assistant, and client-controlled override of thread_id/user_id/langgraph_auth_user in create_run_config. |
| 3 | 98 | likely | POST | `/threads/{thread_id}/runs` | path.thread_id (Thread), body.assistant_id (Assistant), and body.config.configurable / body.checkpoint (thread_id, user_id, langgraph_auth_user) | _prepare_run does not verify ThreadORM.user_id == user.identity in _validate_resume_command, update_thread_metadata, or set_thread_status, allowing an attacker to modify another user's thread, execute a graph against the victim's checkpoint state, and retrieve output via the newly created RunORM owned by the attacker. It also queries AssistantORM without checking user_id, leaking another user's private assistant config/context in the Run response, and create_run_config/inject_user_context allow client config.configurable and checkpoint to override thread_id, user_id, and langgraph_auth_user. |
| 4 | 95 | likely | POST | `/threads/{thread_id}/state` | path.thread_id AND body.checkpoint dict (can contain thread_id, user_id, langgraph_auth_user) targeting LangGraph checkpointer state | After verifying ownership of the URL path thread_id, the handler merges the unrestricted dict request.checkpoint directly into config['configurable'] via `.update(request.checkpoint)`. Any authenticated user who owns a thread with a graph_id can pass another user's thread_id inside request.checkpoint to overwrite config['configurable']['thread_id'] (and user_id/langgraph_auth_user) and mutate the victim's LangGraph checkpoint state. |
| 5 | 95 | likely | POST | `/runs/wait` | body.assistant_id (Assistant) and body.config.configurable / body.checkpoint (thread_id, user_id, langgraph_auth_user) | Delegates to wait_for_run/_prepare_run, allowing any authenticated caller to execute another user's private assistant via body.assistant_id without an ownership check. Furthermore, despite generating an ephemeral thread_id, create_run_config preserves client-supplied config['configurable']['thread_id'] (and overwrites it from request.checkpoint) and inject_user_context preserves client-supplied user_id/langgraph_auth_user, allowing cross-user checkpoint access and identity spoofing. |
| 6 | 95 | likely | POST | `/threads/{thread_id}/history` | path.thread_id AND body.checkpoint dict (can contain thread_id, user_id, langgraph_auth_user) targeting LangGraph checkpoint history | After checking ownership of path.thread_id, the handler merges the unrestricted dict request.checkpoint into config['configurable'] via `.update(cfg_cp)`. A caller owning any thread with a graph_id can supply another user's thread_id in request.checkpoint to overwrite config['configurable']['thread_id'] and retrieve the victim's full checkpoint state history from AsyncPostgresSaver. |
| 7 | 95 | likely | POST | `/runs/stream` | body.assistant_id (Assistant) and body.config.configurable / body.checkpoint (thread_id, user_id, langgraph_auth_user) | Delegates to create_and_stream_run/_prepare_run, allowing execution of another user's private assistant via unscoped AssistantORM lookup, and allowing client-supplied config.configurable.thread_id or checkpoint.thread_id to override the ephemeral thread_id and stream/mutate another user's LangGraph thread state. |
| 8 | 95 | likely | POST | `/runs` | body.assistant_id (Assistant) and body.config.configurable / body.checkpoint (thread_id, user_id, langgraph_auth_user) | Delegates to create_run/_prepare_run, enabling an attacker to reference any user's private assistant_id and immediately read its merged config and context in the returned Run JSON, as well as override the ephemeral thread_id and user_id/langgraph_auth_user via config.configurable or checkpoint. |
| 9 | 15 | unlikely | POST | `/assistants/{assistant_id}/latest` | path.assistant_id and body.version selecting an Assistant and AssistantVersion | Ownership is enforced at the database layer via AssistantORM.user_id == user_identity before accessing versions or updating; minor gap is omission of the @auth.on handle_event hook present on sibling assistant routes. |
| 10 | 15 | unlikely | POST | `/assistants/{assistant_id}/versions` | path.assistant_id selecting an Assistant's versions | Verifies the parent AssistantORM belongs to user_identity or 'system' before listing its AssistantVersionORM rows; minor gap is omitting handle_event. |
| 11 | 15 | unlikely | GET | `/assistants/{assistant_id}/schemas` | path.assistant_id selecting an Assistant's graph schemas | Assistant lookup restricts access to assistants owned by user.identity or 'system' defaults before extracting graph schemas. |
| 12 | 15 | unlikely | GET | `/assistants/{assistant_id}/graph` | path.assistant_id selecting an Assistant's graph structure | Assistant lookup enforces user_id == user.identity or 'system' before building the visualizable graph. |
| 13 | 15 | unlikely | GET | `/assistants/{assistant_id}/subgraphs` | path.assistant_id selecting an Assistant's subgraphs | Assistant lookup enforces user_id == user.identity or 'system' before inspecting subgraphs. |
| 14 | 10 | unlikely | GET | `/threads/{thread_id}/history` | path.thread_id selecting Thread checkpoint history | Delegates to get_thread_history_post with checkpoint=None and before as a plain checkpoint_id string, preventing config['configurable']['thread_id'] override while enforcing ThreadORM.user_id == user.identity. |
| 15 | 10 | unlikely | POST | `/threads/{thread_id}/state/checkpoint` | path.thread_id and body.checkpoint.checkpoint_id | Although ThreadCheckpoint has a thread_id field, the handler ignores request.checkpoint.thread_id and passes only the URL path thread_id, checkpoint_id, and checkpoint_ns to get_thread_state_at_checkpoint, which verifies ownership. |
| 16 | 10 | unlikely | GET | `/threads/{thread_id}/runs/{run_id}/join` | path.thread_id and path.run_id selecting a Run to join | Both the initial validation query and the final output query strictly scope RunORM by run_id, thread_id, and user.identity. |
| 17 | 10 | unlikely | GET | `/threads/{thread_id}/state/{checkpoint_id}` | path.thread_id and path.checkpoint_id selecting a Thread checkpoint | Verifies ThreadORM.user_id == user.identity on thread_id and only sets checkpoint_id and checkpoint_ns in config['configurable'], scoping the checkpointer lookup to the owned thread. |
| 18 | 10 | unlikely | PATCH | `/threads/{thread_id}/runs/{run_id}` | path.thread_id and path.run_id selecting a Run to interrupt | Verifies RunORM ownership via run_id, thread_id, and user_id == user.identity before interrupting or updating the run. |
| 19 | 10 | unlikely | GET | `/threads/{thread_id}/state` | path.thread_id selecting Thread state from LangGraph checkpointer | Enforces ThreadORM.user_id == user.identity and only allows setting checkpoint_ns on config['configurable'], so the caller cannot redirect the checkpointer lookup to another thread_id. |
| 20 | 10 | unlikely | PATCH | `/threads/{thread_id}` | path.thread_id selecting a Thread to update | Only threads matching ThreadORM.user_id == user.identity can be updated; callers can overwrite metadata_json['owner'] on their own thread, but cannot modify another user's thread or change the user_id column. |
| 21 | 10 | unlikely | GET | `/threads/{thread_id}/runs` | path.thread_id selecting Runs on a thread | Query filters RunORM by user_id == user.identity so a caller cannot list runs belonging to another user even if they supply a victim's thread_id. |
| 22 | 10 | unlikely | GET | `/threads` |  | Query strictly filters ThreadORM by user.identity (custom @auth.on filters are currently a no-op pass, but base per-user scoping is enforced). |
| 23 | 10 | unlikely | GET | `/threads/{thread_id}/runs/{run_id}/stream` | path.thread_id and path.run_id selecting a Run to stream | Verifies RunORM ownership via run_id, thread_id, and user_id == user.identity before attaching to the run's SSE broker. |
| 24 | 10 | unlikely | POST | `/threads/{thread_id}/runs/{run_id}/cancel` | path.thread_id and path.run_id selecting a Run to cancel | Verifies RunORM ownership via run_id, thread_id, and user_id == user.identity before issuing cancellation or updating status. |
| 25 | 10 | unlikely | POST | `/assistants/count` | body filters counting Assistants | Count query always filters AssistantORM to user_identity or 'system' defaults. |
| 26 | 10 | unlikely | POST | `/assistants/search` | body filters (name, description, graph_id, metadata) selecting Assistants | Search query always restricts AssistantORM rows to user_identity or 'system'; although custom @auth.on handler filters written to request.filters are ignored by AssistantService, users cannot read other users' private assistants. |
| 27 | 10 | unlikely | GET | `/assistants` |  | Results are always scoped to assistants owned by user.identity or shared 'system' defaults; custom @auth.on search filters are not applied because AssistantSearchRequest lacks a filters field, but base user isolation holds. |
| 28 | 5 | unlikely | DELETE | `/threads/{thread_id}/runs/{run_id}` | path.thread_id and path.run_id selecting a Run to delete | Both the lookup and the DELETE statement strictly enforce RunORM.user_id == user.identity. |
| 29 | 5 | unlikely | PUT | `/store/items` | body.namespace and body.key selecting a Store item | All writes are unconditionally prefixed with ['users', user.identity] by apply_user_namespace_scoping, isolating store keys per user. |
| 30 | 5 | unlikely | GET | `/store/items` | query.namespace and query.key selecting a Store item | Namespace input (dotted string or list) is normalized and forced under ['users', user.identity] before calling store.aget. |
| 31 | 5 | unlikely | DELETE | `/store/items` | body/query.namespace and key selecting a Store item to delete | Deletes are unconditionally constrained to the caller's ['users', user.identity] namespace prefix. |
| 32 | 5 | unlikely | POST | `/store/items/search` | body.namespace_prefix selecting Store items to search | Search prefix is always scoped under ['users', user.identity] via apply_user_namespace_scoping. |
| 33 | 5 | unlikely | POST | `/store/namespaces` | body.prefix and body.suffix selecting Store namespaces | Namespace listing always constrains the prefix to ['users', user.identity, ...], isolating namespace discovery per user. |
| 34 | 5 | unlikely | GET | `/threads/{thread_id}/runs/{run_id}` | path.thread_id and path.run_id selecting a Run | Run lookup strictly filters by run_id, thread_id, and user_id == user.identity, preventing retrieval of another user's run records. |
| 35 | 5 | unlikely | POST | `/threads/search` | body search filters selecting Threads | Search query always restricts results to ThreadORM.user_id == user.identity. |
| 36 | 5 | unlikely | DELETE | `/threads/{thread_id}` | path.thread_id selecting a Thread to delete | Verifies ThreadORM.user_id == user.identity before cancelling runs and deleting the thread. |
| 37 | 5 | unlikely | GET | `/threads/{thread_id}` | path.thread_id selecting a Thread | Thread lookup explicitly scopes by ThreadORM.user_id == user.identity and returns 404 otherwise. |
| 38 | 5 | unlikely | POST | `/threads` | body.thread_id (optional Thread ID) | Existing thread lookup for idempotency is scoped by user.identity, and new threads are created with user_id and metadata['owner'] set to user.identity. |
| 39 | 5 | unlikely | DELETE | `/assistants/{assistant_id}` | path.assistant_id selecting an Assistant to delete | Assistant lookup strictly requires AssistantORM.user_id == user_identity before deletion. |
| 40 | 5 | unlikely | PATCH | `/assistants/{assistant_id}` | path.assistant_id selecting an Assistant to update | Both the pre-check SELECT and the UPDATE strictly require AssistantORM.user_id == user_identity (excluding even 'system' assistants). |
| 41 | 5 | unlikely | GET | `/assistants/{assistant_id}` | path.assistant_id selecting an Assistant | Lookup enforces ownership by restricting AssistantORM to user_identity or 'system' defaults and returns 404 otherwise. |
| 42 | 5 | unlikely | POST | `/assistants` | body.assistant_id (optional Assistant ID) and body.graph_id | New assistants are always created with user_id bound to the authenticated user, and duplicate checks are scoped to user_identity (colliding with another user's assistant_id fails at DB PK constraint rather than returning or modifying the other user's record). |
| 43 | 0 | unlikely | GET | `/metrics` |  | Exposes aggregate Prometheus metrics when enabled; does not accept or access per-user objects. |
| 44 | 0 | unlikely | GET | `/live` |  | Returns static alive status with no object identifier or data access. |
| 45 | 0 | unlikely | GET | `/ready` |  | Performs readiness probes using hardcoded identifiers only; no user-controlled object identifier is accepted. |
| 46 | 0 | unlikely | GET | `/health` |  | Performs connectivity probes using hardcoded identifiers only; no user-controlled object identifier is accepted. |
| 47 | 0 | unlikely | GET | `/info` |  | Returns static service name, version, and feature flags with no object identifier or data access. |
| 48 | 0 | unlikely | GET | `/` |  | Returns static service metadata (name, version, status) and accepts no user-controlled object identifiers. |

## Details

### 1. POST /threads/{thread_id}/runs/wait — likely (100)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:275 wait_for_run`
- Data access: `SELECT/UPDATE ThreadORM WHERE thread_id = ? (unscoped); SELECT AssistantORM WHERE assistant_id = ? (unscoped); INSERT RunORM; waits and returns final graph output on victim thread`
- Auth checks: require_auth router dependency only; NO handle_event call; NO user_id check on ThreadORM or AssistantORM; client config/checkpoint overrides thread_id/user_id
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:275-307; libs/aegra-api/src/aegra_api/services/run_preparation.py:34,112-144,186-205; libs/aegra-api/src/aegra_api/services/langgraph_service.py:541-550,582-615
- Reason: Calls _prepare_run directly without invoking handle_event or checking ownership of ThreadORM or AssistantORM, allowing an attacker to mutate and execute on another user's thread (receiving its final state output directly), invoke another user's private assistant, or override thread_id/user_id/langgraph_auth_user via config.configurable or checkpoint.
- Fix: Invoke handle_event('threads', 'create_run'), enforce ThreadORM.user_id == user.identity and AssistantORM.user_id IN (user.identity, 'system') in _prepare_run, and prevent client config/checkpoint from overriding thread_id, user_id, or langgraph_auth_user.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:275 wait_for_run
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:147 _prepare_run
  1. libs/aegra-api/src/aegra_api/services/run_executor.py:42 execute_run
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:568 create_run_config
  1. libs/aegra-api/src/aegra_api/services/run_waiters.py:48 heartbeat_wait_body

### 2. POST /threads/{thread_id}/runs/stream — likely (100)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:76 create_and_stream_run`
- Data access: `SELECT/UPDATE ThreadORM WHERE thread_id = ? (unscoped); SELECT AssistantORM WHERE assistant_id = ? (unscoped); INSERT RunORM; SSE stream of graph execution on victim thread`
- Auth checks: require_auth router dependency only; NO handle_event call; NO user_id check on ThreadORM or AssistantORM; client config/checkpoint overrides thread_id/user_id
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:76-112; libs/aegra-api/src/aegra_api/services/run_preparation.py:34,112-144,186-205; libs/aegra-api/src/aegra_api/services/langgraph_service.py:541-550,582-615
- Reason: Calls _prepare_run directly without even invoking handle_event, inheriting all three BOLA flaws: unscoped ThreadORM read/update and graph execution against another user's thread (streaming the victim's checkpoint state/messages directly back via SSE), unscoped AssistantORM lookup allowing execution of another user's private assistant, and client-controlled override of thread_id/user_id/langgraph_auth_user in create_run_config.
- Fix: Invoke handle_event('threads', 'create_run'), verify ThreadORM.user_id == user.identity and AssistantORM.user_id IN (user.identity, 'system') inside _prepare_run, and force server-authoritative thread_id/user_id/langgraph_auth_user in create_run_config and inject_user_context.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:76 create_and_stream_run
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:147 _prepare_run
  1. libs/aegra-api/src/aegra_api/services/run_executor.py:42 execute_run
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:568 create_run_config
  1. libs/aegra-api/src/aegra_api/services/streaming_service.py:85 stream_run_execution

### 3. POST /threads/{thread_id}/runs — likely (98)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:38 create_run`
- Data access: `SELECT/UPDATE ThreadORM WHERE thread_id = ? (unscoped); SELECT AssistantORM WHERE assistant_id = ? (unscoped); INSERT RunORM with user_id = user.identity; graph execution on checkpointer`
- Auth checks: require_auth router dependency; handle_event('threads', 'create_run') allows by default; NO user_id check on ThreadORM or AssistantORM; client config/checkpoint overrides thread_id/user_id
- Evidence: libs/aegra-api/src/aegra_api/services/run_preparation.py:34,112-144,186-205; libs/aegra-api/src/aegra_api/services/langgraph_service.py:541-550,582-615
- Reason: _prepare_run does not verify ThreadORM.user_id == user.identity in _validate_resume_command, update_thread_metadata, or set_thread_status, allowing an attacker to modify another user's thread, execute a graph against the victim's checkpoint state, and retrieve output via the newly created RunORM owned by the attacker. It also queries AssistantORM without checking user_id, leaking another user's private assistant config/context in the Run response, and create_run_config/inject_user_context allow client config.configurable and checkpoint to override thread_id, user_id, and langgraph_auth_user.
- Fix: In _prepare_run, reject requests with 404/403 if an existing ThreadORM has user_id != user.identity, scope AssistantORM lookup to user_id IN (user.identity, 'system'), and overwrite (not setdefault) thread_id, run_id, user_id, and langgraph_auth_user in create_run_config/inject_user_context after sanitizing checkpoint fields.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:38 create_run
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:147 _prepare_run
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:30 _validate_resume_command
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:94 update_thread_metadata
  1. libs/aegra-api/src/aegra_api/services/run_status.py:50 set_thread_status
  1. libs/aegra-api/src/aegra_api/services/run_executor.py:42 execute_run
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:568 create_run_config

### 4. POST /threads/{thread_id}/state — likely (95)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:372 update_thread_state`
- Data access: `AsyncPostgresSaver checkpoint write via agent.aupdate_state(config, update_values, as_node=...)`
- Auth checks: require_auth router dependency; ThreadORM.user_id == user.identity checked ONLY on path.thread_id, then bypassed by merging user-controlled request.checkpoint into config['configurable']; omits handle_event
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:394-451; libs/aegra-api/src/aegra_api/models/threads.py:130-134
- Reason: After verifying ownership of the URL path thread_id, the handler merges the unrestricted dict request.checkpoint directly into config['configurable'] via `.update(request.checkpoint)`. Any authenticated user who owns a thread with a graph_id can pass another user's thread_id inside request.checkpoint to overwrite config['configurable']['thread_id'] (and user_id/langgraph_auth_user) and mutate the victim's LangGraph checkpoint state.
- Fix: Only copy allowlisted checkpoint fields (checkpoint_id and checkpoint_ns) from request.checkpoint into config['configurable'], and always re-assert config['configurable']['thread_id'] = thread_id and server-derived user context afterward.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:372 update_thread_state
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:555 create_thread_config
  1. config['configurable'].update(request.checkpoint)
  1. agent.aupdate_state(config, update_values)

### 5. POST /runs/wait — likely (95)

- Handler: `libs/aegra-api/src/aegra_api/api/stateless_runs.py:101 stateless_wait_for_run`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? (unscoped); AsyncPostgresSaver checkpoint read/write using client-overridden thread_id`
- Auth checks: require_auth router dependency only; NO user_id check on AssistantORM; client config/checkpoint overrides ephemeral thread_id and user_id/langgraph_auth_user
- Evidence: libs/aegra-api/src/aegra_api/api/stateless_runs.py:101-116; libs/aegra-api/src/aegra_api/services/run_preparation.py:186-196; libs/aegra-api/src/aegra_api/services/langgraph_service.py:541-550,582-615
- Reason: Delegates to wait_for_run/_prepare_run, allowing any authenticated caller to execute another user's private assistant via body.assistant_id without an ownership check. Furthermore, despite generating an ephemeral thread_id, create_run_config preserves client-supplied config['configurable']['thread_id'] (and overwrites it from request.checkpoint) and inject_user_context preserves client-supplied user_id/langgraph_auth_user, allowing cross-user checkpoint access and identity spoofing.
- Fix: Scope AssistantORM lookup in _prepare_run to user_id IN (user.identity, 'system'), and unconditionally assign server-derived thread_id, run_id, user_id, and langgraph_auth_user in create_run_config and inject_user_context.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/stateless_runs.py:101 stateless_wait_for_run
  1. libs/aegra-api/src/aegra_api/api/runs.py:275 wait_for_run
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:147 _prepare_run
  1. libs/aegra-api/src/aegra_api/services/run_executor.py:42 execute_run
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:568 create_run_config

### 6. POST /threads/{thread_id}/history — likely (95)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:601 get_thread_history_post`
- Data access: `AsyncPostgresSaver checkpoint history read via agent.aget_state_history(config, ...)`
- Auth checks: require_auth router dependency; ThreadORM.user_id == user.identity checked ONLY on path.thread_id, then bypassed by merging user-controlled request.checkpoint into config['configurable']; omits handle_event
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:622-676; libs/aegra-api/src/aegra_api/models/threads.py:148-156
- Reason: After checking ownership of path.thread_id, the handler merges the unrestricted dict request.checkpoint into config['configurable'] via `.update(cfg_cp)`. A caller owning any thread with a graph_id can supply another user's thread_id in request.checkpoint to overwrite config['configurable']['thread_id'] and retrieve the victim's full checkpoint state history from AsyncPostgresSaver.
- Fix: Restrict request.checkpoint merging to checkpoint_id and checkpoint_ns only, and enforce config['configurable']['thread_id'] = thread_id (and do not allow request.before to override thread_id) before calling aget_state_history.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:601 get_thread_history_post
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:555 create_thread_config
  1. config['configurable'].update(cfg_cp)
  1. agent.aget_state_history(config, ...)

### 7. POST /runs/stream — likely (95)

- Handler: `libs/aegra-api/src/aegra_api/api/stateless_runs.py:165 stateless_stream_run`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? (unscoped); AsyncPostgresSaver checkpoint read/write and SSE stream using client-overridden thread_id`
- Auth checks: require_auth router dependency only; NO user_id check on AssistantORM; client config/checkpoint overrides ephemeral thread_id and user_id/langgraph_auth_user
- Evidence: libs/aegra-api/src/aegra_api/api/stateless_runs.py:165-182; libs/aegra-api/src/aegra_api/services/run_preparation.py:186-196; libs/aegra-api/src/aegra_api/services/langgraph_service.py:541-550,582-615
- Reason: Delegates to create_and_stream_run/_prepare_run, allowing execution of another user's private assistant via unscoped AssistantORM lookup, and allowing client-supplied config.configurable.thread_id or checkpoint.thread_id to override the ephemeral thread_id and stream/mutate another user's LangGraph thread state.
- Fix: Scope AssistantORM lookup in _prepare_run to user_id IN (user.identity, 'system'), and unconditionally assign server-derived thread_id, run_id, user_id, and langgraph_auth_user in create_run_config and inject_user_context.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/stateless_runs.py:165 stateless_stream_run
  1. libs/aegra-api/src/aegra_api/api/runs.py:76 create_and_stream_run
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:147 _prepare_run
  1. libs/aegra-api/src/aegra_api/services/run_executor.py:42 execute_run
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:568 create_run_config

### 8. POST /runs — likely (95)

- Handler: `libs/aegra-api/src/aegra_api/api/stateless_runs.py:220 stateless_create_run`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? (unscoped); returns merged assistant config/context in Run response; executes on client-overridden thread_id`
- Auth checks: require_auth router dependency; handle_event('threads', 'create_run') allows by default; NO user_id check on AssistantORM; client config/checkpoint overrides ephemeral thread_id and user_id/langgraph_auth_user
- Evidence: libs/aegra-api/src/aegra_api/api/stateless_runs.py:220-238; libs/aegra-api/src/aegra_api/services/run_preparation.py:186-254; libs/aegra-api/src/aegra_api/services/langgraph_service.py:541-550,582-615
- Reason: Delegates to create_run/_prepare_run, enabling an attacker to reference any user's private assistant_id and immediately read its merged config and context in the returned Run JSON, as well as override the ephemeral thread_id and user_id/langgraph_auth_user via config.configurable or checkpoint.
- Fix: Scope AssistantORM lookup in _prepare_run to user_id IN (user.identity, 'system'), and unconditionally assign server-derived thread_id, run_id, user_id, and langgraph_auth_user in create_run_config and inject_user_context.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/stateless_runs.py:220 stateless_create_run
  1. libs/aegra-api/src/aegra_api/api/runs.py:38 create_run
  1. libs/aegra-api/src/aegra_api/services/run_preparation.py:147 _prepare_run
  1. libs/aegra-api/src/aegra_api/services/run_executor.py:42 execute_run
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:568 create_run_config

### 9. POST /assistants/{assistant_id}/latest — unlikely (15)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:202 set_assistant_latest`
- Data access: `SELECT/UPDATE AssistantORM WHERE assistant_id = ? AND user_id = user_identity; SELECT AssistantVersionORM WHERE assistant_id = ? AND version = ?`
- Auth checks: require_auth router dependency; DB SELECT and UPDATE enforce AssistantORM.user_id == user_identity (note: does not invoke handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/assistants.py:202-215; libs/aegra-api/src/aegra_api/services/assistant_service.py:354-391
- Reason: Ownership is enforced at the database layer via AssistantORM.user_id == user_identity before accessing versions or updating; minor gap is omission of the @auth.on handle_event hook present on sibling assistant routes.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:202 set_assistant_latest
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:354 set_assistant_latest

### 10. POST /assistants/{assistant_id}/versions — unlikely (15)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:221 list_assistant_versions`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? AND (user_id = user_identity OR user_id = 'system'); SELECT AssistantVersionORM WHERE assistant_id = ?`
- Auth checks: require_auth router dependency; DB query scopes parent AssistantORM to user_identity or 'system' (does not invoke handle_event)
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:393-428
- Reason: Verifies the parent AssistantORM belongs to user_identity or 'system' before listing its AssistantVersionORM rows; minor gap is omitting handle_event.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:221 list_assistant_versions
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:393 list_assistant_versions

### 11. GET /assistants/{assistant_id}/schemas — unlikely (15)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:239 get_assistant_schemas`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? AND (user_id = user.identity OR user_id = 'system')`
- Auth checks: require_auth router dependency; DB query scopes AssistantORM to user.identity or 'system' (does not invoke handle_event)
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:430-450
- Reason: Assistant lookup restricts access to assistants owned by user.identity or 'system' defaults before extracting graph schemas.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:239 get_assistant_schemas
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:430 get_assistant_schemas
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:349 get_graph_for_validation

### 12. GET /assistants/{assistant_id}/graph — unlikely (15)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:253 get_assistant_graph`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? AND (user_id = user.identity OR user_id = 'system')`
- Auth checks: require_auth router dependency; DB query scopes AssistantORM to user.identity or 'system' (does not invoke handle_event)
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:452-488
- Reason: Assistant lookup enforces user_id == user.identity or 'system' before building the visualizable graph.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:253 get_assistant_graph
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:452 get_assistant_graph
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:349 get_graph_for_validation

### 13. GET /assistants/{assistant_id}/subgraphs — unlikely (15)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:272 get_assistant_subgraphs`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? AND (user_id = user.identity OR user_id = 'system')`
- Auth checks: require_auth router dependency; DB query scopes AssistantORM to user.identity or 'system' (does not invoke handle_event)
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:490-525
- Reason: Assistant lookup enforces user_id == user.identity or 'system' before inspecting subgraphs.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:272 get_assistant_subgraphs
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:490 get_assistant_subgraphs
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:349 get_graph_for_validation

### 14. GET /threads/{thread_id}/history — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:694 get_thread_history_get`
- Data access: `SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity; AsyncPostgresSaver via agent.aget_state_history(config)`
- Auth checks: require_auth router dependency; delegates to get_thread_history_post with checkpoint=None and string before
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:715-725
- Reason: Delegates to get_thread_history_post with checkpoint=None and before as a plain checkpoint_id string, preventing config['configurable']['thread_id'] override while enforcing ThreadORM.user_id == user.identity.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:694 get_thread_history_get
  1. libs/aegra-api/src/aegra_api/api/threads.py:601 get_thread_history_post
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity
  1. agent.aget_state_history(config, ...)

### 15. POST /threads/{thread_id}/state/checkpoint — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:573 get_thread_state_at_checkpoint_post`
- Data access: `SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity; AsyncPostgresSaver via agent.aget_state(config)`
- Auth checks: require_auth router dependency; delegates to get_thread_state_at_checkpoint using path thread_id (ignores body.checkpoint.thread_id)
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:585-597
- Reason: Although ThreadCheckpoint has a thread_id field, the handler ignores request.checkpoint.thread_id and passes only the URL path thread_id, checkpoint_id, and checkpoint_ns to get_thread_state_at_checkpoint, which verifies ownership.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:573 get_thread_state_at_checkpoint_post
  1. libs/aegra-api/src/aegra_api/api/threads.py:496 get_thread_state_at_checkpoint
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity
  1. agent.aget_state(config)

### 16. GET /threads/{thread_id}/runs/{run_id}/join — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:225 join_run`
- Data access: `SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity (both initial check and read_run_output)`
- Auth checks: require_auth router dependency; both initial DB check and read_run_output enforce RunORM.user_id == user.identity (omits handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:248-259; libs/aegra-api/src/aegra_api/services/run_waiters.py:24-40
- Reason: Both the initial validation query and the final output query strictly scope RunORM by run_id, thread_id, and user.identity.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:225 join_run
  1. SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity
  1. libs/aegra-api/src/aegra_api/services/run_waiters.py:48 heartbeat_wait_body
  1. libs/aegra-api/src/aegra_api/services/run_waiters.py:24 read_run_output

### 17. GET /threads/{thread_id}/state/{checkpoint_id} — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:496 get_thread_state_at_checkpoint`
- Data access: `SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity; AsyncPostgresSaver via agent.aget_state(config)`
- Auth checks: require_auth router dependency; ThreadORM.user_id == user.identity check before checkpointer read (omits handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:510-544
- Reason: Verifies ThreadORM.user_id == user.identity on thread_id and only sets checkpoint_id and checkpoint_ns in config['configurable'], scoping the checkpointer lookup to the owned thread.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:496 get_thread_state_at_checkpoint
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:555 create_thread_config
  1. agent.aget_state(config)

### 18. PATCH /threads/{thread_id}/runs/{run_id} — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:181 update_run`
- Data access: `SELECT RunORM scoped by user_id == user.identity; interrupt + UPDATE RunORM`
- Auth checks: require_auth router dependency; pre-check SELECT enforces RunORM.user_id == user.identity (omits handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:194-215
- Reason: Verifies RunORM ownership via run_id, thread_id, and user_id == user.identity before interrupting or updating the run.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:181 update_run
  1. SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity
  1. streaming_service.interrupt_run(run_id)
  1. UPDATE RunORM WHERE run_id = ?

### 19. GET /threads/{thread_id}/state — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:282 get_thread_state`
- Data access: `SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity; AsyncPostgresSaver via agent.aget_state(config)`
- Auth checks: require_auth router dependency; ThreadORM.user_id == user.identity check before checkpointer read (omits handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:296-336
- Reason: Enforces ThreadORM.user_id == user.identity and only allows setting checkpoint_ns on config['configurable'], so the caller cannot redirect the checkpointer lookup to another thread_id.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:282 get_thread_state
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity
  1. libs/aegra-api/src/aegra_api/services/langgraph_service.py:555 create_thread_config
  1. agent.aget_state(config)

### 20. PATCH /threads/{thread_id} — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:244 update_thread`
- Data access: `SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity; UPDATE metadata_json`
- Auth checks: require_auth router dependency; handle_event('threads', 'update'); DB query filters by ThreadORM.user_id == user.identity
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:265-279
- Reason: Only threads matching ThreadORM.user_id == user.identity can be updated; callers can overwrite metadata_json['owner'] on their own thread, but cannot modify another user's thread or change the user_id column.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:244 update_thread
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity; update metadata_json

### 21. GET /threads/{thread_id}/runs — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:151 list_runs`
- Data access: `SELECT RunORM WHERE thread_id = ? AND user_id = user.identity`
- Auth checks: require_auth router dependency; DB query filters RunORM by user_id == user.identity (omits handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:165-178
- Reason: Query filters RunORM by user_id == user.identity so a caller cannot list runs belonging to another user even if they supply a victim's thread_id.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:151 list_runs
  1. SELECT RunORM WHERE thread_id = ? AND user_id = user.identity

### 22. GET /threads — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:195 list_threads`
- Data access: `SELECT ThreadORM WHERE user_id = user.identity`
- Auth checks: require_auth router dependency; handle_event('threads', 'search'); DB query scoped to ThreadORM.user_id == user.identity
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:208-216
- Reason: Query strictly filters ThreadORM by user.identity (custom @auth.on filters are currently a no-op pass, but base per-user scoping is enforced).
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:195 list_threads
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT ThreadORM WHERE user_id = user.identity

### 23. GET /threads/{thread_id}/runs/{run_id}/stream — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:310 stream_run`
- Data access: `SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity; broker replay/live stream`
- Auth checks: require_auth router dependency; DB query enforces RunORM.user_id == user.identity (omits handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:327-336
- Reason: Verifies RunORM ownership via run_id, thread_id, and user_id == user.identity before attaching to the run's SSE broker.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:310 stream_run
  1. SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity
  1. libs/aegra-api/src/aegra_api/services/streaming_service.py:85 stream_run_execution

### 24. POST /threads/{thread_id}/runs/{run_id}/cancel — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:366 cancel_run_endpoint`
- Data access: `SELECT RunORM scoped by user_id == user.identity; cancel/interrupt broker + UPDATE RunORM`
- Auth checks: require_auth router dependency; pre-check and reload SELECT enforce RunORM.user_id == user.identity (omits handle_event)
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:386-395
- Reason: Verifies RunORM ownership via run_id, thread_id, and user_id == user.identity before issuing cancellation or updating status.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:366 cancel_run_endpoint
  1. SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity
  1. streaming_service.cancel_run / interrupt_run
  1. UPDATE RunORM

### 25. POST /assistants/count — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:102 count_assistants`
- Data access: `SELECT COUNT(*) FROM assistant WHERE user_id = user_identity OR user_id = 'system'`
- Auth checks: require_auth router dependency; handle_event('assistants', 'search'); DB query scoped to user_identity or 'system'
- Evidence: libs/aegra-api/src/aegra_api/api/assistants.py:112-121; libs/aegra-api/src/aegra_api/services/assistant_service.py:242-259
- Reason: Count query always filters AssistantORM to user_identity or 'system' defaults.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:102 count_assistants
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:237 count_assistants

### 26. POST /assistants/search — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:80 search_assistants`
- Data access: `SELECT AssistantORM WHERE user_id = user_identity OR user_id = 'system'`
- Auth checks: require_auth router dependency; handle_event('assistants', 'search'); DB query scoped to user_identity or 'system'
- Evidence: libs/aegra-api/src/aegra_api/api/assistants.py:90-99; libs/aegra-api/src/aegra_api/services/assistant_service.py:211-235
- Reason: Search query always restricts AssistantORM rows to user_identity or 'system'; although custom @auth.on handler filters written to request.filters are ignored by AssistantService, users cannot read other users' private assistants.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:80 search_assistants
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:206 search_assistants

### 27. GET /assistants — unlikely (10)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:57 list_assistants`
- Data access: `SELECT AssistantORM WHERE user_id = user_identity OR user_id = 'system'`
- Auth checks: require_auth router dependency; handle_event('assistants', 'search'); DB query scoped to user_identity or 'system'
- Evidence: libs/aegra-api/src/aegra_api/api/assistants.py:67-76; libs/aegra-api/src/aegra_api/services/assistant_service.py:198-205
- Reason: Results are always scoped to assistants owned by user.identity or shared 'system' defaults; custom @auth.on search filters are not applied because AssistantSearchRequest lacks a filters field, but base user isolation holds.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:57 list_assistants
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:198 list_assistants / search_assistants

### 28. DELETE /threads/{thread_id}/runs/{run_id} — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:446 delete_run`
- Data access: `SELECT and DELETE RunORM scoped by run_id, thread_id, and user_id == user.identity`
- Auth checks: require_auth router dependency; handle_event('runs', 'delete'); both SELECT and DELETE filter by RunORM.user_id == user.identity
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:464-500
- Reason: Both the lookup and the DELETE statement strictly enforce RunORM.user_id == user.identity.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:446 delete_run
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT/DELETE RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity

### 29. PUT /store/items — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/store.py:26 put_store_item`
- Data access: `AsyncPostgresStore.aput scoped to ['users', user.identity, ...]`
- Auth checks: require_auth router dependency; handle_event('store', 'put'); apply_user_namespace_scoping enforces ['users', user.identity] prefix
- Evidence: libs/aegra-api/src/aegra_api/api/store.py:45-50,214-226
- Reason: All writes are unconditionally prefixed with ['users', user.identity] by apply_user_namespace_scoping, isolating store keys per user.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/store.py:26 put_store_item
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/api/store.py:214 apply_user_namespace_scoping
  1. store.aput(namespace, key, value)

### 30. GET /store/items — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/store.py:54 get_store_item`
- Data access: `AsyncPostgresStore.aget scoped to ['users', user.identity, ...]`
- Auth checks: require_auth router dependency; handle_event('store', 'get'); apply_user_namespace_scoping enforces ['users', user.identity] prefix
- Evidence: libs/aegra-api/src/aegra_api/api/store.py:76-90,214-226
- Reason: Namespace input (dotted string or list) is normalized and forced under ['users', user.identity] before calling store.aget.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/store.py:54 get_store_item
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/api/store.py:214 apply_user_namespace_scoping
  1. store.aget(namespace, key)

### 31. DELETE /store/items — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/store.py:94 delete_store_item`
- Data access: `AsyncPostgresStore.adelete scoped to ['users', user.identity, ...]`
- Auth checks: require_auth router dependency; handle_event('store', 'delete'); apply_user_namespace_scoping enforces ['users', user.identity] prefix
- Evidence: libs/aegra-api/src/aegra_api/api/store.py:124-133,214-226
- Reason: Deletes are unconditionally constrained to the caller's ['users', user.identity] namespace prefix.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/store.py:94 delete_store_item
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/api/store.py:214 apply_user_namespace_scoping
  1. store.adelete(namespace, key)

### 32. POST /store/items/search — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/store.py:136 search_store_items`
- Data access: `AsyncPostgresStore.asearch scoped to ['users', user.identity, ...]`
- Auth checks: require_auth router dependency; handle_event('store', 'search'); apply_user_namespace_scoping enforces ['users', user.identity] prefix
- Evidence: libs/aegra-api/src/aegra_api/api/store.py:157-171,214-226
- Reason: Search prefix is always scoped under ['users', user.identity] via apply_user_namespace_scoping.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/store.py:136 search_store_items
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/api/store.py:214 apply_user_namespace_scoping
  1. store.asearch(prefix, ...)

### 33. POST /store/namespaces — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/store.py:181 list_namespaces`
- Data access: `AsyncPostgresStore.alist_namespaces scoped to prefix ['users', user.identity, ...]`
- Auth checks: require_auth router dependency; handle_event('store', 'search'); apply_user_namespace_scoping enforces ['users', user.identity] prefix
- Evidence: libs/aegra-api/src/aegra_api/api/store.py:199-211,214-226
- Reason: Namespace listing always constrains the prefix to ['users', user.identity, ...], isolating namespace discovery per user.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/store.py:181 list_namespaces
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/api/store.py:214 apply_user_namespace_scoping
  1. store.alist_namespaces(prefix, ...)

### 34. GET /threads/{thread_id}/runs/{run_id} — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/runs.py:115 get_run`
- Data access: `SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity`
- Auth checks: require_auth router dependency; handle_event('runs', 'read'); DB query enforces RunORM.user_id == user.identity
- Evidence: libs/aegra-api/src/aegra_api/api/runs.py:131-141
- Reason: Run lookup strictly filters by run_id, thread_id, and user_id == user.identity, preventing retrieval of another user's run records.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/runs.py:115 get_run
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT RunORM WHERE run_id = ? AND thread_id = ? AND user_id = user.identity

### 35. POST /threads/search — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:775 search_threads`
- Data access: `SELECT ThreadORM WHERE user_id = user.identity AND ...`
- Auth checks: require_auth router dependency; handle_event('threads', 'search'); DB query filters by ThreadORM.user_id == user.identity
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:786-816
- Reason: Search query always restricts results to ThreadORM.user_id == user.identity.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:775 search_threads
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT ThreadORM WHERE user_id = user.identity

### 36. DELETE /threads/{thread_id} — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:728 delete_thread`
- Data access: `SELECT/DELETE ThreadORM scoped by user_id == user.identity; cancel active RunORM scoped by user_id == user.identity`
- Auth checks: require_auth router dependency; handle_event('threads', 'delete'); DB queries filter both ThreadORM and RunORM by user.identity
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:744-769
- Reason: Verifies ThreadORM.user_id == user.identity before cancelling runs and deleting the thread.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:728 delete_thread
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity
  1. SELECT RunORM WHERE thread_id = ? AND user_id = user.identity
  1. session.delete(thread)

### 37. GET /threads/{thread_id} — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:222 get_thread`
- Data access: `SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity`
- Auth checks: require_auth router dependency; handle_event('threads', 'read'); DB query filters by ThreadORM.user_id == user.identity
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:235-241
- Reason: Thread lookup explicitly scopes by ThreadORM.user_id == user.identity and returns 404 otherwise.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:222 get_thread
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity

### 38. POST /threads — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/threads.py:134 create_thread`
- Data access: `SELECT ThreadORM WHERE thread_id = ? AND user_id = user.identity; INSERT ThreadORM with user_id = user.identity`
- Auth checks: require_auth router dependency; handle_event('threads', 'create'); ThreadORM.user_id == user.identity on existence check and insert
- Evidence: libs/aegra-api/src/aegra_api/api/threads.py:159-186
- Reason: Existing thread lookup for idempotency is scoped by user.identity, and new threads are created with user_id and metadata['owner'] set to user.identity.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/threads.py:134 create_thread
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. SELECT/INSERT ThreadORM

### 39. DELETE /assistants/{assistant_id} — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:178 delete_assistant`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? AND user_id = user_identity; session.delete(assistant)`
- Auth checks: require_auth router dependency; handle_event('assistants', 'delete'); DB SELECT enforces user_id == user_identity
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:338-352
- Reason: Assistant lookup strictly requires AssistantORM.user_id == user_identity before deletion.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:178 delete_assistant
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:338 delete_assistant

### 40. PATCH /assistants/{assistant_id} — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:152 update_assistant`
- Data access: `SELECT/UPDATE AssistantORM WHERE assistant_id = ? AND user_id = user_identity; INSERT AssistantVersionORM`
- Auth checks: require_auth router dependency; handle_event('assistants', 'update'); DB SELECT and UPDATE both enforce user_id == user_identity
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:290-335
- Reason: Both the pre-check SELECT and the UPDATE strictly require AssistantORM.user_id == user_identity (excluding even 'system' assistants).
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:152 update_assistant
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:273 update_assistant

### 41. GET /assistants/{assistant_id} — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:129 get_assistant`
- Data access: `SELECT AssistantORM WHERE assistant_id = ? AND (user_id = user_identity OR user_id = 'system')`
- Auth checks: require_auth router dependency; handle_event('assistants', 'read'); DB query scoped to user_identity or 'system'
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:261-271
- Reason: Lookup enforces ownership by restricting AssistantORM to user_identity or 'system' defaults and returns 404 otherwise.
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:129 get_assistant
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:261 get_assistant

### 42. POST /assistants — unlikely (5)

- Handler: `libs/aegra-api/src/aegra_api/api/assistants.py:31 create_assistant`
- Data access: `SELECT AssistantORM WHERE user_id = user_identity AND (...); INSERT AssistantORM + AssistantVersionORM with user_id = user_identity`
- Auth checks: require_auth router dependency; handle_event('assistants', 'create'); AssistantORM.user_id == user_identity on existence check and insert
- Evidence: libs/aegra-api/src/aegra_api/services/assistant_service.py:163-196
- Reason: New assistants are always created with user_id bound to the authenticated user, and duplicate checks are scoped to user_identity (colliding with another user's assistant_id fails at DB PK constraint rather than returning or modifying the other user's record).
- Execution path:
  1. libs/aegra-api/src/aegra_api/api/assistants.py:31 create_assistant
  1. libs/aegra-api/src/aegra_api/core/auth_handlers.py:55 handle_event
  1. libs/aegra-api/src/aegra_api/services/assistant_service.py:122 create_assistant

### 43. GET /metrics — unlikely (0)

- Handler: `libs/aegra-api/src/aegra_api/observability/metrics.py:15 setup_prometheus_metrics`
- Data access: `Prometheus registry exposition (when ENABLE_PROMETHEUS_METRICS=true)`
- Auth checks: none (intentionally unauthenticated when enabled)
- Evidence: libs/aegra-api/src/aegra_api/observability/metrics.py:34-43
- Reason: Exposes aggregate Prometheus metrics when enabled; does not accept or access per-user objects.
- Execution path:
  1. libs/aegra-api/src/aegra_api/main.py:310 setup_prometheus_metrics
  1. libs/aegra-api/src/aegra_api/observability/metrics.py:42 instrumentator.expose

### 44. GET /live — unlikely (0)

- Handler: `libs/aegra-api/src/aegra_api/core/health.py:143 liveness_check`
- Data access: ``
- Auth checks: none (public liveness probe)
- Evidence: libs/aegra-api/src/aegra_api/core/health.py:143-149
- Reason: Returns static alive status with no object identifier or data access.
- Execution path:
  1. libs/aegra-api/src/aegra_api/core/health.py:143 liveness_check

### 45. GET /ready — unlikely (0)

- Handler: `libs/aegra-api/src/aegra_api/core/health.py:107 readiness_check`
- Data access: `Hardcoded readiness probes on Postgres, checkpointer, and store`
- Auth checks: none (public readiness probe)
- Evidence: libs/aegra-api/src/aegra_api/core/health.py:107-139
- Reason: Performs readiness probes using hardcoded identifiers only; no user-controlled object identifier is accepted.
- Execution path:
  1. libs/aegra-api/src/aegra_api/core/health.py:107 readiness_check
  1. db_manager.engine SELECT 1
  1. checkpointer.aget_tuple('ready-check')
  1. store.aget(('ready',), 'check')

### 46. GET /health — unlikely (0)

- Handler: `libs/aegra-api/src/aegra_api/core/health.py:51 health_check`
- Data access: `Hardcoded connectivity probes on Postgres, checkpointer, and store`
- Auth checks: none (public health endpoint)
- Evidence: libs/aegra-api/src/aegra_api/core/health.py:51-103
- Reason: Performs connectivity probes using hardcoded identifiers only; no user-controlled object identifier is accepted.
- Execution path:
  1. libs/aegra-api/src/aegra_api/core/health.py:51 health_check
  1. db_manager.engine SELECT 1
  1. checkpointer.aget_tuple('health-check')
  1. store.aget(('health',), 'check')

### 47. GET /info — unlikely (0)

- Handler: `libs/aegra-api/src/aegra_api/core/health.py:34 info`
- Data access: ``
- Auth checks: none (health router is intentionally unauthenticated)
- Evidence: libs/aegra-api/src/aegra_api/core/health.py:34-47
- Reason: Returns static service name, version, and feature flags with no object identifier or data access.
- Execution path:
  1. libs/aegra-api/src/aegra_api/core/health.py:34 info

### 48. GET / — unlikely (0)

- Handler: `libs/aegra-api/src/aegra_api/main.py:172 root_handler`
- Data access: ``
- Auth checks: none (public root status endpoint)
- Evidence: libs/aegra-api/src/aegra_api/main.py:172-179
- Reason: Returns static service metadata (name, version, status) and accepts no user-controlled object identifiers.
- Execution path:
  1. libs/aegra-api/src/aegra_api/main.py:172 root_handler
