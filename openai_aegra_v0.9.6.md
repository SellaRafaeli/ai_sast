# BOLA/IDOR review by gpt-6.2-astra

- Repo: https://github.com/aegra/aegra/tree/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd
- Turns: 13 (stopped by budget), reasoning.effort=high
- Tokens: in 1647649 (+0 tool), out 15748, thinking 13210, web searches 32; cost ≈ $4.93
- Framework: FastAPI and Starlette, with APIRouter modules mounted by main.py. Source paths below are relative to libs/aegra-api/src/aegra_api/ unless they start with examples/. Line references use the fetched source views.

This static review covers 51 application routes, including streaming routes, the configured example routes, and optional metrics; framework-generated documentation routes are excluded. With distinct authenticated users, many operations constrain the database query by owner, and existing-run streaming checks the run, thread, and caller before opening either replay or live delivery. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/main.py)) The main findings concern preserving the authorized thread through checkpoint operations, enforcing custom visibility filters in addition to baseline ownership, and keeping thread deletion consistent with checkpoint retention. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py)) The six run-creation variants remain unknown at the cutoff: their shared execution machinery was identified, but end-to-end authorization of every referenced object was not established; a score of 50 on those entries denotes incomplete evidence, not a confirmed vulnerability. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))

| # | Score | Verdict | Method | Path | Object | Reason |
|---|---|---|---|---|---|---|
| 1 | 75 | possible | POST | `/threads/{thread_id}/history` | Thread and checkpoint history | The ownership check on the metadata row does not establish that the subsequent history read stays within that row's persistence scope. Response serialization is not a second authorization check. |
| 2 | 75 | possible | POST | `/threads/{thread_id}/state` | Thread and checkpoint | The write branch does not establish that the final persistence scope is identical to the thread that passed authorization. The read delegation should not be treated as evidence that the write branch is safe. |
| 3 | 50 | unknown | POST | `/threads/{thread_id}/runs` | Parent thread and requested assistant | Assigning the new run to the caller does not by itself authorize its parent relationships. |
| 4 | 50 | unknown | POST | `/threads/{thread_id}/runs/stream` | Parent thread and requested assistant | This creates work rather than attaching to an existing run. The verified ownership check on stream attachment is not evidence about run creation. |
| 5 | 50 | unknown | POST | `/threads/{thread_id}/runs/wait` | Parent thread and requested assistant | A scoped output read does not establish that all earlier reads and writes during creation were authorized. |
| 6 | 50 | unknown | POST | `/runs/wait` | Requested assistant; server-generated thread | Generating the thread removes one caller-controlled parent reference, but does not establish authorization of every object used by the run. |
| 7 | 50 | unknown | POST | `/runs/stream` | Requested assistant; server-generated thread | The cleanup check protects deletion. It does not establish authorization of inputs to the earlier graph execution. |
| 8 | 50 | unknown | POST | `/runs` | Requested assistant; server-generated thread | A server-generated thread and a caller-owned run record are not evidence that every referenced resource is authorized. |
| 9 | 45 | possible | GET | `/threads` | Thread collection | Baseline cross-user isolation is present. A deployment that uses the documented hook to restrict an owner to a subset of their threads can receive a broader list than its policy permits. |
| 10 | 35 | possible | POST | `/assistants/search` | Assistant collection selected by search criteria | The query excludes other users' private rows. The route and service do not use the same representation for additional policy filters, so narrower deployment-specific visibility is not established. |
| 11 | 35 | possible | GET | `/assistants` | Assistant collection | The baseline owner boundary is present, and system visibility is intentional. The filtered branch does not establish that an additional visibility restriction returned by a custom hook becomes a SQL predicate. |
| 12 | 30 | possible | POST | `/assistants/count` | Count of matching assistants | The result is an aggregate, not an assistant record. A count can nevertheless reveal the existence of records excluded by a narrower custom policy if it does not use the same authorized query as search. |
| 13 | 12 | unlikely | PATCH | `/threads/{thread_id}/runs/{run_id}` | Thread ID and run ID | Later operations use the same run ID after authorization; an unscoped internal call is not by itself an independently reachable IDOR. |
| 14 | 12 | unlikely | POST | `/threads/search` | Thread collection selected by metadata and status | Search criteria narrow the owner-scoped relation. This conclusion does not imply support for every possible custom policy field. |
| 15 | 12 | unlikely | POST | `/threads` | Optional client-specified thread ID | The idempotent branch does not return another owner's existing thread. This conclusion concerns the metadata row, not the lifetime of separately persisted checkpoints. |
| 16 | 12 | unlikely | DELETE | `/threads/{thread_id}` | Thread ID and its active runs | The immediate deletion is owner-scoped. Separately, the handler says checkpoint history survives deletion, whereas the guide says all state is removed; this review did not establish safe isolation of retained state across the full thread lifecycle. |
| 17 | 12 | unlikely | GET | `/threads/{thread_id}/history` | Thread ID, checkpoint cursor, and namespace | Sharing a helper does not make these two history routes equivalent: the GET adapter constructs a narrower request. |
| 18 | 10 | unlikely | GET | `/threads/{thread_id}/state` | Thread ID and optional checkpoint namespace | The same thread ID is used for the owner check and the state request. The caller can select a namespace, not a different parent thread through this handler. |
| 19 | 10 | unlikely | GET | `/threads/{thread_id}/state/{checkpoint_id}` | Thread ID, checkpoint ID, and optional namespace | The handler adds the checkpoint selector without replacing the authorized parent thread. |
| 20 | 10 | unlikely | POST | `/threads/{thread_id}/state/checkpoint` | Path thread ID and body checkpoint ID | This POST is a read adapter. It extracts the checkpoint ID and namespace rather than forwarding the entire body as the storage configuration. |
| 21 | 8 | unlikely | POST | `/threads/{thread_id}/runs/{run_id}/cancel` | Thread ID and run ID | Cancellation is not sent merely because a caller knows the run ID. |
| 22 | 8 | unlikely | POST | `/assistants` | Optional assistant ID; configured graph ID | The idempotent branch returns an existing row only after an owner-scoped lookup. Selecting a registered graph is not the same as selecting another user's assistant. |
| 23 | 8 | unlikely | GET | `/assistants/{assistant_id}` | Assistant ID | The owner predicate is part of the lookup. A private assistant belonging to a different identity does not match. |
| 24 | 8 | unlikely | GET | `/assistants/{assistant_id}/subgraphs` | Assistant ID and optional subgraph namespace | The namespace filters within the selected graph; it does not choose another user's assistant row. |
| 25 | 8 | unlikely | POST | `/assistants/{assistant_id}/latest` | Assistant ID and version number | A version number is not resolved globally. Both the child selection and parent mutation retain the authorized assistant ID. |
| 26 | 8 | unlikely | POST | `/assistants/{assistant_id}/versions` | Assistant ID and its version history | The child query relies on a preceding check of the same parent ID; it is not an independent unscoped version lookup. |
| 27 | 7 | unlikely | GET | `/threads/{thread_id}/runs` | Thread ID and its run collection | A thread ID does not cause the endpoint to return runs owned by another user. |
| 28 | 7 | unlikely | GET | `/assistants/{assistant_id}/schemas` | Assistant ID | The graph is derived from the authorized row before its schema is inspected. |
| 29 | 7 | unlikely | GET | `/assistants/{assistant_id}/graph` | Assistant ID | The expansion option changes the detail returned, not which assistant is selected. |
| 30 | 7 | unlikely | PATCH | `/threads/{thread_id}` | Thread ID | Changing metadata through this handler does not change the owner column used to select the thread. |
| 31 | 5 | unlikely | POST | `/store/namespaces` | Namespace prefix and suffix | The suffix and pagination options operate within the scoped enumeration. |
| 32 | 5 | unlikely | POST | `/store/items/search` | Namespace prefix and matching items | Search terms and metadata filters do not choose a different namespace root. |
| 33 | 5 | unlikely | DELETE | `/store/items` | Namespace and key | Selecting the body instead of the query string does not skip authorization. |
| 34 | 5 | unlikely | GET | `/store/items` | Namespace and key | Alternate namespace representations do not remove the caller's prefix. |
| 35 | 5 | unlikely | PUT | `/store/items` | Namespace and key | A caller-provided namespace is not accepted as another user's storage root. |
| 36 | 5 | unlikely | GET | `/threads/{thread_id}` | Thread ID | A foreign ID does not match the query and produces a not-found response. |
| 37 | 5 | unlikely | PATCH | `/assistants/{assistant_id}` | Assistant ID | System assistants are not included merely because they are readable. The mutation repeats the owner predicate. |
| 38 | 5 | unlikely | DELETE | `/threads/{thread_id}/runs/{run_id}` | Thread ID and run ID | The force option changes active-run handling, not ownership scope. |
| 39 | 5 | unlikely | DELETE | `/assistants/{assistant_id}` | Assistant ID | A missing or foreign assistant is rejected before deletion. |
| 40 | 5 | unlikely | GET | `/threads/{thread_id}/runs/{run_id}/stream` | Thread ID, run ID, and replay cursor | Neither broker uses the replay cursor to select a different run. A cursor miss stays inside the authorized run's buffer. |
| 41 | 5 | unlikely | GET | `/threads/{thread_id}/runs/{run_id}/join` | Thread ID and run ID | Releasing the database connection during the wait does not discard the ownership check on the final output. |
| 42 | 5 | unlikely | GET | `/threads/{thread_id}/runs/{run_id}` | Thread ID and run ID | Neither a run ID alone nor a matching parent alone is sufficient. |
| 43 | 0 | unlikely | GET | `/` |  | Returns service metadata, not a selected user's object. |
| 44 | 0 | unlikely | GET | `/info` |  | No object identifier is consumed. |
| 45 | 0 | unlikely | GET | `/health` |  | The caller cannot direct the probe to a tenant object. |
| 46 | 0 | unlikely | GET | `/ready` |  | The presence of a database lookup does not make this an IDOR: none of its object selectors come from the request. |
| 47 | 0 | unlikely | GET | `/live` |  | Returns process liveness without loading tenant data. |
| 48 | 0 | unlikely | GET | `/custom/whoami` |  | There is no parameter for selecting another profile. |
| 49 | 0 | unlikely | GET | `/custom/public` |  | The handler returns fixed text. |
| 50 | 0 | unlikely | GET | `/custom/protected` |  | The caller cannot supply the identity whose attributes are returned. |
| 51 | 0 | unlikely | GET | `/metrics` |  | Public metrics exposure is a deployment concern, but it is not object-level authorization bypass under the requested definition. |

## Details

### 1. POST /threads/{thread_id}/history — possible (75)

- Handler: `api/threads.py:604 get_thread_history_post`
- Data access: `Pages through persisted snapshots and converts them to thread-state responses.`
- Auth checks: The path thread is owner-checked before the history configuration is finalized.
- Evidence: api/threads.py:614–645,659–683. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: The ownership check on the metadata row does not establish that the subsequent history read stays within that row's persistence scope. Response serialization is not a second authorization check.
- Fix: Bind the history query to the authorized thread independently of caller-supplied checkpoint and pagination options.
- Execution path:
  1. get_thread_history_post
  1. owned thread lookup
  1. history configuration
  1. graph.aget_state_history

### 2. POST /threads/{thread_id}/state — possible (75)

- Handler: `api/threads.py:379 update_thread_state`
- Data access: `Reads current state when no values are supplied; otherwise submits an update to the graph checkpointer.`
- Auth checks: The metadata lookup checks the caller's ownership of the path thread. The persistence configuration is then assembled separately.
- Evidence: api/threads.py:392–435,449–458. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: The write branch does not establish that the final persistence scope is identical to the thread that passed authorization. The read delegation should not be treated as evidence that the write branch is safe.
- Fix: Construct the write from an immutable authorized thread identity and accept only checkpoint options that cannot change that identity.
- Execution path:
  1. update_thread_state
  1. read delegation or owned thread lookup
  1. graph state update

### 3. POST /threads/{thread_id}/runs — unknown (50)

- Handler: `api/runs.py:34 create_run`
- Data access: `Prepares a run, updates thread metadata, persists execution parameters, and submits work.`
- Auth checks: Create-run hook and current user are visible. Authorization of every referenced object was not established end to end.
- Evidence: api/runs.py:33–64; services/run_preparation.py:184–253. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: Assigning the new run to the caller does not by itself authorize its parent relationships.
- Fix: Require authorized thread and assistant records before any state change or job submission.
- Execution path:
  1. create_run
  1. _prepare_run
  1. persist RunJob
  1. executor.submit

### 4. POST /threads/{thread_id}/runs/stream — unknown (50)

- Handler: `api/runs.py:69 create_and_stream_run`
- Data access: `Creates a run and opens an event stream for it.`
- Auth checks: Authenticated identity is available; the complete creation policy was not established.
- Evidence: api/runs.py:68–101; services/run_preparation.py:184–253. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: This creates work rather than attaching to an existing run. The verified ownership check on stream attachment is not evidence about run creation.
- Fix: Make streaming creation use the same authorized preparation operation as non-streaming creation.
- Execution path:
  1. create_and_stream_run
  1. shared run preparation
  1. execute and stream

### 5. POST /threads/{thread_id}/runs/wait — unknown (50)

- Handler: `api/runs.py:264 wait_for_run`
- Data access: `Creates a run and waits for its output.`
- Auth checks: Final output is scoped to caller, thread, and run; the creation path was not fully resolved.
- Evidence: api/runs.py:278–289; services/run_waiters.py:24–41. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: A scoped output read does not establish that all earlier reads and writes during creation were authorized.
- Fix: Authorize all referenced objects before preparation, not only when returning output.
- Execution path:
  1. wait_for_run
  1. _prepare_run
  1. heartbeat_wait_body
  1. read_run_output

### 6. POST /runs/wait — unknown (50)

- Handler: `api/stateless_runs.py:97 stateless_wait_for_run`
- Data access: `Delegates creation and execution, then handles the ephemeral thread lifecycle.`
- Auth checks: The wrapper uses the current user and generates its thread; delegated object authorization remains unresolved.
- Evidence: api/stateless_runs.py:2–5,39–74,96–153. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/stateless_runs.py))
- Reason: Generating the thread removes one caller-controlled parent reference, but does not establish authorization of every object used by the run.
- Fix: Apply the shared run-creation authorization contract to stateless runs as well.
- Execution path:
  1. stateless_wait_for_run
  1. ephemeral thread
  1. threaded wait path
  1. conditional cleanup

### 7. POST /runs/stream — unknown (50)

- Handler: `api/stateless_runs.py:157 stateless_stream_run`
- Data access: `Delegates to threaded streaming with the caller and generated thread ID.`
- Auth checks: Caller is propagated; cleanup selects by thread and owner.
- Evidence: api/stateless_runs.py:163–198; api/runs.py:68–101. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/stateless_runs.py))
- Reason: The cleanup check protects deletion. It does not establish authorization of inputs to the earlier graph execution.
- Fix: Authorize referenced objects before starting the stream or its underlying job.
- Execution path:
  1. stateless_stream_run
  1. ephemeral thread
  1. create_and_stream_run
  1. conditional cleanup

### 8. POST /runs — unknown (50)

- Handler: `api/stateless_runs.py:213 stateless_create_run`
- Data access: `Submits a background run through the threaded creation path.`
- Auth checks: Current user is passed to creation and cleanup; complete delegated authorization was not established.
- Evidence: api/stateless_runs.py:212–244; services/run_preparation.py:198–253. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/stateless_runs.py))
- Reason: A server-generated thread and a caller-owned run record are not evidence that every referenced resource is authorized.
- Fix: Build the job from authorized records and preserve those identities through execution.
- Execution path:
  1. stateless_create_run
  1. ephemeral thread
  1. create_run
  1. optional background cleanup

### 9. GET /threads — possible (45)

- Handler: `api/threads.py:199 list_threads`
- Data access: `Selects rows owned by the caller.`
- Auth checks: Owner equality is enforced; additional restrictions returned by the search hook are not applied in this branch.
- Evidence: api/threads.py:206–221; docs/guides/authentication.mdx:125–129. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: Baseline cross-user isolation is present. A deployment that uses the documented hook to restrict an owner to a subset of their threads can receive a broader list than its policy permits.
- Fix: Use the same policy-constrained query builder for thread listing and search.
- Execution path:
  1. list_threads
  1. search authorization hook
  1. thread collection query

### 10. POST /assistants/search — possible (35)

- Handler: `api/assistants.py:77 search_assistants`
- Data access: `Filters the caller-or-system query, then applies pagination.`
- Auth checks: Owner-or-system predicate; route also accepts restrictions from the search hook.
- Evidence: api/assistants.py:86–95; services/assistant_service.py:208–236. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/assistants.py))
- Reason: The query excludes other users' private rows. The route and service do not use the same representation for additional policy filters, so narrower deployment-specific visibility is not established.
- Fix: Intersect policy restrictions with search criteria in SQL and reject unsupported policy fields.
- Execution path:
  1. search_assistants
  1. search authorization hook
  1. AssistantService.search_assistants

### 11. GET /assistants — possible (35)

- Handler: `api/assistants.py:54 list_assistants`
- Data access: `Selects caller-owned and system assistants.`
- Auth checks: Authenticated identity scopes both service branches.
- Evidence: api/assistants.py:62–74; services/assistant_service.py:201–236. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/assistants.py))
- Reason: The baseline owner boundary is present, and system visibility is intentional. The filtered branch does not establish that an additional visibility restriction returned by a custom hook becomes a SQL predicate.
- Fix: Apply normalized authorization predicates in the shared query builder rather than relying on conversion to a search request.
- Execution path:
  1. list_assistants
  1. search authorization hook
  1. AssistantService.list_assistants or search_assistants

### 12. POST /assistants/count — possible (30)

- Handler: `api/assistants.py:99 count_assistants`
- Data access: `Counts caller-owned and system rows matching supported search fields.`
- Auth checks: Owner-or-system predicate; custom search hook.
- Evidence: api/assistants.py:108–117; services/assistant_service.py:237–258. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/assistants.py))
- Reason: The result is an aggregate, not an assistant record. A count can nevertheless reveal the existence of records excluded by a narrower custom policy if it does not use the same authorized query as search.
- Fix: Compute the count from the same policy-constrained relation used for listing.
- Execution path:
  1. count_assistants
  1. search authorization hook
  1. AssistantService.count_assistants

### 13. PATCH /threads/{thread_id}/runs/{run_id} — unlikely (12)

- Handler: `api/runs.py:170 update_run`
- Data access: `Checks the selected row before interrupting the run or changing its status.`
- Auth checks: Initial lookup binds run, parent, and owner.
- Evidence: api/runs.py:181–212. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: Later operations use the same run ID after authorization; an unscoped internal call is not by itself an independently reachable IDOR.
- Execution path:
  1. update_run
  1. scoped run lookup
  1. optional broker interruption
  1. status update

### 14. POST /threads/search — unlikely (12)

- Handler: `api/threads.py:769 search_threads`
- Data access: `Selects caller-owned rows before applying filters and pagination.`
- Auth checks: Owner equality; supported hook-provided metadata restrictions are merged into the query.
- Evidence: api/threads.py:778–812. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: Search criteria narrow the owner-scoped relation. This conclusion does not imply support for every possible custom policy field.
- Execution path:
  1. search_threads
  1. search hook
  1. owner-scoped query with metadata and status filters

### 15. POST /threads — unlikely (12)

- Handler: `api/threads.py:136 create_thread`
- Data access: `Returns an existing owned thread or inserts a row owned by the caller.`
- Auth checks: Existing row must match both the thread ID and caller. New row ownership comes from authenticated identity.
- Evidence: api/threads.py:147–196. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: The idempotent branch does not return another owner's existing thread. This conclusion concerns the metadata row, not the lifetime of separately persisted checkpoints.
- Execution path:
  1. create_thread
  1. create hook
  1. owner-scoped existing-thread lookup
  1. thread insert

### 16. DELETE /threads/{thread_id} — unlikely (12)

- Handler: `api/threads.py:727 delete_thread`
- Data access: `Cancels matching active runs and deletes the selected thread row.`
- Auth checks: Both the thread lookup and active-run query include the current owner.
- Evidence: api/threads.py:732–763; docs/guides/threads-and-state.mdx:137–142. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: The immediate deletion is owner-scoped. Separately, the handler says checkpoint history survives deletion, whereas the guide says all state is removed; this review did not establish safe isolation of retained state across the full thread lifecycle.
- Fix: Align checkpoint retention with thread deletion and ensure retained state cannot be rebound to another owner.
- Execution path:
  1. delete_thread
  1. delete hook
  1. owned thread lookup
  1. owner-scoped active-run lookup
  1. thread row deletion

### 17. GET /threads/{thread_id}/history — unlikely (12)

- Handler: `api/threads.py:694 get_thread_history_get`
- Data access: `Delegates with a string cursor and without a body checkpoint configuration.`
- Auth checks: The delegated reader checks ownership of the path thread.
- Evidence: api/threads.py:693–724,624–640. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: Sharing a helper does not make these two history routes equivalent: the GET adapter constructs a narrower request.
- Execution path:
  1. get_thread_history_get
  1. construct bounded history request
  1. get_thread_history_post
  1. graph.aget_state_history

### 18. GET /threads/{thread_id}/state — unlikely (10)

- Handler: `api/threads.py:287 get_thread_state`
- Data access: `Reads a snapshot using a configuration built for the selected thread.`
- Auth checks: Checks thread ID and caller before obtaining the graph or returning an empty state.
- Evidence: api/threads.py:299–347; services/langgraph_service.py:627–636. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: The same thread ID is used for the owner check and the state request. The caller can select a namespace, not a different parent thread through this handler.
- Execution path:
  1. get_thread_state
  1. owned thread lookup
  1. create_thread_config
  1. graph.aget_state

### 19. GET /threads/{thread_id}/state/{checkpoint_id} — unlikely (10)

- Handler: `api/threads.py:504 get_thread_state_at_checkpoint`
- Data access: `Requests the named checkpoint under the configured thread.`
- Auth checks: Thread ownership is checked before constructing the checkpoint selector.
- Evidence: api/threads.py:516–545. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: The handler adds the checkpoint selector without replacing the authorized parent thread.
- Execution path:
  1. get_thread_state_at_checkpoint
  1. owned thread lookup
  1. create_thread_config
  1. graph.aget_state

### 20. POST /threads/{thread_id}/state/checkpoint — unlikely (10)

- Handler: `api/threads.py:576 get_thread_state_at_checkpoint_post`
- Data access: `Delegates to the single-checkpoint reader.`
- Auth checks: Delegation preserves the path thread ID and current user.
- Evidence: api/threads.py:587–601,516–545. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: This POST is a read adapter. It extracts the checkpoint ID and namespace rather than forwarding the entire body as the storage configuration.
- Execution path:
  1. get_thread_state_at_checkpoint_post
  1. get_thread_state_at_checkpoint
  1. owned thread lookup
  1. graph.aget_state

### 21. POST /threads/{thread_id}/runs/{run_id}/cancel — unlikely (8)

- Handler: `api/runs.py:359 cancel_run_endpoint`
- Data access: `Signals the authorized run and updates its status.`
- Auth checks: Run, parent, and owner are checked before signaling and on final reload.
- Evidence: api/runs.py:377–405,418–428. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: Cancellation is not sent merely because a caller knows the run ID.
- Execution path:
  1. cancel_run_endpoint
  1. scoped run lookup
  1. broker cancel or interrupt
  1. status update and scoped reload

### 22. POST /assistants — unlikely (8)

- Handler: `api/assistants.py:30 create_assistant`
- Data access: `Looks for an existing assistant belonging to the caller; otherwise inserts the assistant and its initial version.`
- Auth checks: Create hook; the service receives the authenticated identity and assigns it as owner.
- Evidence: api/assistants.py:41–51; services/assistant_service.py:120–136,151–200. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/assistants.py))
- Reason: The idempotent branch returns an existing row only after an owner-scoped lookup. Selecting a registered graph is not the same as selecting another user's assistant.
- Execution path:
  1. create_assistant
  1. AssistantService.create_assistant
  1. owner-scoped existing-assistant lookup or insert

### 23. GET /assistants/{assistant_id} — unlikely (8)

- Handler: `api/assistants.py:126 get_assistant`
- Data access: `Selects the ID only among caller-owned or system assistants.`
- Auth checks: Read hook and owner-or-system query.
- Evidence: api/assistants.py:135–140; services/assistant_service.py:259–269. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/assistants.py))
- Reason: The owner predicate is part of the lookup. A private assistant belonging to a different identity does not match.
- Execution path:
  1. get_assistant
  1. AssistantService.get_assistant
  1. scoped assistant lookup

### 24. GET /assistants/{assistant_id}/subgraphs — unlikely (8)

- Handler: `api/assistants.py:257 get_assistant_subgraphs`
- Data access: `Enumerates subgraphs on the graph obtained from the visible assistant.`
- Auth checks: Assistant ID plus caller-or-system ownership.
- Evidence: services/assistant_service.py:481–509. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/services/assistant_service.py))
- Reason: The namespace filters within the selected graph; it does not choose another user's assistant row.
- Execution path:
  1. get_assistant_subgraphs
  1. AssistantService.get_assistant_subgraphs
  1. visible assistant lookup
  1. subgraph enumeration

### 25. POST /assistants/{assistant_id}/latest — unlikely (8)

- Handler: `api/assistants.py:193 set_assistant_latest`
- Data access: `Loads the version under the selected assistant and updates the owner-scoped parent.`
- Auth checks: Authenticated user must own the parent assistant.
- Evidence: services/assistant_service.py:349–385. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/services/assistant_service.py))
- Reason: A version number is not resolved globally. Both the child selection and parent mutation retain the authorized assistant ID.
- Execution path:
  1. set_assistant_latest
  1. AssistantService.set_assistant_latest
  1. owned parent lookup
  1. child version lookup
  1. scoped update

### 26. POST /assistants/{assistant_id}/versions — unlikely (8)

- Handler: `api/assistants.py:211 list_assistant_versions`
- Data access: `Selects versions of an assistant already found in the caller-or-system scope.`
- Auth checks: Parent assistant visibility check.
- Evidence: services/assistant_service.py:386–401. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/services/assistant_service.py))
- Reason: The child query relies on a preceding check of the same parent ID; it is not an independent unscoped version lookup.
- Execution path:
  1. list_assistant_versions
  1. AssistantService.list_assistant_versions
  1. visible parent lookup
  1. version query

### 27. GET /threads/{thread_id}/runs — unlikely (7)

- Handler: `api/runs.py:137 list_runs`
- Data access: `Selects runs matching thread ID and caller before pagination.`
- Auth checks: Run owner equality in the collection query.
- Evidence: api/runs.py:151–167. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: A thread ID does not cause the endpoint to return runs owned by another user.
- Execution path:
  1. list_runs
  1. thread-and-owner-scoped run query

### 28. GET /assistants/{assistant_id}/schemas — unlikely (7)

- Handler: `api/assistants.py:227 get_assistant_schemas`
- Data access: `Loads the graph named by the visible assistant row.`
- Auth checks: Assistant ID plus caller-or-system ownership.
- Evidence: services/assistant_service.py:424–442. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/services/assistant_service.py))
- Reason: The graph is derived from the authorized row before its schema is inspected.
- Execution path:
  1. get_assistant_schemas
  1. AssistantService.get_assistant_schemas
  1. visible assistant lookup
  1. graph schema extraction

### 29. GET /assistants/{assistant_id}/graph — unlikely (7)

- Handler: `api/assistants.py:239 get_assistant_graph`
- Data access: `Inspects the graph attached to the caller-visible assistant.`
- Auth checks: Assistant ID plus caller-or-system ownership.
- Evidence: services/assistant_service.py:446–474. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/services/assistant_service.py))
- Reason: The expansion option changes the detail returned, not which assistant is selected.
- Execution path:
  1. get_assistant_graph
  1. AssistantService.get_assistant_graph
  1. visible assistant lookup
  1. graph visualization

### 30. PATCH /threads/{thread_id} — unlikely (7)

- Handler: `api/threads.py:247 update_thread`
- Data access: `Modifies metadata on the selected owned ORM row.`
- Auth checks: The ownership check uses the user_id column, not caller-editable metadata.
- Evidence: api/threads.py:256–284. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: Changing metadata through this handler does not change the owner column used to select the thread.
- Execution path:
  1. update_thread
  1. update hook
  1. owner-scoped thread lookup
  1. metadata update

### 31. POST /store/namespaces — unlikely (5)

- Handler: `api/store.py:179 list_namespaces`
- Data access: `Enumerates namespaces under the identity-derived prefix.`
- Auth checks: An omitted prefix defaults to the caller's root rather than the global root.
- Evidence: api/store.py:187–212,215–227. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/store.py))
- Reason: The suffix and pagination options operate within the scoped enumeration.
- Execution path:
  1. list_namespaces
  1. search hook
  1. user-scoped prefix
  1. store.alist_namespaces

### 32. POST /store/items/search — unlikely (5)

- Handler: `api/store.py:135 search_store_items`
- Data access: `Searches beneath the authenticated user's prefix.`
- Auth checks: Identity scoping is applied after hook and request filters are combined.
- Evidence: api/store.py:142–167. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/store.py))
- Reason: Search terms and metadata filters do not choose a different namespace root.
- Execution path:
  1. search_store_items
  1. search hook
  1. user-scoped prefix
  1. store.asearch

### 33. DELETE /store/items — unlikely (5)

- Handler: `api/store.py:92 delete_store_item`
- Data access: `Deletes the key from the caller-scoped namespace.`
- Auth checks: Both parameter sources converge before identity scoping.
- Evidence: api/store.py:102–129. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/store.py))
- Reason: Selecting the body instead of the query string does not skip authorization.
- Execution path:
  1. delete_store_item
  1. body or query selection
  1. delete hook
  1. user scoping
  1. store.adelete

### 34. GET /store/items — unlikely (5)

- Handler: `api/store.py:50 get_store_item`
- Data access: `Reads from the scoped namespace tuple.`
- Auth checks: The authenticated identity determines the root after parsing.
- Evidence: api/store.py:60–85,215–227. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/store.py))
- Reason: Alternate namespace representations do not remove the caller's prefix.
- Execution path:
  1. get_store_item
  1. get hook
  1. namespace normalization and user scoping
  1. store.aget

### 35. PUT /store/items — unlikely (5)

- Handler: `api/store.py:23 put_store_item`
- Data access: `Writes the item under the caller's namespace root.`
- Auth checks: Identity-derived scoping is applied after hook processing.
- Evidence: api/store.py:28–45,215–227. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/store.py))
- Reason: A caller-provided namespace is not accepted as another user's storage root.
- Execution path:
  1. put_store_item
  1. put hook
  1. apply_user_namespace_scoping
  1. store.aput

### 36. GET /threads/{thread_id} — unlikely (5)

- Handler: `api/threads.py:225 get_thread`
- Data access: `Selects by thread ID and authenticated user ID.`
- Auth checks: Read hook and SQL ownership predicate.
- Evidence: api/threads.py:234–243. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/threads.py))
- Reason: A foreign ID does not match the query and produces a not-found response.
- Execution path:
  1. get_thread
  1. read hook
  1. owner-scoped thread lookup

### 37. PATCH /assistants/{assistant_id} — unlikely (5)

- Handler: `api/assistants.py:148 update_assistant`
- Data access: `Creates a version after selecting the owned assistant; updates the parent by ID and owner.`
- Auth checks: Update hook and owner equality.
- Evidence: services/assistant_service.py:287–333. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/services/assistant_service.py))
- Reason: System assistants are not included merely because they are readable. The mutation repeats the owner predicate.
- Execution path:
  1. update_assistant
  1. AssistantService.update_assistant
  1. owner lookup
  1. version insert and scoped update

### 38. DELETE /threads/{thread_id}/runs/{run_id} — unlikely (5)

- Handler: `api/runs.py:435 delete_run`
- Data access: `Deletes using the run ID, thread ID, and authenticated user ID.`
- Auth checks: All three conditions apply before forced cancellation and again to deletion.
- Evidence: api/runs.py:447–484. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: The force option changes active-run handling, not ownership scope.
- Execution path:
  1. delete_run
  1. delete hook
  1. scoped run lookup
  1. optional cancellation
  1. scoped DELETE

### 39. DELETE /assistants/{assistant_id} — unlikely (5)

- Handler: `api/assistants.py:171 delete_assistant`
- Data access: `Selects by assistant ID and owner, then deletes the selected row.`
- Auth checks: Delete hook and owner equality.
- Evidence: services/assistant_service.py:335–348. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/services/assistant_service.py))
- Reason: A missing or foreign assistant is rejected before deletion.
- Execution path:
  1. delete_assistant
  1. AssistantService.delete_assistant
  1. delete selected ORM row

### 40. GET /threads/{thread_id}/runs/{run_id}/stream — unlikely (5)

- Handler: `api/runs.py:298 stream_run`
- Data access: `Opens the broker for the selected run; the cursor chooses a replay position.`
- Auth checks: The route checks run ID, thread ID, and caller before selecting the broker.
- Evidence: api/runs.py:312–345; services/streaming_service.py:76–96,106–131; services/redis_broker.py:177–206,230–240. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: Neither broker uses the replay cursor to select a different run. A cursor miss stays inside the authorized run's buffer.
- Execution path:
  1. stream_run
  1. scoped run lookup
  1. stream_run_execution
  1. run-specific replay or live subscription

### 41. GET /threads/{thread_id}/runs/{run_id}/join — unlikely (5)

- Handler: `api/runs.py:215 join_run`
- Data access: `Reads terminal output immediately or fetches it again after waiting.`
- Auth checks: Initial and deferred output reads both include run, thread, and owner.
- Evidence: api/runs.py:232–255; services/run_waiters.py:24–41,92–93. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: Releasing the database connection during the wait does not discard the ownership check on the final output.
- Execution path:
  1. join_run
  1. scoped run lookup
  1. immediate output or heartbeat_wait_body
  1. read_run_output

### 42. GET /threads/{thread_id}/runs/{run_id} — unlikely (5)

- Handler: `api/runs.py:104 get_run`
- Data access: `Selects one run by run ID, parent thread, and caller.`
- Auth checks: All three values must match one row.
- Evidence: api/runs.py:114–134. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/api/runs.py))
- Reason: Neither a run ID alone nor a matching parent alone is sufficient.
- Execution path:
  1. get_run
  1. read hook
  1. scoped run lookup

### 43. GET / — unlikely (0)

- Handler: `main.py:159 root_handler`
- Data access: ``
- Auth checks: No caller-selected object.
- Evidence: main.py:158–165,301–303,328. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/main.py))
- Reason: Returns service metadata, not a selected user's object.
- Execution path:
  1. root_handler
  1. application settings

### 44. GET /info — unlikely (0)

- Handler: `core/health.py:33 info`
- Data access: ``
- Auth checks: Intentionally public.
- Evidence: core/health.py:32–44. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/core/health.py))
- Reason: No object identifier is consumed.
- Execution path:
  1. info
  1. service information response

### 45. GET /health — unlikely (0)

- Handler: `core/health.py:47 health_check`
- Data access: `Uses a constant SQL probe and fixed checkpoint and store probe identifiers.`
- Auth checks: No caller-selected object.
- Evidence: core/health.py:46–93. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/core/health.py))
- Reason: The caller cannot direct the probe to a tenant object.
- Execution path:
  1. health_check
  1. database and fixed backend probes

### 46. GET /ready — unlikely (0)

- Handler: `core/health.py:97 readiness_check`
- Data access: `Checks connectivity and uses fixed readiness identifiers.`
- Auth checks: No caller-selected object.
- Evidence: core/health.py:96–127. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/core/health.py))
- Reason: The presence of a database lookup does not make this an IDOR: none of its object selectors come from the request.
- Execution path:
  1. readiness_check
  1. database and fixed backend probes

### 47. GET /live — unlikely (0)

- Handler: `core/health.py:131 liveness_check`
- Data access: ``
- Auth checks: No caller-selected object.
- Evidence: core/health.py:130–137. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/core/health.py))
- Reason: Returns process liveness without loading tenant data.
- Execution path:
  1. liveness_check
  1. constant response

### 48. GET /custom/whoami — unlikely (0)

- Handler: `examples/custom_routes_example.py:47 whoami`
- Data access: `Reads attributes of the current principal.`
- Auth checks: The principal comes from the authentication dependency.
- Evidence: aegra.json:11–13; examples/custom_routes_example.py:46–62. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/aegra.json))
- Reason: There is no parameter for selecting another profile.
- Execution path:
  1. require_auth
  1. whoami
  1. current user attributes

### 49. GET /custom/public — unlikely (0)

- Handler: `examples/custom_routes_example.py:65 public_endpoint`
- Data access: ``
- Auth checks: Public example; no selected resource.
- Evidence: examples/custom_routes_example.py:64–74. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/examples/custom_routes_example.py))
- Reason: The handler returns fixed text.
- Execution path:
  1. public_endpoint
  1. constant response

### 50. GET /custom/protected — unlikely (0)

- Handler: `examples/custom_routes_example.py:77 protected_endpoint`
- Data access: `Reads the current principal's identity and role.`
- Auth checks: The principal comes from the authentication dependency.
- Evidence: examples/custom_routes_example.py:76–87. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/examples/custom_routes_example.py))
- Reason: The caller cannot supply the identity whose attributes are returned.
- Execution path:
  1. require_auth
  1. protected_endpoint
  1. current user attributes

### 51. GET /metrics — unlikely (0)

- Handler: `observability/metrics.py:43 setup_prometheus_metrics registers the library handler`
- Data access: `Exposes the metrics registry when enabled.`
- Auth checks: Intentionally outside application authentication; no caller-selected tenant object was identified.
- Evidence: observability/metrics.py:28–44; main.py:330. ([raw.githubusercontent.com](https://raw.githubusercontent.com/aegra/aegra/d7d80c850010a9c5a3d2be59254c19b9eb0e25dd/libs/aegra-api/src/aegra_api/observability/metrics.py))
- Reason: Public metrics exposure is a deployment concern, but it is not object-level authorization bypass under the requested definition.
- Execution path:
  1. setup_prometheus_metrics
  1. conditional Instrumentator.expose
  1. metrics registry
