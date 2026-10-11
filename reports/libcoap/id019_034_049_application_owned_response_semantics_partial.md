# Response Semantics Are Application-Owned

## Summary

These three entries share one root cause: the library leaves the final response semantics to application/resource handlers rather than enforcing them globally in the core dispatch layer.

They are related, but they are not identical in strength:

- The first entry has the strongest core-library support because unknown-resource dispatch can fall back to a default `4.04 Not Found` path.
- The second entry is more handler-owned because, once a resource matches, the final success code is selected by the application/resource handler.
- The third entry is the most handler-owned of the three because content negotiation requires the handler to decide whether the requested `Accept` value can actually be satisfied and to return `4.06 Not Acceptable` when it cannot.

## Standard Requirement

Standard: RFC 7252 multicast/resource and Content-Format handling sections.

Original English requirement excerpts:

```text
C does not have matching response, therefore it sends a Non-confirmable 4.04 (Not Found) response.
```

```text
Servers A and B have a matching resource, therefore they send back a Non-confirmable 2.05 (Content) response.
```

```text
If the preferred Content- Format cannot be returned, then a 4.06 "Not Acceptable" MUST be sent as a response, unless another error code takes precedence for this response.
```

Interpretation: all three require knowing application/resource state:

- whether the multicast endpoint has no matching resource
- whether a matching resource returns 2.05 Content
- whether the preferred Content-Format can be returned

That shared dependency on resource/application state is why they can be grouped together, but the implementation burden is not the same for all three.

## Code Behavior

Relevant sources:

```text
include/coap3/coap_pdu.h
src/coap_pdu.c
src/coap_net.c
src/coap_resource.c
```

The response codes are defined:

```c
COAP_RESPONSE_CODE_NOT_FOUND = COAP_RESPONSE_CODE(404)
COAP_RESPONSE_CODE_CONTENT = COAP_RESPONSE_CODE(205)
COAP_RESPONSE_CODE_NOT_ACCEPTABLE = COAP_RESPONSE_CODE(406)
```

The core dispatch layer routes requests to registered resource handlers. Those handlers decide success response code, payload, and content format. The library does provide defaults such as 4.04 for unknown resources and can emit 4.06 in some framework paths, but it does not globally force all application resources to use one specific response code.

In practical terms:

- The first entry benefits from an existing core fallback path for unknown resources.
- The second entry does not have a comparable core rule that forces every matching resource to answer with `2.05`.
- The third entry does not have a comparable core rule that checks `Accept` against the handler-selected `Content-Format` and rewrites a mismatching success response to `4.06`.

## Runtime Reproduction

The phase-2 runtime checks verified code support for 4.04, 2.05, and 4.06. Source assertions verified that the response-selection paths are handler/application owned.

Additional concrete runtime test:

```text
test-libcoap/001-050/repro_id019_034_049_accept_handler_owned.c
test-libcoap/001-050/repro_id019_034_049_accept_handler_owned.log
```

This test creates a real UDP libcoap server and client, registers two GET resources, and sends requests with `Accept: application/json`.

- `/badfmt`: the handler explicitly observes the JSON Accept option, but knowingly returns `2.05 Content` with `Content-Format: text/plain`.
- `/goodfmt`: the handler explicitly observes the same JSON Accept option and returns `4.06 Not Acceptable`.

Observed output:

```text
client_response[1] code=2.05 content_format=0 data="plain only"
bad_handler_saw_accept_json PASS
bad_handler_response_code_not_rewritten_to_4_06 PASS got=69
bad_handler_response_is_text_plain PASS
client_response[2] code=4.06 content_format=none/0 data=""
good_handler_saw_accept_json PASS
good_handler_can_return_4_06 PASS got=134
OVERALL PASS
```

Result: when a handler knows the preferred Content-Format cannot be satisfied but still returns `2.05` with a different Content-Format, libcoap does not centrally rewrite the response to `4.06`. A compliant application handler can return `4.06`, but the library does not enforce this as a global dispatch invariant.

## Phase-2 Decision

standard_check: the RFC examples and Content-Format rule depend on resource matching and acceptable representation state.

code_check: libcoap supports the codes and default branches, but final response choice is delegated to the application/resource handler. The first entry retains stronger core support because unknown-resource handling can default to `4.04`; the second and especially the third depend more directly on handler-selected semantics. The new Accept/content negotiation runtime test confirms libcoap does not override a mismatching handler response.

test_check: runtime confirms code support; source review confirms handler-owned response selection; `repro_id019_034_049_accept_handler_owned` confirms that a handler-owned unacceptable representation remains `2.05` unless the handler itself returns `4.06`.

decision_reason: partial. The protocol mechanisms exist, but the full behavior is not a uniform core library invariant across all three entries. The first has stronger default core behavior, while the second and third rely more heavily on application/handler compliance.

## Implemented and Missing Parts

| Requirement part | libcoap behavior |
|---|---|
| Define 4.04 Not Found | Implemented |
| Define 2.05 Content | Implemented |
| Define 4.06 Not Acceptable | Implemented |
| Return 4.04 for unknown resource dispatch | Implemented; strongest core support among these three entries |
| Allow handlers to emit 2.05 | Implemented; final choice for matching resources remains handler-owned |
| Allow framework paths to emit 4.06 | Implemented; does not imply central Accept/Content-Format enforcement |
| Guarantee all multicast no-match cases resolve the same way without application context | Missing |
| Guarantee all matching resources return 2.05 | Handler-owned; weaker core guarantee than the first entry |
| Guarantee all preferred Content-Format failures are decided centrally | Missing; runtime shows a knowingly mismatching handler response is not rewritten to 4.06, making the third entry the most handler-owned of the three |
