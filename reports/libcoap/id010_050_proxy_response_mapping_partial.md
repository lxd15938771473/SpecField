# Proxy Response Mapping Is Path Dependent

## Summary

These two entries are both about proxy response-code selection being path dependent rather than enforced by one universal rule. One concerns 5.04 Gateway Timeout; the other concerns 5.02 Bad Gateway when a proxy cannot process a destination response.

## Standard Requirement

Standard: RFC 7252 proxy/server-error response rules.

Original English requirement excerpts:

```text
5.04 Gateway Timeout
```

```text
If the request to the destination returns a response that cannot be processed by the proxy (e.g, due to unrecognized critical options or message format errors), then a 5.02 (Bad Gateway) response MUST be returned.
```

Interpretation: both items are proxy response-mapping problems. The audit question is whether libcoap applies the required proxy response code generically, or only on selected code paths.

## Code Behavior

Relevant sources:

```text
include/coap3/coap_pdu.h
src/coap_pdu.c
src/coap_proxy.c
src/coap_net.c
```

5.04 is defined and phrase-mapped:

```c
COAP_RESPONSE_CODE_GATEWAY_TIMEOUT = COAP_RESPONSE_CODE(504)
{ COAP_RESPONSE_CODE(504), "Gateway Timeout" }
```

5.02 is also defined and used in proxy failure paths:

```c
COAP_RESPONSE_CODE_BAD_GATEWAY = COAP_RESPONSE_CODE(502)
{ COAP_RESPONSE_CODE(502), "Bad Gateway" }
```

Representative proxy-path behavior:

```c
if (info_list == NULL) {
  response->code = COAP_RESPONSE_CODE(502);
  coap_proxy_remove_association(session, 0);
  return NULL;
}
```

and:

```c
/* Need to send back a gateway failure */
response = coap_pdu_init(proxy_req->pdu->type,
                         COAP_RESPONSE_CODE(502), ...);
```

The review did not find one generic proxy rule that automatically maps every timeout condition to 5.04 or every unprocessable downstream response to 5.02 independent of path/callback context.

## Runtime Reproduction

Targeted runtime reproduction:

```text
test-libcoap/001-050/repro_id010_050_proxy_response_mapping.c
test-libcoap/001-050/repro_id010_050_proxy_response_mapping.exe
test-libcoap/001-050/repro_id010_050_proxy_response_mapping.log
```

Build command used:

```powershell
gcc -Ilibcoap-develop/include -Ilibcoap-develop/include/coap3 -Ibuild-libcoap-151-200-lib/include -Ibuild-libcoap-151-200-lib -o test-libcoap/001-050/repro_id010_050_proxy_response_mapping.exe test-libcoap/001-050/repro_id010_050_proxy_response_mapping.c build-libcoap-151-200-lib/libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

Run command used:

```powershell
test-libcoap/001-050/repro_id010_050_proxy_response_mapping.exe
```

This test exercises two separate proxy behaviors:

1. Reverse-proxy forwarding with an unresolvable upstream host.
   Expected question: does libcoap map this failure to 5.02 in actual proxy handling?
   Observed result: yes.
2. Idle-timeout handling on an existing proxy entry with an outstanding request.
   Expected question: does the timeout path emit 5.04 back to the client?
   Observed result: no. The proxy entry is removed by `coap_proxy_check_timeouts()`,
   but no 5.04 response is produced.

Test design details:

- The 5.02 scenario starts a minimal libcoap reverse proxy and a real libcoap
  client. The reverse proxy is configured with upstream host
  `nonexistent.invalid`, forcing `coap_resolve_address_info()` to return no
  destination and exercising the actual proxy failure path that sets
  `response->code = COAP_RESPONSE_CODE(502)`.
- The timeout scenario constructs an existing proxy entry with an outstanding
  request and calls `coap_proxy_check_timeouts()` under libcoap's internal
  lock. This directly exercises the idle-timeout cleanup path, which removes
  the association through `coap_proxy_remove_association(..., 0)` and does not
  emit a client-visible response.

Observed output from `repro_id010_050_proxy_response_mapping.log`:

```text
SCENARIO bad_gateway_unresolvable_upstream
server_context_created PASS
client_context_created PASS
client_session_created PASS
proxy_request_sent PASS
reverse_proxy_handler forward failed response_code=162
client_received_error_response PASS
unresolvable_upstream_maps_to_5_02 PASS got=162

SCENARIO timeout_without_5_04_mapping
timeout_server_context_created PASS
timeout_incoming_session_created PASS
timeout_ongoing_session_created PASS
timeout_proxy_list_allocated PASS
timeout_proxy_req_allocated PASS
timeout_request_pdu_allocated PASS
timeout_request_token_added PASS
proxy_entry_created_for_timeout_case PASS got=1
timeout_check_reports_no_future_expiry_after_deadline PASS
proxy_entry_removed_after_timeout PASS got=0
no_client_response_after_timeout_cleanup PASS got=0
no_5_04_emitted_after_timeout_cleanup PASS got=0

OVERALL PASS
```

Interpretation of runtime evidence:

- 5.02 is not just defined as a constant; it is actually returned on one real
  proxy failure path (`getaddrinfo` / upstream resolution failure).
- The idle-timeout path does not implement an automatic 5.04 mapping. Instead,
  the proxy association is silently cleaned up from the client-observable
  perspective in this reproduction.

## Phase-2 Decision

standard_check: RFC 7252 defines 5.04 for gateway timeout and 5.02 for unprocessable destination responses.

code_check: libcoap defines both 5.02 and 5.04, and reviewed proxy paths show explicit 5.02 failure handling while timeout cleanup uses `coap_proxy_remove_association(..., 0)` without a 5.04 response path.

test_check: runtime now confirms one actual 5.02 proxy mapping case and one timeout cleanup case with no emitted 5.04 response.

decision_reason: partial, leaning inconsistent for the combined claim. 5.02 is implemented on specific failure paths, but 5.04 is not enforced as a generic proxy-timeout response in the reproduced timeout path.

## Implemented and Missing Parts

| Requirement part                                                              | libcoap behavior                                |
| ----------------------------------------------------------------------------- | ----------------------------------------------- |
| Define 5.04 Gateway Timeout                                                   | Implemented                                     |
| Define 5.02 Bad Gateway                                                       | Implemented                                     |
| Emit 5.04 on a universal proxy timeout rule                                   | Contradicted by reproduced timeout cleanup path |
| Emit 5.02 for every unprocessable destination response via one universal rule | Only shown for specific failure paths           |
