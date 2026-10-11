# Unrecognized Error Codes Are Not Globally Normalized

## Summary 

This remains partial. libcoap defines generic 4.00 and 5.00 response codes and preserves response classes, but the reviewed receive paths do not globally rewrite every unrecognized 4.xx or 5.xx response to 4.00 or 5.00 before delivering it to application callbacks.

## Standard Requirement

Standard: RFC 7252, Section 5.9.

Original English anchors:

```text
4.00
5.00
```

Detailed interpretation: if an endpoint does not recognize a client-error or server-error response code, it should treat the code as the generic response code of that class. This is a semantic equivalence requirement; it does not necessarily require byte-level rewriting, but the endpoint behavior should be equivalent.

## Code Behavior

Relevant sources:

```text
include/coap3/coap_pdu.h
src/coap_pdu.c
src/coap_net.c
```

Generic constants and phrases exist:

```c
COAP_RESPONSE_CODE_BAD_REQUEST = COAP_RESPONSE_CODE(400)
COAP_RESPONSE_CODE_INTERNAL_ERROR = COAP_RESPONSE_CODE(500)
```

The phrase table includes known codes, and `coap_check_code_class()` validates by class. However, the reviewed receive/dispatch behavior preserves numeric response codes and routes them to callbacks. A single normalization rule that converts every unrecognized 4.xx to 4.00 and every unrecognized 5.xx to 5.00 was not found.

## Runtime Reproduction

Targeted runtime reproduction:

```text
test-libcoap/001-050/repro_id037_unrecognized_error_generic_mapping.c
test-libcoap/001-050/repro_id037_unrecognized_error_generic_mapping.exe
test-libcoap/001-050/repro_id037_unrecognized_error_generic_mapping.log
```

Build command used:

```powershell
gcc -Ilibcoap-develop/include -Ilibcoap-develop/include/coap3 -Ibuild-libcoap-151-200-lib/include -Ibuild-libcoap-151-200-lib -o test-libcoap/001-050/repro_id037_unrecognized_error_generic_mapping.exe test-libcoap/001-050/repro_id037_unrecognized_error_generic_mapping.c build-libcoap-151-200-lib/libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

Run command used:

```powershell
test-libcoap/001-050/repro_id037_unrecognized_error_generic_mapping.exe
```

This test starts a real UDP libcoap server and client on loopback and registers
two resources:

- `/unknown4`: handler returns `COAP_RESPONSE_CODE(431)` (`4.31`)
- `/unknown5`: handler returns `COAP_RESPONSE_CODE(531)` (`5.31`)

These are both within valid error classes accepted by `coap_check_code_class()`,
but they are not the generic `4.00` / `5.00` codes. If libcoap globally
normalized unrecognized error responses before delivering them to the
application callback, the client callback would observe `4.00` and `5.00`
instead of `4.31` and `5.31`.

Observed output from `repro_id037_unrecognized_error_generic_mapping.log`:

```text
send_unknown_4xx_request PASS
client_response[1] code=4.31 raw=159
recv_unknown_4xx_response PASS
send_unknown_5xx_request PASS
client_response[2] code=5.31 raw=191
recv_unknown_5xx_response PASS
unknown_4xx_delivered_as_original_4_31 PASS got=159
unknown_4xx_not_rewritten_to_generic_4_00 PASS got=0
unknown_5xx_delivered_as_original_5_31 PASS got=191
unknown_5xx_not_rewritten_to_generic_5_00 PASS got=0
OVERALL PASS
```

Interpretation of runtime evidence:

- The receive path accepts the error-class responses and delivers them to the
  client response handler.
- The response handler sees the original numeric codes `4.31` and `5.31`.
- No library-level rewrite to `4.00 Bad Request` or `5.00 Internal Server Error`
  occurred before callback delivery.

This runtime result strengthens the partial classification: the library
supports generic error constants and class checking, but the actual callback
surface preserves unrecognized error response codes rather than globally
normalizing them.

## Phase-2 Decision

standard_check: RFC 7252 requires unrecognized error response codes to be treated as generic codes of their class.

code_check: libcoap has generic constants and class handling, and the reviewed receive/dispatch path passes response PDUs through to the application callback without a visible universal `4.xx -> 4.00` or `5.xx -> 5.00` rewrite.

test_check: loopback runtime reproduction confirms a client callback receives `4.31` and `5.31` unchanged; source checks confirm class validation and phrase support but no audited global rewrite invariant.

decision_reason: partial. Equivalent handling may be possible in application code, but the core library does not enforce it globally.

## Implemented and Missing Parts

Implemented:

| Requirement part                    | libcoap behavior |
| ----------------------------------- | ---------------- |
| Define generic 4.00 and 5.00        | Implemented      |
| Preserve and validate error classes | Implemented      |

Missing or condition-dependent:

| Requirement part                                    | libcoap behavior                    |
| --------------------------------------------------- | ----------------------------------- |
| Globally normalize all unrecognized 4.xx/5.xx codes | Not found in reviewed receive paths |
