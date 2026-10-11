# 2.03 Valid Cache Semantics Are Partially Implemented

## Summary 

These two entries cover the same RFC 7252 cache-validation issue and are reported together.

Final judgment: confirmed partial, with runtime evidence. libcoap implements the protocol mechanism for ETag validation: it can return `2.03 Valid` when a request nominates a matching stored representation by ETag, and it returns a normal non-`2.03` response when the representation has changed. However, libcoap does not automatically manage the client's stored-response cache state. Reusing a stored response after `2.03`, or marking nominated stored responses unsuitable after a non-`2.03` response, remains application/cache-owned.

## Standard Requirement

Standard: RFC 7252, Section 5.9.1.3.

Original English requirement excerpts:

```text
A 2.03 (Valid) response indicates the stored response identified by the entity-tag given in the response's ETag Option can be reused.
```

```text
Any other Response Code indicates that none of the stored responses nominated in the request is suitable.
```

Interpretation:

| Entry | Condition                                          | Required semantic effect                      |
| ----- | -------------------------------------------------- | --------------------------------------------- |
| 12    | A `2.03 Valid` response is received with an ETag | The nominated stored response can be reused   |
| 35    | The validation response code is not `2.03 Valid` | The nominated stored responses are unsuitable |

These requirements are about cache state, not just response-code constants.

## Code Evidence

Relevant sources:

```text
include/coap3/coap_pdu.h
src/coap_pdu.c
include/coap3/coap_cache.h
src/coap_cache.c
src/coap_block.c
src/coap_net.c
```

Implemented protocol pieces:

```c
COAP_RESPONSE_CODE_VALID = COAP_RESPONSE_CODE(203)
{ COAP_RESPONSE_CODE(203), "Valid" }
```

`src/coap_block.c` implements the ETag match path inside `coap_add_data_large_response()` / `coap_add_data_large_internal()` when libcoap block handling is enabled:

```c
if (etag == etag_r) {
  pdu->code = COAP_RESPONSE_CODE(203);
  return 1;
}
```

`include/coap3/coap_cache.h` and `src/coap_cache.c` expose cache entries and app data APIs:

```c
coap_new_cache_entry(...)
coap_cache_get_by_pdu(...)
coap_cache_set_app_data2(...)
coap_cache_get_app_data(...)
coap_delete_cache_entry(...)
```

But the cache API stores application-owned data. Generic client response dispatch in `src/coap_net.c` delivers the received PDU to the registered response handler and sends ACK/RST as needed; it does not centrally rewrite, reuse, or invalidate arbitrary application cache entries.

## Runtime Reproduction

Dedicated repro:

```text
test-libcoap/001-050/repro_id012_035_valid_cache_semantics.c
test-libcoap/001-050/repro_id012_035_valid_cache_semantics.log
```

Compile command used:

```text
gcc -Ibuild-libcoap-151-200-lib -Ibuild-libcoap-151-200-lib/include -Ilibcoap-develop/include -o test-libcoap/001-050/repro_id012_035_valid_cache_semantics.exe test-libcoap/001-050/repro_id012_035_valid_cache_semantics.c build-libcoap-151-200-lib/libcoap-3.a -lws2_32 -liphlpapi -lpthread
```

Test design:

1. Start a local libcoap UDP server and client.
2. Enable `COAP_BLOCK_USE_LIBCOAP` on the server so `coap_add_data_large_response()` exercises its ETag/`2.03` helper path.
3. First request receives `2.05 Content`, `ETag=0x11`, and payload `generation-0`.
4. Client creates a libcoap cache entry and stores application data `generation-0`.
5. Second request nominates the stored response by sending `ETag=0x11`.
6. Server returns `2.03 Valid`, `ETag=0x11`, and no payload.
7. The test verifies the client cache app data was not automatically rewritten by libcoap.
8. Server changes the representation to `generation-1` with `ETag=0x22`.
9. Third request still sends old `ETag=0x11`.
10. Server returns non-`2.03`: `2.05 Content`, `ETag=0x22`, and payload `generation-1`.
11. The test verifies the old client cache app data was not automatically invalidated by libcoap.

Key runtime results:

```text
client_response[1] code=2.05 etag=17 data_len=12 data="generation-0"
response_1_etag PASS got=17

client_response[2] code=2.03 etag=17 data_len=0 data=""
response_2_code_valid PASS got=67
response_2_no_payload PASS got=0
client_cache_not_auto_rewritten_on_2_03 PASS

client_response[3] code=2.05 etag=34 data_len=12 data="generation-1"
response_3_new_etag PASS got=34
client_cache_not_auto_invalidated_on_non_2_03 PASS

OVERALL PASS
```

## Decision

standard_check: RFC 7252 defines both positive validation reuse on `2.03 Valid` and negative unsuitability on any other response code for nominated stored responses.

code_check: libcoap implements the ETag/`2.03 Valid` response mechanism and exposes cache APIs, but the cache entry app data is application-owned and generic client response processing does not automatically reuse or invalidate stored responses.

test_check: The dedicated runtime repro confirms both sides: the `2.03 Valid` mechanism works, while client-side stored-response reuse/invalidation is not automatic.

decision_reason: partial. This is not a full unsatisfied case because libcoap correctly implements the protocol-level `2.03`/ETag helper behavior. It is also not fully satisfied as an end-to-end cache semantics implementation because the stored-response state transitions required by RFC 7252 are left to the application or cache layer using libcoap.

## Implemented and Application-Owned Parts

| Requirement part                                                     | libcoap behavior                        | Evidence                                                               |
| -------------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------- |
| Define `2.03 Valid`                                                | Implemented                             | Response constant and phrase exist                                     |
| Emit `2.03 Valid` when request ETag matches current representation | Implemented                             | Runtime response 2 returned `code=2.03 etag=17 data_len=0`           |
| Return non-`2.03` when nominated ETag no longer matches            | Implemented at response mechanism level | Runtime response 3 returned `2.05`, new `ETag=34`, and new payload |
| Reuse stored response after `2.03 Valid`                           | Application/cache-owned                 | Runtime cache app data was not auto-rewritten/replayed                 |
| Mark nominated stored responses unsuitable after non-`2.03`        | Application/cache-owned                 | Runtime cache app data was not auto-invalidated                        |
