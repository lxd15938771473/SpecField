# Payload Legality Is Not Enforced By The Core PDU API

## Summary

libcoap's low-level PDU API can add and expose payload bytes without checking whether the Method or Response Code is defined to carry a payload. Endpoint handlers can still behave correctly, so this is a conditional inconsistency rather than proof every libcoap application violates RFC 7252.

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252), Section 5.5, "Payloads and Representations".

Relevant original English text:

```text
If a Method or Response Code is not defined to have a payload, then a sender MUST NOT include one, and a recipient MUST ignore it.
```

## Relevant Source Code

`libcoap-develop/src/coap_pdu.c` adds payload data without checking `pdu->code`.

```c
int
coap_add_data(coap_pdu_t *pdu, size_t len, const uint8_t *data) {
  if (len == 0) {
    return 1;
  } else {
    uint8_t *payload = coap_add_data_after(pdu, len);
    if (payload != NULL)
      memcpy(payload, data, len);
    return payload != NULL;
  }
}
```

The receive-side getter exposes payload data generically, again without checking whether the code is allowed to have payload.

```c
int
coap_get_data(const coap_pdu_t *pdu, size_t *len, const uint8_t **data) {
  size_t offset;
  size_t total;

  return coap_get_data_large(pdu, len, data, &offset, &total);
}
```

```c
*data = pdu->data;
if (pdu->data == NULL) {
  *len = 0;
  *total = 0;
  return 0;
}
```

## Runtime / Probe Result

The phase 2 probe confirmed that payload add/get behavior is code-agnostic.

```text
Payload legality probe: PASS - payload add/get path is code-agnostic
```

An additional end-to-end repro is available here:

- `test-libcoap/201-250/repro_id244_245_payload_runtime.c`
- `test-libcoap/201-250/repro_id244_245_payload_runtime.exe`

This repro performs two concrete runtime tests around `2.03 Valid`, which RFC
7252 defines as a response that MUST include `ETag` and MUST NOT include a
payload.

### Build Command

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\201-250\repro_id244_245_payload_runtime.exe D:\project\conditionFuzzing\test-libcoap\201-250\repro_id244_245_payload_runtime.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

### Observed Runtime Output

```text
CASE1_wire_invalid_203 response_seen=1 code=2.03 etag_present=1 etag=0x42 payload_marker=1 payload_len=16 payload=ILLEGAL-203-BODY
CASE2_client_accepts_invalid_203 request_seen=1 response_seen=1 code=2.03 etag_present=1 etag=0x42 coap_get_data=1 payload_len=13 payload=FORGED-UPDATE safe_cached_body=cached-clean-body naive_cached_body=FORGED-UPDATE naive_misused_payload=1
```

### Interpretation By Test

#### 1. Send-side: libcoap server emits wire-level payload on `2.03 Valid`

The repro starts a libcoap server handler that explicitly constructs:

- response code `2.03 Valid`
- `ETag: 0x42`
- payload `"ILLEGAL-203-BODY"` added with `coap_add_data()`

A raw UDP probe client then reads the actual datagram bytes on the wire.

Observed result:

- `code=2.03`
- `etag_present=1`
- `payload_marker=1`
- `payload_len=16`
- `payload=ILLEGAL-203-BODY`

This is concrete wire-level proof that libcoap will serialize and send a
payload-bearing `2.03 Valid` response if an application builds one through the
core PDU API. The library does not stop `coap_add_data()` from producing an
RFC-invalid response body for this code.

#### 2. Receive-side: libcoap client exposes payload from invalid `2.03 Valid`

The repro then starts a libcoap client and a deliberately malicious libcoap
server. The server returns:

- response code `2.03 Valid`
- `ETag: 0x42`
- payload `"FORGED-UPDATE"`

The client response handler calls `coap_get_data()` and records both a safe
and a naive application behavior.

Observed result:

- `code=2.03`
- `coap_get_data=1`
- `payload_len=13`
- `payload=FORGED-UPDATE`
- `safe_cached_body=cached-clean-body`
- `naive_cached_body=FORGED-UPDATE`
- `naive_misused_payload=1`

So the libcoap client does not automatically suppress or ignore the illegal
payload. `coap_get_data()` exposes it to the application as ordinary payload
bytes.

The safe control path keeps the previously cached body unchanged and ignores
the payload, which is the RFC-correct application behavior for this invalid
message. The naive control path instead treats the exposed payload as fresh
representation data and overwrites its cached body with `FORGED-UPDATE`. That
shows the practical consequence of the API design: once the invalid payload is
surfaced, an application that does not add its own code-aware check can use it
incorrectly.

## Inconsistency Reason

RFC 7252 places a sender and recipient requirement on payload legality. libcoap's core PDU API is lower-level than an endpoint policy engine and does not enforce this check. As a result, applications can construct invalid no-payload-code messages, and received invalid payloads are exposed unless the application ignores them.

## Impact

The runtime repro shows both sides concretely:

- a libcoap endpoint can emit an RFC-invalid `2.03 Valid` response with a
  real wire-level payload
- a libcoap client will expose that payload through `coap_get_data()`
- a naive client can then treat the forged payload as valid representation
  data and overwrite previously cached state

Correct handlers can still avoid the issue by checking response-code semantics
themselves, but the core API does not prevent invalid output or automatically
hide invalid input payloads.
