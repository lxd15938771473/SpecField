# Confirmable Duplicate Processing for Requests Depends on Optional Response Caching

## Summary 

libcoap has some duplicate-handling support for Confirmable traffic, but for incoming duplicate Confirmable requests the effective "process only once" behavior is not a default guarantee.

The key point is:

- by default, duplicate Confirmable requests can be delivered to the application handler again
- duplicate request replay protection is materially improved only when `COAP_BLOCK_CACHE_RESPONSE` is explicitly enabled

This keeps the finding in `partial` rather than `satisfied`: libcoap has a mitigation path, but it is optional and disabled by default.

## Standard Requirement

CoAP standard: RFC 7252, Section 4.5

[https://www.rfc-editor.org/rfc/rfc7252#section-4.5](https://www.rfc-editor.org/rfc/rfc7252#section-4.5)

Relevant RFC language:

```text
SHOULD acknowledge each duplicate copy
```

```text
process any request or response in a given message only once
```

```text
within the EXCHANGE_LIFETIME
```

RFC 7252 does leave room for application semantics and idempotent handling, so this is not an unconditional MUST-style violation for every deployment. But the general expectation is that duplicate Confirmable messages should not repeatedly trigger non-idempotent processing.

## Relevant Source Code

Source file: `libcoap-develop/src/coap_net.c`

Duplicate request replay is only attempted when cached-response mode is enabled and a cached ACK response exists:

```c
if (COAP_PDU_IS_REQUEST(pdu) && session->cached_pdu &&
    (session->block_mode & COAP_BLOCK_CACHE_RESPONSE)) {
  coap_digest_t digest;

  coap_pdu_cksum(pdu, &digest);
  if (memcmp(&digest, &session->cached_pdu_cksum, sizeof(digest)) == 0) {
    coap_pdu_reference_lkd(session->cached_pdu);
    coap_log_debug("Retransmit response to duplicate request\n");
    if (coap_send_internal(session, session->cached_pdu, NULL) != COAP_INVALID_MID) {
      goto finish;
    }
  }
}
```

The cached response is only stored when `COAP_BLOCK_CACHE_RESPONSE` is set:

```c
if ((session->block_mode & COAP_BLOCK_CACHE_RESPONSE) &&
    session->cached_pdu != pdu &&
    request_pdu && COAP_PROTO_NOT_RELIABLE(session->proto) &&
    COAP_PDU_IS_REQUEST(request_pdu) &&
    COAP_PDU_IS_RESPONSE(pdu) && pdu->type == COAP_MESSAGE_ACK) {
  coap_delete_pdu_lkd(session->cached_pdu);
  session->cached_pdu = pdu;
  coap_pdu_reference_lkd(session->cached_pdu);
  coap_pdu_cksum(request_pdu, &session->cached_pdu_cksum);
}
```

Some duplicate suppression exists for recent incoming CON/ACK response handling, but this is not a general request-side EXCHANGE_LIFETIME table:

```c
if (COAP_PROTO_NOT_RELIABLE(session->proto)) {
  if (rcvd->type == COAP_MESSAGE_CON) {
    if (rcvd->mid == session->last_con_mid) {
      /* Duplicate response: send ACK/RST, but don't process */
      if (session->last_con_handler_res == COAP_RESPONSE_OK)
        coap_send_ack_lkd(session, rcvd);
      else
        coap_send_rst_lkd(session, rcvd);
      return;
    }
    session->last_con_mid = rcvd->mid;
  } else if (rcvd->type == COAP_MESSAGE_ACK) {
    if (rcvd->mid == session->last_ack_mid) {
      /* Duplicate response */
      return;
    }
    session->last_ack_mid = rcvd->mid;
  }
}
```

Default context allocation starts zeroed:

```c
c = coap_malloc_type(COAP_CONTEXT, sizeof(coap_context_t));
if (!c) {
  coap_log_emerg("coap_init: malloc: failed\n");
  return NULL;
}
memset(c, 0, sizeof(coap_context_t));
```

New sessions inherit `context->block_mode`:

```c
session->block_mode = context->block_mode;
```

That means `COAP_BLOCK_CACHE_RESPONSE` is not on unless the application explicitly enables it through `coap_context_set_block_mode()`.

## Runtime Reproduction

Repro file:

- `test-libcoap/101-150/repro_id143_duplicate_confirmable_cache.c`

The repro:

- starts a UDP libcoap server
- registers a non-idempotent `POST /counter` handler
- increments a counter every time the handler runs
- sends the exact same Confirmable POST twice
- keeps the same MID and the same Token across both sends
- runs two scenarios:
  - default configuration
  - `COAP_BLOCK_CACHE_RESPONSE` enabled

Build command:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\101-150\repro_id143_duplicate_confirmable_cache.exe D:\project\conditionFuzzing\test-libcoap\101-150\repro_id143_duplicate_confirmable_cache.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

Observed runtime output:

```text
=== default ===
enable_cache_response=0 handler_calls=2 recv_count=2
response1 len=18 type=2 code=2.04 mid=0x1234 tkl=4 payload="counter=1"
response2 len=18 type=2 code=2.04 mid=0x1234 tkl=4 payload="counter=2"
responses_identical=0
=== cache_response ===
enable_cache_response=1 handler_calls=1 recv_count=2
response1 len=18 type=2 code=2.04 mid=0x1234 tkl=4 payload="counter=1"
response2 len=18 type=2 code=2.04 mid=0x1234 tkl=4 payload="counter=1"
responses_identical=1
```

Interpretation:

- under default settings, the same duplicate Confirmable request reached the application twice
- with `COAP_BLOCK_CACHE_RESPONSE` enabled, the duplicate request was answered from cache and the handler ran only once

This runtime behavior matches the source-level reading: duplicate suppression for requests depends on optional response caching rather than being a default request-side lifetime guarantee.

## Inconsistency Reason

The implementation has useful duplicate-handling components, but the default path does not demonstrate a complete received-request duplicate table retained for `EXCHANGE_LIFETIME`.

What exists:

- optional cached ACK response replay when `COAP_BLOCK_CACHE_RESPONSE` is enabled
- recent `last_con_mid` and `last_ack_mid` checks in some response-handling paths

What is missing or conditional:

- a default, general request-side duplicate suppression mechanism keyed to peer + Message ID for the relevant lifetime

So the library can behave correctly for this scenario when optional response caching is turned on, but does not provide that as the default guarantee.

## Security Impact

The security impact is application-dependent, but real.

If an application exposes non-idempotent Confirmable operations such as:

- `POST` that creates records
- `POST` or `PUT` that increments counters, quotas, balances, or usage state
- actuator commands that trigger one-shot physical actions
- webhook-style request handlers with external side effects

then duplicate delivery under default settings can cause repeated execution of the same operation.

Potential consequences include:

- duplicated state changes
- repeated financial or quota-consuming actions
- duplicate job creation or message enqueueing
- duplicate audit/log entries that hide the true execution path
- denial-of-service amplification against expensive handlers by replaying the same valid Confirmable request

The impact is stronger when all of the following are true:

- the deployment uses unsecured UDP CoAP or otherwise permits replay by an on-path attacker or a sender that can retransmit crafted duplicates
- the application handler is non-idempotent
- the deployment relies on libcoap core behavior for duplicate suppression and does not add its own application-side deduplication

The impact is weaker when:

- handlers are idempotent
- the application independently tracks processed requests
- `COAP_BLOCK_CACHE_RESPONSE` is enabled and the traffic pattern matches the cached-response replay path

So this is best classified as a `partial` security-relevant inconsistency: not every libcoap deployment is vulnerable in practice, but the default behavior can allow duplicate non-idempotent processing.

## Recheck Result

This remains a real partial inconsistency.

It should not be overstated as "libcoap always violates RFC 7252 duplicate handling", because:

- RFC 7252 uses `SHOULD` language here
- idempotent operations and application semantics matter
- libcoap does provide an optional cached-response mitigation path

However, it is also not correct to treat the issue as purely theoretical, because the local runtime repro shows duplicate handler execution under default configuration and suppression only after explicitly enabling `COAP_BLOCK_CACHE_RESPONSE`.

## Test / Check Result

The phase2 script was run from `test-libcoap/101-150`:

```text
python worker_135_150_phase2_check.py
```

Observed result:

```text
PASS: tx_mid randomized for non-reliable sessions
PASS: new MID implementation increments session->tx_mid
PASS: outgoing duplicate guard only scans session->delayqueue
PASS: no explicit EXCHANGE_LIFETIME MID cache found
PASS: ICMP destination unreachable mapped to -2
PASS: ICMP issue mapped to COAP_NACK_ICMP_ISSUE
PASS: no ICMP original CoAP header validation code found
```

Additional runtime confirmation from `repro_id143_duplicate_confirmable_cache.exe`:

```text
default mode: duplicate CON POST invoked handler twice
cache-response mode: duplicate CON POST invoked handler once and replayed cached ACK response
```
