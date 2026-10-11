# Proxy Timeout Is Not Converted To Gateway Timeout

## Summary 

RFC7252 requires a proxy timeout to be reported with CoAP response code `5.04 (Gateway Timeout)`. libcoap defines this response code, but the reviewed proxy forwarding path does not convert upstream send failure, timeout, or negative acknowledgement events into a `5.04` response. The example proxy negative-acknowledgement handler also ignores the relevant nack reasons.

Result: **not satisfied**.

## Standard Requirement

CoAP standard: RFC7252, Section 5.10.2, "Proxying"; Section 5.9.3.5, "5.04 Gateway Timeout".

Online source: [https://www.rfc-editor.org/rfc/rfc7252#section-5.10.2](https://www.rfc-editor.org/rfc/rfc7252#section-5.10.2)

Original English requirement excerpt:

```text
5.04 (Gateway Timeout) response MUST be returned
```

This requirement is about proxy response generation when the proxy cannot obtain a timely response from the destination endpoint.

## Source Code Behavior

The response code exists in libcoap:

```c
/* libcoap-develop/include/coap3/coap_pdu.h */
COAP_RESPONSE_CODE_GATEWAY_TIMEOUT = COAP_RESPONSE_CODE(504),
```

However, the proxy forwarding failure path returns `5.00`, not `5.04`:

```c
/* libcoap-develop/src/coap_proxy.c */
coap_proxy_log_entry(proxy_req->incoming, proxy_req->pdu, proxy_req->token_used,  "fwd");
if (coap_send_lkd(proxy_entry->ongoing, pdu) == COAP_INVALID_MID) {
  pdu = NULL;
  coap_log_debug("proxy: upstream PDU send error\n");
  goto failed;
}

failed:
  response->code = COAP_RESPONSE_CODE(500);
  coap_delete_pdu_lkd(pdu);
  return 0;
```

The example proxy nack handler receives timeout and delivery failure signals, but does not translate them into a response:

```c
/* libcoap-develop/examples/coap-server.c */
switch (reason) {
case COAP_NACK_TOO_MANY_RETRIES:
case COAP_NACK_NOT_DELIVERABLE:
case COAP_NACK_RST:
case COAP_NACK_TLS_FAILED:
case COAP_NACK_WS_FAILED:
case COAP_NACK_TLS_LAYER_FAILED:
case COAP_NACK_WS_LAYER_FAILED:
case COAP_NACK_ICMP_ISSUE:
case COAP_NACK_BAD_RESPONSE:
default:
  break;
}
return;
```

## Runtime And Static Check

The local protocol check confirmed that libcoap exposes the required response code constant:

```text
PASS 5.04 constant is defined
```

I then ran the existing proxy response mapping repro harness, which exercises two relevant runtime paths:

```text
SCENARIO bad_gateway_unresolvable_upstream
reverse_proxy_handler forward failed response_code=162
client_received_error_response PASS
unresolvable_upstream_maps_to_5_02 PASS got=162
SCENARIO timeout_without_5_04_mapping
proxy_entry_removed_after_timeout PASS got=0
no_client_response_after_timeout_cleanup PASS got=0
no_5_04_emitted_after_timeout_cleanup PASS got=0
OVERALL PASS
```

Here `162` is `COAP_RESPONSE_CODE(502)`, so the tested proxy error path returned `5.02 Bad Gateway`, not `5.04 Gateway Timeout`. In the timeout cleanup scenario, the proxy association expired and was removed, but no client response was emitted at all, which again means no `5.04` mapping was produced.

Static review is still relevant for the exact source locations: the reviewed `coap_proxy.c` send-failure path sets `5.00`, and the example proxy nack handler ignores timeout-related nack reasons instead of converting them into a timeout response.

## Inconsistency

| Expected by RFC7252                                                                                         | Observed in libcoap                                                  |
| ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| A proxy destination timeout is reported as `5.04 Gateway Timeout`.                                        | The reviewed proxy failure path sets `5.00 Internal Server Error`. |
| Nack reasons such as too many retries or not deliverable should be usable to generate the timeout response. | The shipped example proxy nack handler ignores these events.         |

## Decision

The implementation contains the `5.04` constant but does not apply it in the reviewed proxy timeout/failure behavior. This is a real protocol mismatch for libcoap's CoAP proxy behavior.
