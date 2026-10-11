# Accept-Based Content Negotiation Is Application Specific

## Summary 

RFC7252 defines `Accept` as the client's preferred response content format. In libcoap, the core validates the wire format of the `Accept` option and delivers it to the resource handler, but it does not implement a generic representation-selection policy. Whether the server returns `4.06 Not Acceptable` or still emits some other response is determined by the application handler.

Result: **partially satisfied**.

## Standard Requirement

CoAP standard: RFC7252, Section 5.10.4, "Accept".

Online source: [https://www.rfc-editor.org/rfc/rfc7252#section-5.10.4](https://www.rfc-editor.org/rfc/rfc7252#section-5.10.4)

Original English requirement excerpts:

```text
preferred content-format
```

```text
returns the preferred Content-Format if available
```

These clauses describe client preference signaling and server-side representation selection behavior.

## Source Code Behavior

The parser enforces the `Accept` option length restriction:

```c
/* libcoap-develop/src/coap_pdu.c */
case COAP_OPTION_ACCEPT:
  if (len > 2)
    res = 0;
  break;
```

The receive path recognizes `Accept` as a known critical option:

```c
/* libcoap-develop/src/coap_net.c */
case COAP_OPTION_ACCEPT:
  break;
```

Request dispatch then hands the parsed request to the registered resource handler:

```c
/* libcoap-develop/src/coap_net.c */
if (resource == &resource_uri_wellknown) {
  h(resource, session, pdu, query, response);
} else {
  ...
  h(resource, session, pdu, query, response);
}
```

This means libcoap core validates and exposes `Accept`, but the actual negotiation decision is handler-owned.

## Runtime Reproduction

Local repro file: [repro_id069_070_content_negotiation.c](/D:/project/conditionFuzzing/test-libcoap/051-100/repro_id069_070_content_negotiation.c)

The repro uses one local UDP libcoap context with two resources:

- `/good`: checks `Accept` and explicitly returns `4.06 Not Acceptable` when the requested format is unsupported.
- `/bad`: ignores `Accept` and always returns `2.05 Content` with `Content-Format: text/plain`.

Tested items:

| Test item        | Purpose                                                                                          | Expected result                                                             | Actual result                                                             |
| ---------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| malformed Accept | Show that libcoap core performs protocol-format validation.                                      | An invalid `Accept` length is rejected.                                   | Passed: the parser rejects the malformed option directly.                 |
| good handler     | Show that an application handler can use libcoap to return a compliant `4.06`.                 | The client receives `4.06 Not Acceptable`.                                | Passed: the client received `4.06`.                                     |
| bad handler      | Show that libcoap core does not automatically rewrite an application-defined incorrect response. | The client still receives the handler-defined `2.05 text/plain` response. | Passed: the client received `2.05` with `Content-Format: text/plain`. |

Observed output:

```text
PASS allocate malformed Accept parser pdu
PASS malformed Accept length > 2 is rejected
PASS good handler returns 4.06 for unsupported Accept
PASS bad handler response code stays 2.05
PASS bad handler text/plain Content-Format is preserved
PASS bad handler payload is delivered unchanged
```

## Interpretation

The runtime result cleanly separates core behavior from application behavior:

- libcoap core does enforce protocol-level `Accept` syntax validation.
- A well-behaved application handler can use libcoap APIs to return RFC-consistent `4.06 Not Acceptable`.
- libcoap core does not automatically override a handler that ignores `Accept` and emits `2.05 text/plain` anyway.

So IDs 69 and 70 are best classified as partial: wire-format handling is implemented by libcoap core, but representation negotiation policy is not globally enforced by the core library.

## Decision

The implementation is partially compliant. libcoap correctly parses and validates the `Accept` option and allows an application to return a compliant `4.06` response, but it does not impose a generic content-negotiation policy on resource handlers. Final negotiation semantics remain application-specific.
