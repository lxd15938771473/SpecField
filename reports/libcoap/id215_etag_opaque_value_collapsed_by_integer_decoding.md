# ETag Opaque Value Is Collapsed By Integer Decoding

## Summary

RFC 7252 defines ETag as an opaque byte string. libcoap decodes ETag bytes into `uint64_t` in several proxy and blockwise code paths, so byte-distinct values such as `01` and `00 01` can collapse to the same integer.

This is inconsistent with the RFC requirement that an endpoint receiving an ETag must treat it as opaque and make no assumptions about its content or structure.

- RFC 7252 requires ETag to be treated as opaque bytes

- libcoap still has internal paths that numerically decode ETag values
- byte-distinct ETag values can therefore be treated as equal by integer value instead of byte identity

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252), Section 5.10.6, "ETag".

Relevant original English text:

```text
An endpoint receiving an entity-tag MUST treat it as opaque and make no assumptions about its content or structure.
```

## Relevant Source Code

`libcoap-develop/src/coap_proxy.c` decodes response ETag bytes into an integer before rebuilding a forwarded response:

```c
option = coap_check_option(rcvd, COAP_OPTION_ETAG, &opt_iter);
if (option) {
  etag = coap_decode_var_bytes8(coap_opt_value(option),
                                coap_opt_length(option));
}
```

The proxy cache metadata also stores the ETag as an integer:

```c
option = coap_check_option(rcvd, COAP_OPTION_ETAG, &opt_iter);
if (option) {
  proxy_cache->etag = coap_decode_var_bytes8(coap_opt_value(option),
                                             coap_opt_length(option));
} else {
  proxy_cache->etag = 0;
}
```

Some blockwise helper paths likewise decode ETag values numerically:

```c
uint64_t etag_r = coap_decode_var_bytes8(coap_opt_value(etag_opt),
                                         coap_opt_length(etag_opt));
if (etag == etag_r) {
  pdu->code = COAP_RESPONSE_CODE(203);
  return 1;
}
```

## Runtime / Probe Result

The phase 2 probe confirmed that integer decoding is present in the relevant paths.

```text
ETag opacity probe: PASS - proxy and blockwise paths decode ETag option bytes into integers
```

An additional local repro is available here:

- `test-libcoap/201-250/repro_id215_etag_proxy_blockwise.c`

## Inconsistency Reason

Opaque comparison must preserve byte length and byte sequence. Integer decoding removes leading-zero distinctions and treats the option value as structured numeric data. That is incompatible with the RFC requirement to make no assumptions about content or structure.

## Impact

Proxy response handling, cache-related metadata handling, and blockwise helper logic can confuse different ETag values that share the same decoded integer value. This can lead to incorrect ETag matching logic and protocol-semantics errors in paths that rely on those decoded values.

Related runtime boundary:

- the separate repro `test-libcoap/201-250/repro_id233_dual_etag_runtime.c`
  confirmed that libcoap directly accepts a response containing multiple ETag
  options and exposes both to the application on the client receive side
- that same repro also showed a libcoap proxy observe-cache replay path where a
  later client request carrying `ETag: 01` was satisfied from stale cached
  content and only one ETag was exposed on the proxy path

That stale replay result does not by itself prove that the integer-collapse
behavior from this ID was the sole cause. It does, however, show that ETag
handling gaps are not limited to static RFC mismatch. In real intermediary
paths they can coincide with ETag selection/drop behavior and stale
representation reuse.
