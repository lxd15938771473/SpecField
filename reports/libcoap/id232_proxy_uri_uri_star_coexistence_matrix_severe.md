# Proxy-Uri And Uri-* Coexistence Matrix

## Summary  

libcoap does not reject requests that contain `Proxy-Uri` together with
`Uri-*` options. At runtime, `Uri-Host` and `Uri-Port` are dropped, but
`Uri-Path` and `Uri-Query` are retained and pollute the forwarded upstream
request.

## Covered Test Groups

This report covers:

- test group 1: `Proxy-Uri + Uri-Path/Uri-Query` coexistence
- test group 4: detailed `Proxy-Uri + Uri-Host/Uri-Port/Uri-Path/Uri-Query`
  comparison

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252),
Section 5.10.2.

Relevant original English text:

```text
The Proxy-Uri Option MUST take precedence over any of the Uri-Host, Uri-Port, Uri-Path or Uri-Query options (each of which MUST NOT be included in a request containing the Proxy-Uri Option).
```

## Relevant Source Code

`libcoap-develop/src/coap_proxy.c` splits `Proxy-Uri`, but does not reject
the request merely because `Uri-*` options coexist with it.

```c
case COAP_OPTION_PROXY_URI:
  if (coap_split_proxy_uri(coap_opt_value(option),
                           coap_opt_length(option),
                           &uri) < 0) {
    coap_log_warn("Proxy URI not decodable\n");
    coap_delete_pdu_lkd(pdu);
    return 0;
  }
  if (!coap_uri_into_optlist(&uri, NULL, &optlist, 0)) {
    coap_log_err("Failed to create options for URI\n");
    goto failed;
  }
  break;
```

Only `Uri-Host` and `Uri-Port` are explicitly dropped. Other `Uri-*` options
fall through the default copy path.

```c
case COAP_OPTION_URI_HOST:
case COAP_OPTION_URI_PORT:
  break;
default:
  coap_insert_optlist(&optlist,
                      coap_new_optlist(opt_iter.number,
                                       coap_opt_length(option),
                                       coap_opt_value(option)));
  break;
```

## Runtime Repro

Repro files:

- `test-libcoap/201-250/repro_id223_232_234_235_237_proxy_runtime.c`
- `test-libcoap/201-250/repro_id223_232_234_235_237_proxy_runtime.exe`

Build command:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\201-250\repro_id223_232_234_235_237_proxy_runtime.exe D:\project\conditionFuzzing\test-libcoap\201-250\repro_id223_232_234_235_237_proxy_runtime.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

## Observed Runtime Output

```text
CASE1_proxy_uri_plus_path_query client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=1 protected-hit proxy_policy_checked=0 proxy_policy_allowed=0 proxy_seen_proxy_uri=<absent> proxy_audit_logged=0 proxy_audit_logged_uri=<absent> origin_hits=1 origin_path=b/a origin_query=x=1 origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/b/a?x=1 origin_protected_hit=1 origin_protected_action=0 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=<unchanged> config_after=<unchanged> client_nack=0
CASE4_proxy_uri_plus_uri_host client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=4 proxy_policy_checked=0 proxy_policy_allowed=0 proxy_seen_proxy_uri=<absent> proxy_audit_logged=0 proxy_audit_logged_uri=<absent> origin_hits=1 origin_path=a origin_query=<absent> origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/a origin_protected_hit=0 origin_protected_action=0 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=<unchanged> config_after=<unchanged> client_nack=0
CASE4_proxy_uri_plus_uri_port client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=5 proxy_policy_checked=0 proxy_policy_allowed=0 proxy_seen_proxy_uri=<absent> proxy_audit_logged=0 proxy_audit_logged_uri=<absent> origin_hits=1 origin_path=a origin_query=<absent> origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/a origin_protected_hit=0 origin_protected_action=0 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=<unchanged> config_after=<unchanged> client_nack=0
CASE4_proxy_uri_plus_uri_path client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=6 protected-hit proxy_policy_checked=0 proxy_policy_allowed=0 proxy_seen_proxy_uri=<absent> proxy_audit_logged=0 proxy_audit_logged_uri=<absent> origin_hits=1 origin_path=b/a origin_query=<absent> origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/b/a origin_protected_hit=1 origin_protected_action=0 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=<unchanged> config_after=<unchanged> client_nack=0
CASE4_proxy_uri_plus_uri_query client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=7 proxy_policy_checked=0 proxy_policy_allowed=0 proxy_seen_proxy_uri=<absent> proxy_audit_logged=0 proxy_audit_logged_uri=<absent> origin_hits=1 origin_path=a origin_query=x=1 origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/a?x=1 origin_protected_hit=0 origin_protected_action=0 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=<unchanged> config_after=<unchanged> client_nack=0
CASE5_proxy_uri_policy_bypass client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=8 protected-hit proxy_policy_checked=1 proxy_policy_allowed=1 proxy_seen_proxy_uri=coap://127.0.0.1:56991/a proxy_audit_logged=1 proxy_audit_logged_uri=coap://127.0.0.1:56991/a origin_hits=1 origin_path=b/a origin_query=x=1 origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/b/a?x=1 origin_protected_hit=1 origin_protected_action=0 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=<unchanged> config_after=<unchanged> client_nack=0
CASE7_proxy_uri_protected_side_effect client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=10 config=debug proxy_policy_checked=1 proxy_policy_allowed=1 proxy_seen_proxy_uri=coap://127.0.0.1:56991/a proxy_audit_logged=1 proxy_audit_logged_uri=coap://127.0.0.1:56991/a origin_hits=1 origin_path=b/a origin_query=x=1 origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/b/a?x=1 origin_protected_hit=1 origin_protected_action=1 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=safe config_after=debug client_nack=0
CASE8_proxy_uri_audit_mismatch client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=11 config=debug proxy_policy_checked=1 proxy_policy_allowed=1 proxy_seen_proxy_uri=coap://127.0.0.1:56991/a proxy_audit_logged=1 proxy_audit_logged_uri=coap://127.0.0.1:56991/a origin_hits=1 origin_path=b/a origin_query=x=1 origin_uri_host=<absent> origin_uri_port=<absent> origin_effective_uri=/b/a?x=1 origin_protected_hit=1 origin_protected_action=1 origin_req_unknown_unsafe=0 origin_req_unknown_unsafe_value=0 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 config_before=safe config_after=debug client_nack=0
```

## Interpretation

### 1. Proxy-Uri + Uri-Path / Uri-Query

The client sent `Proxy-Uri: coap://127.0.0.1:56991/a` together with extra
`Uri-Path: b` and `Uri-Query: x=1`.

Observed result:

- the proxy did not reject the request
- the client received `2.05`
- the origin was hit
- the origin saw `path=b/a`
- the origin saw `query=x=1`

This shows concrete target-URI pollution. The extra `Uri-Path` and `Uri-Query`
were not discarded. They were merged into the forwarded upstream request.

### Additional policy-bypass probe

The harness also simulates a proxy-side prefilter that checks only
`Proxy-Uri` and allows `coap://127.0.0.1:56991/a`, while intending to block
`/b/a`, protected handlers, and query parameter `x=1`.

Observed result:

- `proxy_policy_checked=1`
- `proxy_policy_allowed=1`
- `proxy_seen_proxy_uri=coap://127.0.0.1:56991/a`
- `proxy_audit_logged=1`
- `proxy_audit_logged_uri=coap://127.0.0.1:56991/a`
- the origin still received `path=b/a`
- the origin still received `query=x=1`
- `origin_effective_uri=/b/a?x=1`
- `origin_protected_hit=1`

So the policy layer saw only the clean `Proxy-Uri` and allowed the request,
while the actual forwarded upstream request hit the protected `b/a` handler
with the forbidden query parameter. This upgrades URI pollution into a concrete
policy-bypass demonstration.

### Additional protected-side-effect probe

The harness also upgrades the protected handler into a state-changing sensitive
interface. In this probe, `/b/a?x=1` changes a config state from `safe` to
`debug`.

Observed result:

- `proxy_policy_allowed=1`
- `origin_protected_hit=1`
- `origin_protected_action=1`
- `origin_effective_uri=/b/a?x=1`
- `config_before=safe`
- `config_after=debug`

This shows that the issue is not limited to unexpected path reachability. The
polluted effective URI reached a sensitive handler and caused a concrete,
unexpected state modification.

### Additional policy / audit mismatch probe

The harness also records what the proxy policy layer checked and what the proxy
audit layer logged, while the origin records the real effective URI it
executed.

Observed result:

- `proxy_policy_allowed=1`
- `proxy_seen_proxy_uri=coap://127.0.0.1:56991/a`
- `proxy_audit_logged_uri=coap://127.0.0.1:56991/a`
- `origin_effective_uri=/b/a?x=1`
- `origin_protected_hit=1`
- `origin_protected_action=1`
- `config_before=safe`
- `config_after=debug`

So the security decision object and the logged audit object were both `/a`,
while the real execution object was `/b/a?x=1`. This demonstrates not only
policy bypass but also audit misdirection: operators reviewing proxy-side logs
would see a benign allowed URI, while the origin actually executed a different
protected action target.

### 4. Detailed Uri-* coexistence matrix

Observed result:

- `Proxy-Uri + Uri-Host`: origin saw `path=a`; extra `Uri-Host` was absent
- `Proxy-Uri + Uri-Port`: origin saw `path=a`; extra `Uri-Port` was absent
- `Proxy-Uri + Uri-Path`: origin saw `path=b/a`; extra `Uri-Path` polluted forwarding
- `Proxy-Uri + Uri-Query`: origin saw `path=a` and `query=x=1`; extra `Uri-Query` polluted forwarding

This exactly matches the reviewed switch in `coap_proxy.c`: `Uri-Host` and
`Uri-Port` are explicitly dropped, while `Uri-Path` and `Uri-Query` are kept.

## Inconsistency Reason

libcoap recognizes `Proxy-Uri` and rewrites it into split upstream options, but
it does not enforce the RFC rule that forbids any co-present `Uri-*` options.
The implementation only strips `Uri-Host` and `Uri-Port`; the remaining
`Uri-*` options continue through the default copy path.

## Impact

An intermediary can forward requests with invalid `Proxy-Uri + Uri-*`
combinations, and the actual upstream target can be polluted by extra
`Uri-Path` or `Uri-Query` values. If a deployment enforces path or query policy
based only on `Proxy-Uri`, that pollution can become a proxy-side policy
bypass. If the polluted target resolves to a sensitive handler, the effect can
escalate into unintended state changes. And if the proxy's audit layer records
only the original `Proxy-Uri`, the resulting logs can be actively misleading
about what request target was really executed upstream.
