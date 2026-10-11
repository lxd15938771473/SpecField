# Proxy Cache Replays Responses Without Reducing Max-Age

## Summary 

RFC 7252 requires a proxy-generated cached response to reduce Max-Age by the time the representation spent in cache. libcoap records cache expiration time, but when it returns a cached response it reuses the cached PDU and sends it through the response handler without recomputing Max-Age.

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252), Section 5.7.1 and 5.7.2 proxy/cache freshness behavior.

Relevant original English text:

```text
proxy-max-age = original-max-age - cache-age
```

```text
If a response is generated out of a cache, the generated (or implied) Max-Age Option MUST NOT extend the max-age originally set by the server, considering the time the resource representation spent in the cache.
```

## Relevant Source Code

`libcoap-develop/src/coap_proxy.c` records expiration using the received Max-Age or the default 60 seconds.

```c
option = coap_check_option(rcvd, COAP_OPTION_MAXAGE, &opt_iter);
if (option) {
  expire = coap_decode_var_bytes(coap_opt_value(option),
                                 coap_opt_length(option));
} else {
  /* Default is 60 seconds */
  expire = 60;
}
proxy_cache->expire = now + expire * COAP_TICKS_PER_SECOND;
```

When using the cache, the code calls the response handler with the cached PDU. There is no Max-Age rewrite in this cached replay block.

```c
return_cached_info:
  if (obs_opt && !proxy_req->doing_observe) {
    int observe_action;

    observe_action = coap_decode_var_bytes(coap_opt_value(obs_opt),
                                           coap_opt_length(obs_opt));
```

```c
coap_proxy_log_entry(session, request, &proxy_cache->rsp_pdu->actual_token,  "rspc");
coap_proxy_call_response_handler(session, request, proxy_cache->rsp_pdu,
                                 &r_token, proxy_req, 1, obs_opt ? 0 : 1);
```

## Runtime / Probe Result

Dynamic runtime testing confirmed the inconsistency, but with an important scope note: in the current libcoap proxy implementation, the cache replay path is exercised on the Observe proxy path, not by two ordinary GETs. A direct `origin -> libcoap proxy -> client` experiment with two plain GET requests showed that both requests were forwarded upstream and the origin was hit twice, so that setup does not validate cache replay.

To hit the actual cached replay branch, the runtime test used:

1. a custom origin server on `127.0.0.1:5684` returning `2.05 Content`, `Max-Age=5`, payload `v1`, and logging each hit;
2. `libcoap` example proxy on `127.0.0.1:5685` in forward proxy mode;
3. `client1` sending an Observe GET through the proxy and staying connected;
4. a wait of about 3 seconds;
5. `client2` sending the same Observe GET through the same proxy.

At the moment `client2` received its first response:

- `client2` received `2.05 Content`, payload `v1`, and `Max-Age=5`;
- the proxy log reported `Using Proxy Cache` and `proxy rspc`, proving the response came from the proxy cache replay path;
- the origin log still showed only one hit, proving no second upstream fetch had happened yet.

Observed outputs:

```text
CLIENT_RESULT code=2.05 max_age=5 payload=v1
```

```text
ORIGIN_LISTEN 127.0.0.1 5684
ORIGIN_HIT 1
```

```text
Using Proxy Cache (Active 2)
proxy rspc ... "cachetest" Observe
v:1 t:CON c:2.05 ... [ ... Max-Age:5 ] :: 'v1'
```

This is inconsistent with the RFC freshness rule. After roughly 3 seconds in cache, the proxy-generated response should have advertised about 2 seconds of remaining freshness rather than replaying the original `Max-Age=5`.

## Inconsistency Reason

The implementation tracks whether an entry is fresh enough for reuse, but the RFC also requires the response sent from cache to advertise only the remaining freshness. Replaying the cached PDU with its original Max-Age can make downstream clients or caches believe the representation is fresher than the origin server allowed.

## Impact

This can extend cache freshness across proxy hops and cause stale representations to be reused beyond the origin server's intended lifetime.
