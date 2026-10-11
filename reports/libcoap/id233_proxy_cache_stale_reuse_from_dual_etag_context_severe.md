# Proxy Observe-Cache Replayed Stale Content From A Dual-ETag Context

## Summary

The tested libcoap proxy observe-cache path replayed stale content after the
origin had already changed.

In the local repro, later clients still received old `/policy` and `/config`
data, their request `ETag` values were not forwarded to the origin, and the
downstream proxy path exposed only one ETag from a dual-ETag context.

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252), especially:

- Section 5.7.1, forwarding and cache correctness context for proxies
- Section 5.7.2, cache-generated response behavior
- Section 5.10.6, ETag representation identity semantics

Relevant standard expectations for this repro are:

- a proxy-generated or cache-generated response should reflect valid cached
  representation state rather than replaying superseded origin data
- downstream validation behavior should not silently ignore client-side request
  ETag context when a fresher origin representation exists
- ETag handling should preserve representation identity semantics rather than
  collapsing the response metadata seen by downstream clients

## Repro File

- `test-libcoap/201-250/repro_id233_dual_etag_runtime.c`
- `test-libcoap/201-250/repro_id233_proxy_cache_security_matrix.c`

Build command:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\201-250\repro_id233_dual_etag_runtime.exe D:\project\conditionFuzzing\test-libcoap\201-250\repro_id233_dual_etag_runtime.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

## Runtime Setup

The repro builds a three-party chain:

1. an origin server exposes observable `GET /watch`
2. the first origin version returns `OBSERVE version=1`
3. a libcoap reverse proxy in the middle uses its observe response cache path
4. client 1 establishes the cached observe entry through the proxy
5. the origin is then switched to `OBSERVE version=2`
6. client 2 issues a follow-up observe request through the same proxy carrying
   request `ETag: 01`
7. a direct control request goes to the origin to show what the current fresh
   representation looks like after the version switch

The important question is whether the proxy:

- recontacts the origin for the second client
- forwards the second client's request `ETag`
- replays cached stale content
- preserves or collapses the response ETag set seen downstream

## Security-Focused Follow-Up Repro

The stronger local repro
`test-libcoap/201-250/repro_id233_proxy_cache_security_matrix.c` extends the
same proxy observe-cache idea into two security-meaningful resources and one
validation-forwarding matrix.

Build command:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\201-250\repro_id233_proxy_cache_security_matrix.exe D:\project\conditionFuzzing\test-libcoap\201-250\repro_id233_proxy_cache_security_matrix.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

### 1. Policy Resource

The origin resource is changed to `/policy`:

- version 1 returns `allow=true; role=admin`
- version 2 returns `allow=false; role=revoked`

The client workflow is:

1. client 1 primes proxy cache with version 1
2. origin switches to version 2
3. client 2 requests `/policy` through the proxy under three conditions:
   no request ETag, `ETag: 01`, and different `ETag: 02`
4. if the returned policy still says `allow=true`, the client performs a
   follow-up protected operation

### 2. Config / Manifest-Style Resource

The origin resource is changed to `/config`:

- version 1 returns `mode=debug; update_url=http://old`
- version 2 returns `mode=safe; update_url=https://new`

The client primes cache with version 1, origin switches to version 2, and a
later client then fetches `/config` through the proxy. If the stale cached
response still points to `http://old`, the client uses that old update source
for the next step.

### 3. Validation Forwarding Matrix

The policy repro also records whether the origin sees later request ETags
across a small matrix:

- no request ETag
- same request `ETag: 01`
- different request `ETag: 02`

That lets the repro distinguish "ordinary cache hit" from "proxy-side
validation bypass even when the client supplied request-side validation
context".

## Observed Runtime Output

```text
proxy_case client1_code=69 client1_payload=OBSERVE version=1 client1_observe=1 client1_etag_count=1 client1_etags=01 client2_code=69 client2_payload=OBSERVE version=1 client2_observe=1 client2_etag_count=1 client2_etags=01 origin_hits_after_client1=1 origin_hits_after_client2=1 origin_req_etag_after_client2=0 direct_control_code=69 direct_control_payload=OBSERVE version=2 direct_control_etag_count=0 direct_control_etags= client2_served_from_cache=1 stale_content_reuse=1 origin_hits_after_control=2 origin_req_etag_after_control=1
```

Observed runtime output from the stronger security-focused repro:

```text
policy_prime payload=allow=true; role=admin etag_count=1 etags=01 direct_control_payload=allow=false; role=revoked direct_control_etag_count=0
policy_matrix case=no_etag payload=allow=true; role=admin etag_count=1 etags=01 origin_hits_before=2 origin_hits_after=2 origin_req_etag_before=1 origin_req_etag_after=1 origin_last_req_etag_count=1 origin_last_req_etags=01 served_from_cache=1 stale_payload=1
policy_matrix case=same_etag_01 payload=allow=true; role=admin etag_count=1 etags=01 origin_hits_before=2 origin_hits_after=2 origin_req_etag_before=1 origin_req_etag_after=1 origin_last_req_etag_count=1 origin_last_req_etags=01 served_from_cache=1 stale_payload=1
policy_matrix case=diff_etag_02 payload=allow=true; role=admin etag_count=1 etags=01 origin_hits_before=2 origin_hits_after=2 origin_req_etag_before=1 origin_req_etag_after=1 origin_last_req_etag_count=1 origin_last_req_etags=01 served_from_cache=1 stale_payload=1
policy_followup sent=1 admin_action_hits=1 policy_version_at_action=2 basis=allow=true; role=admin
config_prime payload=mode=debug; update_url=http://old etag_count=1 etags=11 stale_payload=mode=debug; update_url=http://old stale_etag_count=1 stale_etags=11 direct_control_payload=mode=safe; update_url=https://new served_from_cache=1 stale_payload_reused=1 followup_sent=1 config_apply_hits=1 config_version_at_apply=2 selected_update_url=http://old
```

## Interpretation

- client 1 received `OBSERVE version=1` through the proxy
- client 2 also received `OBSERVE version=1`
- `origin_hits_after_client1=1` and `origin_hits_after_client2=1`, so client 2
  was served from proxy cache rather than causing a new origin fetch
- `origin_req_etag_after_client2=0`, so client 2's request `ETag: 01` did not
  reach the origin
- the direct control request then returned `OBSERVE version=2`, proving the
  origin had newer content at that time
- both proxy-served clients only saw one downstream response ETag (`01`)

This means the tested proxy/cache path exhibited:

- stale content reuse
- request-ETag non-forwarding on the cached replay path
- effective downstream ETag selection/drop behavior

The stronger follow-up repro refines that into three more specific findings.

### Policy / Authorization Meaning

- after the origin had already moved to `allow=false; role=revoked`, later
  proxy-served requests still received `allow=true; role=admin`
- the follow-up protected action was actually sent and processed
- `policy_version_at_action=2` together with
  `basis=allow=true; role=admin` shows stale authorization/policy reuse rather
  than merely stale text

### Config / Update Metadata Meaning

- after the origin had already moved to
  `mode=safe; update_url=https://new`, the proxy-served client still received
  `mode=debug; update_url=http://old`
- the follow-up step used `selected_update_url=http://old`
- `config_version_at_apply=2` confirms the update/config decision was made from
  stale metadata after the origin had changed

### Validation Forwarding Matrix Meaning

- for `no_etag`, `same_etag_01`, and `diff_etag_02`, the policy matrix kept
  `origin_hits_before=2` and `origin_hits_after=2`
- the origin-side ETag request count also did not increase across those cases
- `origin_last_req_etags=01` remained from the earlier direct-control request,
  which means the later proxy-served matrix requests did not reach the origin

That makes the behavior stronger than a generic cache hit. In this local path,
the proxy replayed stale policy regardless of whether the later client supplied
no ETag, the same ETag, or a different ETag.

## Security Impact

This repro upgrades the issue from protocol noncompliance to concrete
security-relevant stale-state reuse.

- **stale authorization reuse:** the origin had already moved from
  `allow=true; role=admin` to `allow=false; role=revoked`, but the proxy-served
  client still acted on the stale admin policy and triggered a protected
  follow-up operation
- **stale configuration / update metadata reuse:** the origin had already moved
  from `mode=debug; update_url=http://old` to
  `mode=safe; update_url=https://new`, but the proxy-served client still chose
  the old update source
- **validation bypass signal:** the no-ETag / same-ETag / different-ETag matrix
  all replayed from cache without increasing origin hits, which means later
  requests were not just answered with old data, but were answered without a
  fresh origin check in the tested path

The most important consequence is not merely that content was stale. It is that
security decisions and follow-up actions were made from stale proxy-replayed
state after the origin had already revoked or replaced that state.

## Boundary Of What This Repro Proves

Confirmed here:

- a later client can receive cached stale content after the origin has changed
- the later client's request `ETag` was not forwarded to the origin in this
  cached replay path
- the downstream proxy path exposed only one ETag
- stale authorization/policy reuse can drive a follow-up protected action after
  the origin has already revoked that policy
- stale config/update metadata can drive a follow-up selection of an old update
  source after the origin has already changed to a new safe value
- the no-ETag / same-ETag / different-ETag matrix still replayed from cache in
  the tested path

Not confirmed here:

- an incorrect `2.03 Valid`
- a proof that integer-decoding alone was the sole root cause
- a proof that every libcoap proxy mode behaves this way outside the tested
  observe-cache replay path

## Relationship To The ETag Document

The companion document
`test-libcoap/201-250/id217_227_228_233_option_context_validation_gaps.md`
covers the direct runtime fact that libcoap accepts a response containing two
ETag options and exposes both to the application on the client receive side.

This file focuses only on the downstream proxy/cache consequence: stale replay
and effective ETag collapse/drop behavior in the tested intermediary path.
