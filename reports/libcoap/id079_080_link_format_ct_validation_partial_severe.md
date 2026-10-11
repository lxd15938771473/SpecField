# Link-Format ct Attribute Is Untyped And Can Pollute Discovery Consumers

## Summary

RFC7252 uses the `ct` link-format attribute to advertise CoAP Content-Format
identifiers for resource discovery. In libcoap, resource attributes are stored
as arbitrary strings and emitted into `/.well-known/core` without `ct`-specific
syntax or range validation.

This was rechecked with an expanded live UDP harness that covers four questions:

1. whether extreme `ct` values make a discovery consumer crash or burn CPU/memory
2. whether naive parsing generates dangerous follow-up `Accept` values
3. whether bad discovery metadata can drive wrong content negotiation
4. whether cached discovery metadata can mislead multiple downstream clients

Result after the expanded runtime check:

- the strongest confirmed issue is **metadata/content-negotiation poisoning**
- the current local harness did **not** reproduce a libcoap crash or obvious
  resource-exhaustion DoS from large `ct` attributes alone

## Standard Requirement

CoAP standard: RFC7252, Section 7.2.1, "Resource Discovery".

Online source: [https://www.rfc-editor.org/rfc/rfc7252#section-7.2.1](https://www.rfc-editor.org/rfc/rfc7252#section-7.2.1)

Original English requirement excerpts:

```text
space-separated sequence of Content-Format codes
```

```text
MUST be in the range of 0-65535
```

The standard treats `ct` values as CoAP Content-Format identifiers, not as
arbitrary strings.

## Source Code Behavior

`coap_add_attr()` stores arbitrary attribute name/value strings. It does not
parse or range-check `ct` specially:

```c
/* libcoap-develop/src/coap_resource.c */
coap_attr_t *
coap_add_attr(coap_resource_t *resource,
              coap_str_const_t *name,
              coap_str_const_t *val,
              int flags) {
  ...
  if (attr) {
    ...
    attr->name = name;
    ...
    attr->value = val;
    ...
    LL_PREPEND(resource->link_attr, attr);
  }
  ...
}
```

`coap_print_link()` then appends each attribute name and value directly into the
generated `/.well-known/core` output:

```c
/* libcoap-develop/src/coap_resource.c */
LL_FOREACH(resource->link_attr, attr) {
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, ';', *len);
  COPY_COND_WITH_OFFSET(p, bufend, *offset,
                        attr->name->s, attr->name->length, *len);

  if (attr->value && attr->value->s) {
    PRINT_COND_WITH_OFFSET(p, bufend, *offset, '=', *len);
    COPY_COND_WITH_OFFSET(p, bufend, *offset,
                          attr->value->s, attr->value->length, *len);
  }
}
```

So if an application registers `ct=abc`, `ct=65536`, or a multi-kilobyte quoted
list, libcoap keeps that string and publishes it in discovery output.

## Runtime Reproduction

Local repro file:
[repro_id079_080_link_format_ct_validation.c](/D:/project/conditionFuzzing/test-libcoap/051-100/repro_id079_080_link_format_ct_validation.c)

Log file:
[repro_id079_080_link_format_ct_validation.log](/D:/project/conditionFuzzing/test-libcoap/051-100/repro_id079_080_link_format_ct_validation.log)

The expanded harness runs one real local UDP libcoap server and three client
sessions. It exercises:

- extreme discovery metadata
- boundary-value `ct` parsing
- content-negotiation follow-up on a real `/payload` resource
- shared discovery-cache reuse across multiple clients

## Question 1: Crash / Resource Exhaustion

The server published four large or malformed discovery attributes:

| Resource          | Registered attribute                                          |
| ----------------- | ------------------------------------------------------------- |
| `/doshugeint`   | `ct=999999999999999999999999999999999999999999999999999999` |
| `/dosmixed`     | `ct="-1 -2 -3 999999999999 abc 0"`                          |
| `/dosrepeat`    | `ct="0 0 0 0 ..."` with 2048 tokens                         |
| `/doskilobytes` | `ct="65535 65535 ..."` with 2500 tokens                     |

Observed discovery result:

```text
DOS_DISCOVERY total_len=19518 chunks=1 wall_ms=0 cpu_ms=1.00 mem_delta_kb=280 warn_logs=0 total_logs=0 log_bytes=0 complete=1
DOS_PARSE path=doshugeint raw_len=54 valid=0 invalid=1 wall_ms=0 cpu_ms=0.00
DOS_PARSE path=dosmixed raw_len=27 valid=1 invalid=5 wall_ms=0 cpu_ms=0.00
DOS_PARSE path=dosrepeat raw_len=4095 valid=2048 invalid=0 wall_ms=0 cpu_ms=0.00
DOS_PARSE path=doskilobytes raw_len=14999 valid=2500 invalid=0 wall_ms=0 cpu_ms=0.00
DOS_SANITY code=69 content_format=0 payload_len=5
```

Interpretation:

- the live libcoap discovery response grew to about 19.5 KB and still completed
  successfully
- the local naive/strict parsers handled the tested inputs without crash,
  timeout, visible CPU spike, or log explosion
- a follow-up sanity request still succeeded after the large discovery response

So for the tested sizes, this did **not** escalate into a confirmed libcoap DoS.
That does not prove no consumer can be exhausted, but the current runtime
evidence stays in the "metadata pollution / interoperability" bucket rather than
"confirmed crash/resource-exhaustion" territory.

## Question 2: Dangerous Follow-Up Accept Values

The harness then tested boundary values that a naive consumer might read from
discovery and feed directly into `Accept`:

```text
BOUNDARY path=ct65535 raw_ct=65535 strict_valid=1 strict_invalid=0 parsed=65535 accept_len=2 code=134 handler_seen=1 warn_logs=0
BOUNDARY path=ct65536 raw_ct=65536 strict_valid=0 strict_invalid=1 parsed=65536 accept_len=3 code=130 handler_seen=0 warn_logs=2
BOUNDARY path=ct2147483647 raw_ct=2147483647 strict_valid=0 strict_invalid=1 parsed=2147483647 accept_len=4 code=130 handler_seen=0 warn_logs=2
BOUNDARY path=ct4294967295 raw_ct=4294967295 strict_valid=0 strict_invalid=1 parsed=2147483647 accept_len=4 code=130 handler_seen=0 warn_logs=2
BOUNDARY path=ctnegmin raw_ct=-2147483648 strict_valid=0 strict_invalid=1 parsed=2147483648 accept_len=4 code=130 handler_seen=0 warn_logs=2
BOUNDARY path=ctuint64max raw_ct=18446744073709551615 strict_valid=0 strict_invalid=1 parsed=2147483647 accept_len=4 code=130 handler_seen=0 warn_logs=2
```

Confirmed behavior:

- `65535` is a valid 2-byte value, reaches the handler, and results in
  `4.06 Not Acceptable` because the resource only supports `text/plain`
- `65536` already becomes a 3-byte `Accept`, and libcoap rejects it before the
  handler sees it
- very large and negative strings can turn into 4-byte `Accept` values after
  naive `strtol()`-style parsing, and libcoap returns `4.02 Bad Option`

So the dangerous follow-up effect is real:

- bad discovery metadata can induce malformed follow-up requests
- some malformed values become legal-looking parser outputs before re-encoding
- libcoap then rejects those bad options at the CoAP layer

What the current harness did **not** show:

- infinite retry loops
- client crash
- automatic caching of the malformed `Accept` inside libcoap itself

## Question 3: Wrong Content Negotiation / Wrong Payload Handling

The harness exposed a real `/payload` resource that supports two formats:

- `Accept: 0` -> `text/plain`
- `Accept: 50` -> `application/json`

Then discovery advertised four variants:

- `ct="0 50"`
- `ct=abc`
- `ct=999999`
- `ct="0 abc 50"`

Observed results:

```text
CONTENT_NAIVE path=payloadgood raw_ct=0 50 parsed=0 accept_len=0 code=69 content_format=0 json_ok=0 handler_seen=1 payload=plain
CONTENT_STRICT path=payloadgood raw_ct=0 50 valid=2 invalid=0 chosen=50 saw_json=1 code=69 content_format=50 json_ok=1 handler_seen=1 payload={"msg":"json"}
CONTENT_NAIVE path=payloadalpha raw_ct=abc parsed=0 accept_len=0 code=69 content_format=0 json_ok=0 handler_seen=1 payload=plain
CONTENT_STRICT path=payloadalpha raw_ct=abc valid=0 invalid=1 chosen=none
CONTENT_NAIVE path=payloadhuge raw_ct=999999 parsed=999999 accept_len=3 code=130 content_format=-1 json_ok=0 handler_seen=0 payload=Bad Option 17
CONTENT_STRICT path=payloadhuge raw_ct=999999 valid=0 invalid=1 chosen=none
CONTENT_NAIVE path=payloadmix raw_ct=0 abc 50 parsed=0 accept_len=0 code=69 content_format=0 json_ok=0 handler_seen=1 payload=plain
CONTENT_STRICT path=payloadmix raw_ct=0 abc 50 valid=2 invalid=1 chosen=50 saw_json=1 code=69 content_format=50 json_ok=1 handler_seen=1 payload={"msg":"json"}
```

This is the strongest confirmed security-relevant result in the expanded test.

Confirmed content-negotiation pollution:

- a naive consumer looking at `ct="0 50"` chose `Accept: 0` and fetched
  `text/plain`, even though a strict consumer could choose JSON
- `ct=abc` was naively treated as `0`, again forcing `text/plain`
- `ct="0 abc 50"` caused the naive consumer to ignore the JSON capability and
  still request `text/plain`
- `ct=999999` caused an invalid 3-byte `Accept`, producing `4.02 Bad Option`

So bad discovery metadata can do more than trigger an error response. It can
cause a naive consumer to request the wrong representation and then hand the
wrong payload format to upper layers.

That is materially stronger than the earlier "just returns `4.02`" result.

## Question 4: Cross-Client Cache / Proxy-Style Metadata Propagation

The harness also modeled a minimal shared discovery cache:

- one discovery fetch populated a shared cache
- two downstream clients reused the cached metadata rather than re-fetching
- each then generated its own follow-up request from the cached `ct`

Observed output:

```text
CACHE_CLIENT client=B discovery_fetches=1 path=payloadalpha cached_ct=abc accept=0 code=69 content_format=0 json_ok=0 handler_seen=1
CACHE_CLIENT client=C discovery_fetches=1 path=payloadmix cached_ct=0 abc 50 accept=0 code=69 content_format=0 json_ok=0 handler_seen=1
```

This confirms a real propagation pattern:

- one discovery response can poison a shared metadata cache
- multiple downstream clients can then reuse that poisoned metadata
- all affected clients can be driven toward the wrong `Accept` and wrong
  representation choice

This is not proof that libcoap's built-in proxy/cache automatically stores and
replays these `ct` values as metadata objects. The current result is more
carefully stated:

- **confirmed:** a shared discovery cache layer can propagate the poisoned
  metadata across clients
- **not yet confirmed here:** automatic poisoning inside libcoap core proxy
  machinery itself

So the right label is currently **discovery-cache / metadata poisoning** rather
than a stronger claim about a built-in libcoap cache implementation.

## Inconsistency

| Expected by RFC7252                                    | Observed in libcoap                                                                                                                       |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `ct` advertises Content-Format identifiers.          | `ct` is stored and emitted as an untyped string attribute.                                                                              |
| Each `ct` value must be decimal and in `0..65535`. | Arbitrary strings, out-of-range numbers, negative values, and multi-kilobyte quoted lists are accepted and published in discovery output. |

## Security Impact

The expanded runtime check supports a more specific security conclusion.

Confirmed:

- attacker-controlled resource metadata can be exposed verbatim through
  `/.well-known/core`
- a naive discovery consumer can turn that metadata into malformed or
  misleading `Accept` values
- bad metadata can force a consumer to request the wrong representation
- a shared discovery cache can propagate the bad metadata to multiple clients

So the best current impact statement is:

- **confirmed:** metadata poisoning / discovery cache poisoning /
  content-negotiation pollution
- **possible but not confirmed here:** consumer-side DoS if another client or
  proxy implementation parses these values less safely than the local harness
