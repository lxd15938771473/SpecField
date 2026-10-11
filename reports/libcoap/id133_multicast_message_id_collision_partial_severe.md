# Multicast Sends Do Not Show a Cross-Session Active Message ID Collision Check

## Summary

libcoap generates Message IDs by randomizing a per-session counter and incrementing it for each new UDP or DTLS message. That local strategy does not implement the multicast-specific rule from RFC 7252.

The source review suggested that multicast sends do not scan active unicast exchanges before choosing a Message ID. A dynamic reproduction now confirms the issue: the client can send a multicast NON request with the same MID as an active unicast CON exchange to a server that is also a possible multicast recipient, and the server's RST to the multicast request is then matched to the active unicast exchange.

## Standard Requirement

CoAP standard: RFC 7252, Section 8.2, online text:

<https://www.rfc-editor.org/rfc/rfc7252#section-8.2>

This multicast requirement depends on several related RFC 7252 rules, not just one sentence in Section 8.2:

- Section 4.4 defines Message ID matching for CON/NON exchanges. ACK and RST are correlated using the Message ID and endpoint tuple, so reusing a still-active MID with the same reachable endpoint space can misbind control messages.
- Section 4.4 also requires that the same Message ID not be reused with the same endpoint within the active lifetime window.
- Section 4.8.2 defines the lifetime windows behind that rule. With the default RFC parameters, `EXCHANGE_LIFETIME` is 247 seconds and `NON_LIFETIME` is 145 seconds. The RFC also allows implementations to conservatively retain Message IDs for the larger `EXCHANGE_LIFETIME`.
- Section 8.1 requires multicast requests to be NON. It also says that a server aware that a request arrived through multicast must not send a Reset in reply, but a server that is not aware can still send a Reset using normal CoAP processing.
- Section 8.2 adds the sender-side multicast rule that follows from the above: because such a Reset can be indistinguishable from one for a unicast exchange, the sender must avoid using a Message ID that is still active with any unicast endpoint that might receive the multicast message.

Relevant original English excerpts:

```text
MUST avoid using a Message ID
```

```text
still active from this endpoint
```

```text
any unicast endpoint that might receive
```

Additional RFC 7252 requirements directly relevant to this case:

```text
The same Message ID MUST NOT be reused
```

```text
need to make sure these do not overlap
```

```text
MUST NOT return a Reset message
```

Default RFC 7252 timing values relevant to active-MID lifetime:

- `NON_LIFETIME = 145 s`
- `EXCHANGE_LIFETIME = 247 s`

This matters because a server that is not aware that a request arrived via multicast may send a Reset that is indistinguishable from a Reset for a unicast exchange, and CoAP matching then relies on the MID and endpoint tuple rather than on any explicit multicast marker in the Reset itself.

## Relevant Source Code

Source file: `libcoap-develop/src/coap_session.c`

Session creation randomizes the outgoing Message ID counter for unreliable transports:

```c
/* Randomly initialize */
/* TCP/TLS have no notion of mid */
if (COAP_PROTO_NOT_RELIABLE(session->proto))
  coap_prng_lkd((unsigned char *)&session->tx_mid, sizeof(session->tx_mid));
coap_prng_lkd((unsigned char *)&session->tx_rtag, sizeof(session->tx_rtag));
```

New Message IDs are then allocated by incrementing the session counter:

```c
uint16_t
coap_new_message_id_lkd(coap_session_t *session) {
  coap_lock_check_locked();
  if (COAP_PROTO_NOT_RELIABLE(session->proto))
    return ++session->tx_mid;
  /* TCP/TLS have no notion of mid */
  return 0;
}
```

Source file: `libcoap-develop/src/coap_net.c`

The multicast request path adjusts block handling, but this code does not check active unicast Message IDs:

```c
session->block_mode |= COAP_BLOCK_SINGLE_BODY;
if (coap_is_mcast(&session->addr_info.remote))
  block_mode = session->block_mode;

session->doing_send_recv = 1;
/* So the user needs to delete the PDU */
coap_pdu_reference_lkd(request_pdu);
mid = coap_send_lkd(session, request_pdu);
```

Delayed multicast responses store the response Message ID, but this is response delay handling, not a sender-side cross-session collision check for multicast requests:

```c
node->id = response->mid;
node->pdu = response;
node->is_mcast = 1;
coap_prng_lkd(&r, sizeof(r));
delay = (COAP_DEFAULT_LEISURE_TICKS(session) * r) / 256;
```

## Inconsistency Reason

The implementation has a good local Message ID generator, but the RFC multicast rule is not just "generate a changing Message ID". It requires avoiding overlap with Message IDs still active with any unicast endpoint that might receive the multicast message.

The reviewed code did not show a data structure or loop that checks active unicast exchanges before sending a multicast message. The generator is per session, so two sessions can have independent counters. Random initialization reduces probability of collision, but it does not enforce the multicast rule.

## Recheck Result

This is now dynamically confirmed.

The implemented part is still only per-session randomized and incrementing Message ID allocation. The missing part is the multicast-specific active unicast collision check required by RFC 7252 Section 8.2, and the runtime behavior shows that the missing check is externally observable.

## Test / Check Result

The phase2 static check was run from `test-libcoap/101-150`:

```text
python worker_118_134_static_check.py
```

Observed result:

```text
PASS empty_udp_header_only
PASS ack_rst_echo_mid_empty_code
PASS option_length_ranges
PASS message_id_generation_and_retransmit
PASS retransmit_reuses_queued_pdu
PASS gnutls_rpk_key_usage_not_only_digital_signature
PASS tinydtls_sha256_rpk_note
```

This validates the local Message ID generation and retransmission evidence. Static review alone did not prove runtime collision behavior, so a dedicated dynamic reproduction was added.

## Dynamic Reproduction

Reproduction source:

`test-libcoap/101-150/repro_id133_multicast_message_id_collision.c`

This harness performs the following sequence:

1. Create one UDP client session bound to a fixed local source port and send a unicast CON request to server A.
2. Keep server A from acknowledging that CON, so the exchange remains active from the client's perspective.
3. Reuse the same client socket and force the next multicast NON request to use the same MID as the active unicast request.
4. Make server A a member of the multicast group, observe that it receives the multicast request with the colliding MID, and send back a raw CoAP RST with that MID.
5. Check whether libcoap reports the RST as applying to the active unicast CON exchange.

Build command used:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\101-150\repro_id133_multicast_message_id_collision.exe D:\project\conditionFuzzing\test-libcoap\101-150\repro_id133_multicast_message_id_collision.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

Execution command used:

```text
D:\project\conditionFuzzing\test-libcoap\101-150\repro_id133_multicast_message_id_collision.exe
```

Observed output:

```text
step1_active_unicast_mid=0x8137 serverA_unicast_mid=0x8137 con_active_before_rst=0
step2_multicast_sent_mid=0x8137 serverA_multicast_mid=0x8137 same_src_port=yes recv_count=2
step3_nack_seen=1 nack_reason=2 nack_mid=0x8137 nack_for_con=1 con_active_after_rst=0 response_seen=0
ID133_CONFIRMED: multicast MID collided with active unicast MID and RST was matched to the active unicast CON exchange
May 06 17:48:12.346  1 ALRT got RST for mid=0x8137
```

Interpretation:

- The active unicast request used MID `0x8137`, and server A observed that same MID on the wire.
- The later multicast NON request was also sent with MID `0x8137`, and server A received that multicast request with the same MID.
- The source port was the same client port for both sends, so the server's RST to the multicast request was indistinguishable from an RST for the unicast exchange at the CoAP MID level.
- libcoap raised `COAP_NACK_RST` for MID `0x8137`, and the harness observed that the matched transmitted PDU was the active unicast CON request.

This directly demonstrates the RFC 7252 Section 8.2 violation: the client emitted a multicast request whose MID was still active with a unicast endpoint that could receive the multicast packet, and the resulting RST was misassociated with the active unicast exchange.

## Security Impact

This issue has a real security impact because it breaks the integrity of CoAP request/response correlation across unicast and multicast traffic. A multicast NON request can be sent with a MID that is still active for a unicast exchange, and the resulting RST can then be consumed as if it belonged to the unrelated unicast transaction.

At minimum, this is an availability problem. A legitimate multicast recipient, or any actor able to trigger or spoof the relevant RST on-path or on-link, can cause the client to tear down or fail an in-flight unicast exchange. In the dynamic reproduction above, the RST generated in response to the multicast request was matched to the active unicast CON exchange, which is exactly the failure mode RFC 7252 Section 8.2 is designed to prevent.

The issue is more serious in UDP/NoSec-style deployments. RFC 7252 security considerations already note that spoofed Reset traffic can make an endpoint effectively "deaf". If the implementation also allows multicast/unicast active-MID collisions, the protocol itself creates a collision window that reduces the attacker's work: the attacker no longer depends only on guessing an active MID, because a multicast-triggered RST can be made to line up with a live unicast exchange.

Practical consequences include:

- premature cancellation or failure of legitimate unicast requests;
- loss of reliability for CON exchanges because retransmission state is cleared for the wrong transaction;
- intermittent discovery or group-communication failures when one server participates in both multicast and unicast traffic;
- a denial-of-service primitive against CoAP clients on shared or constrained networks where multicast requests are common.
