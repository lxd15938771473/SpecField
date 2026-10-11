# ICMP Original Datagram Validation Is Missing Before Connected Clients Act on ICMP Errors

## Summary

libcoap has two different UDP ICMP handling behaviors:

- on unconnected server-side sockets, common ICMP-derived receive errors are ignored
- on connected client-side sockets, the same class of error is surfaced as `COAP_NACK_ICMP_ISSUE`

The connected-client path is the problem. The reviewed code shows that libcoap
acts on the ICMP-derived socket error, but the review did not find visible
validation of the ICMP-quoted original datagram before failing the request.

In particular, the reviewed path does not show checks for:

- quoted original UDP source and destination ports
- quoted CoAP type and code
- quoted CoAP Message ID
- quoted CoAP token

That is a real partial inconsistency with RFC 7252 Section 4.2. CoAP does not
have to trust ICMP, but if it does act on ICMP, it should first check the
quoted original datagram. Otherwise, the safer fallback is to ignore the ICMP
error.

## Standard Requirement

CoAP standard: RFC 7252, Section 4.2.

Online source:

<https://www.rfc-editor.org/rfc/rfc7252#section-4.2>

Relevant original English excerpts:

```text
check the information about the original datagram
```

```text
including port numbers and CoAP header information
```

```text
ICMP errors SHOULD be ignored
```

The requirement is conditional. An implementation may ignore ICMP errors. But
if it chooses to use ICMP to fail a CoAP exchange, RFC 7252 says it should vet
the quoted original datagram information first.

## Relevant Source Code

Source file: `libcoap-develop/src/coap_dgrm_posix.c`

Connected UDP sockets convert common ICMP-derived receive errors into `-2`:

```c
len = recv(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0);
if (len < 0) {
#ifdef _WIN32
  coap_win_error_to_errno();
#endif /* _WIN32 */
  if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ECONNRESET) {
    /* client-side ICMP destination unreachable, ignore it */
    coap_log_warn("** %s: coap_socket_recv: ICMP: %s\n",
                  sock->session ?
                  coap_session_str(sock->session) : "",
                  coap_socket_strerror());
    return -2;
  }
```

Unconnected server-side sockets ignore the same error class and return `0`:

```c
if (len < 0) {
#ifdef _WIN32
  coap_win_error_to_errno();
#endif /* _WIN32 */
  if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ECONNRESET) {
    /* server-side ICMP destination unreachable, ignore it. The destination address is in msg_name. */
    coap_log_warn("** %s: coap_socket_recv: ICMP: %s\n",
                  sock->session ?
                  coap_session_str(sock->session) : "",
                  coap_socket_strerror());
    return 0;
  }
```

Source file: `libcoap-develop/src/coap_net.c`

The connected-client `-2` path is translated into a session-level ICMP NACK:

```c
bytes_read = coap_netif_dgrm_read(session, packet);

if (bytes_read < 0) {
  if (bytes_read == -2) {
    coap_address_copy(&session->addr_info.remote, &remote);
    /* Reset the session back to startup defaults */
    coap_session_disconnected_lkd(session, COAP_NACK_ICMP_ISSUE);
  }
}
```

Source file: `libcoap-develop/src/coap_session.c`

`COAP_NACK_ICMP_ISSUE` is surfaced to the application and returned early:

```c
if (reason == COAP_NACK_ICMP_ISSUE) {
  coap_log_debug("***%s: session ICMP issue (%s)\n",
                 coap_session_str(session), coap_nack_name(reason));
  return;
}
```

The same disconnect path selects a queued request on the session, but the
reviewed code does not show ICMP-quote-based request matching:

```c
q = session->context->sendqueue;
while (q) {
  if (q->session == session) {
    /* Take the first one */
    coap_handle_nack(session, q->pdu, reason, q->id);
    sent_nack = 1;
    break;
  }
  q = q->next;
}
```

Across these paths, the review did not find code that parses the ICMP quote and
verifies quoted port numbers or quoted CoAP header fields before raising the
NACK.

## Confirmed Runtime Behavior

The positive-control runtime test on WSL2 confirmed that a real connected UDP
client to a closed UDP port enters the libcoap ICMP NACK path immediately.

Observed output:

```text
May 06 19:55:49.492  1 WARN ** 127.0.0.1:56912 <-> 127.0.0.1:56911 UDP : coap_socket_recv: ICMP: Connection refused
May 06 19:55:49.492  1 DEBG ***127.0.0.1:56912 <-> 127.0.0.1:56911 UDP : session ICMP issue (COAP_NACK_ICMP_ISSUE)
CLOSED_PORT_RESULT response_seen=0 nack_seen=1 reason=4 request_mid=0x3d2e nack_mid=0x3d2e
```

This confirms two important points:

- real kernel-delivered ICMP can reach the connected-client libcoap path
- the result is application-visible `COAP_NACK_ICMP_ISSUE`, not ordinary CoAP retransmission timeout handling

A lower-level UDP probe in the `netns + veth` topology also confirmed the same
positive-control behavior at the socket layer:

```text
NETNS_UDP_CLOSED_PORT send_ok=1 recv_rc=-1 recv_errno=111
```

So this finding is not just theoretical source review. A real ICMP
closed-port condition does produce the faster failure path that libcoap exposes
to the application.

## Inconsistency Reason

The inconsistency is not that libcoap recognizes ICMP at all. The problem is
that the connected-client path acts on ICMP, while the reviewed code does not
show the RFC-described validation step before doing so.

The reviewed implementation therefore shows two different policies:

- server-side unconnected path: ignore ICMP-derived receive errors
- client-side connected path: convert the same class of condition into `COAP_NACK_ICMP_ISSUE`

For the second policy, the review did not find visible:

- parsing of the ICMP-quoted original UDP header
- validation of quoted source and destination UDP ports
- validation of quoted CoAP type, code, Message ID, or token
- request selection based on quoted original-datagram contents

If the implementation cannot perform that vetting through the UDP error API,
RFC 7252 points to the safer fallback of ignoring the ICMP error.

## Security Impact

This gap has real security relevance even without assuming forged-packet
exploitability.

- A real ICMP closed-port condition can fail a request much faster than normal
  CoAP retransmission timeout handling.
- The reviewed code shows session-level NACK attribution based on the send
  queue, not on visible matching of quoted original-datagram contents.
- As a result, the implementation takes an externally induced network error and
  turns it into an application-visible request failure without visible RFC-style
  original-datagram vetting in the reviewed path.

## Claim Boundary

This document intentionally stays within what is confirmed by source review and
positive-control runtime evidence.

Confirmed:

- connected UDP client sessions can surface real ICMP-derived failure as
  `COAP_NACK_ICMP_ISSUE`
- this is a faster failure path than ordinary CoAP timeout/retransmission
- the reviewed code does not show original-datagram validation before raising
  the NACK

Not claimed here:

- forged ICMP exploitability in a specific live deployment
- cross-request failure caused by a demonstrated forged quote
- guaranteed downstream proxy behavior for every deployment

Those are stronger runtime claims and are not needed to establish this
documented partial inconsistency.

## Recheck Result

This remains a real partial inconsistency.

libcoap already has a defined ICMP handling policy, but the connected-client
branch surfaces ICMP failure without visible RFC 7252 Section 4.2 original-
datagram vetting in the reviewed code path.

## Test / Check Result

The phase 2 check confirmed the relevant source-level behavior:

```text
PASS: ICMP destination unreachable mapped to -2
PASS: ICMP issue mapped to COAP_NACK_ICMP_ISSUE
PASS: no ICMP original CoAP header validation code found
```

The runtime positive control confirmed the path is live in practice:

```text
CLOSED_PORT_RESULT response_seen=0 nack_seen=1 reason=4 request_mid=0x3d2e nack_mid=0x3d2e
```
