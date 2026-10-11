# ICMP Error Vetting Does Not Validate Original CoAP Datagram

## Summary 

RFC7252 recommends checking the original datagram information carried inside ICMP errors to reduce spoofing risk. libcoap recognizes some connected-socket ICMP errors and reports them as `COAP_NACK_ICMP_ISSUE`, but no reviewed path parses the ICMP-embedded original UDP/CoAP datagram and compares the CoAP message type or code.

Result: **partially satisfied**.

## Standard Requirement

CoAP standard: RFC7252, Section 11.5, "Spoofing of ICMP Messages".

Online source: [https://www.rfc-editor.org/rfc/rfc7252#section-11.5](https://www.rfc-editor.org/rfc/rfc7252#section-11.5)

Original English requirement excerpt:

```text
check the information about the original datagram
```

The same paragraph refers to port numbers and CoAP header information such as message type and code. The normative strength is `SHOULD`, so incomplete handling is best classified as partial rather than absolute failure.

## Source Code Behavior

libcoap maps connected-socket ICMP-style receive errors to a special return value:

```c
/* libcoap-develop/src/coap_dgrm_posix.c */
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

The network layer turns that return value into a nack reason:

```c
/* libcoap-develop/src/coap_net.c */
bytes_read = coap_netif_dgrm_read(session, packet);

if (bytes_read < 0) {
  if (bytes_read == -2) {
    coap_address_copy(&session->addr_info.remote, &remote);
    /* Reset the session back to startup defaults */
    coap_session_disconnected_lkd(session, COAP_NACK_ICMP_ISSUE);
  }
}
```

The reviewed code does not parse the ICMP payload to recover the original UDP ports or CoAP header fields, so it cannot perform the comparison recommended by the standard.

## Runtime And Static Check

The protocol check executable exercises adjacent parser and validation behavior and confirms that libcoap rejects malformed CoAP messages:

```text
PASS reserved class NON is rejected by code-class validation
PASS empty message with trailing data is rejected
```

For ICMP spoofing mitigation, the meaningful result is static: the implementation reports an ICMP issue but does not validate the embedded original datagram.

## Inconsistency

| Expected by RFC7252                                                        | Observed in libcoap                                                |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Implementations should vet ICMP errors against original datagram details.  | Connected-socket ICMP errors are recognized only as socket errors. |
| The original CoAP type/code should be considered when mitigating spoofing. | No reviewed code parses those CoAP fields from the ICMP payload.   |

## Decision

RFC 7252 Section 11.5 recommends that implementations check the original
datagram information carried in ICMP errors, including UDP port numbers and CoAP
header fields such as message type and code, before acting on such errors. This
is a SHOULD-level spoofing mitigation rather than a MUST-level message-processing
rule.

libcoap does recognize ICMP-derived connected-socket errors such as
ECONNREFUSED, EHOSTUNREACH, and ECONNRESET, and reports them upward as
COAP_NACK_ICMP_ISSUE. However, the reviewed paths do not parse the ICMP-quoted
original UDP/CoAP datagram and therefore cannot compare the original CoAP type,
code, or related fields before acting on the error.

Thus, libcoap partially implements ICMP error handling but does not implement
the original-datagram vetting recommended by RFC 7252. The likely impact is
application-visible send failure or session disruption from spoofed or
misattributed ICMP errors, i.e. primarily availability risk.
