# ID 357: ICMP Original Datagram Type/Code Vetting Is Only Partially Implemented

## Summary

RFC 7252 recommends that when an implementation reacts to ICMP errors, it should validate the quoted original datagram, including CoAP message type, code, Message ID, and Token, before acting on that ICMP indication.

libcoap currently does not implement that validation path. It converts socket-level ICMP-related errors into `COAP_NACK_ICMP_ISSUE`, but no reviewed path was found that parses the ICMP-embedded original CoAP message and checks whether the quoted `type/code/MID/Token` actually match the outstanding exchange.

Therefore, this item is best classified as `partially_satisfied`: libcoap has ICMP issue reporting, but it does not implement the RFC 7252 anti-spoofing validation that this requirement expects.

## Standard Requirement

### RFC Source

RFC 7252, Section 4.2, gives the following recommendation for ICMP handling:

> "implementations SHOULD take care to check the information about the original datagram in the ICMP message, including port numbers and CoAP header information such as message type and code, Message ID, and Token"

This sentence is the core requirement relevant to ID 357. The point is not merely to notice that an ICMP error happened, but to confirm that the ICMP error really belongs to the in-flight CoAP exchange before changing session state or reporting a delivery failure.

### What the Standard Means Here

For this item, the standard expectation is:

- If ICMP is used as an input to delivery failure handling, the implementation should inspect the quoted original datagram inside the ICMP payload.
- That inspection should include CoAP header fields, especially:
  - message `Type`
  - message `Code`
  - `Message ID`
  - `Token`
- The implementation should only act on the ICMP error when those fields are consistent with an outstanding request or exchange.

The purpose of this check is to reduce spoofing risk. Without it, an attacker who can inject or influence ICMP errors may be able to cause a live exchange to fail even when the quoted original datagram does not actually match the real in-flight CoAP request.

## Code Evidence

### Observed libcoap Behavior

The relevant receive/error path is split across `src/coap_dgrm_posix.c` and `src/coap_net.c`.

In [coap_dgrm_posix.c](D:/project/conditionFuzzing/libcoap-develop/src/coap_dgrm_posix.c:728), libcoap treats specific socket errors as ICMP-related delivery problems:

```c
if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ECONNRESET) {
  coap_log_warn("** %s: coap_socket_recv: ICMP: %s\n", ...);
  return -2;
}
```

Code description:

- This path does not parse an ICMP packet body.
- It only observes an `errno`-level socket failure such as `ECONNREFUSED`, `EHOSTUNREACH`, or `ECONNRESET`.
- Once one of these errors occurs, the function returns `-2` as a generic "ICMP issue" signal.

That result is then consumed in [coap_net.c](D:/project/conditionFuzzing/libcoap-develop/src/coap_net.c:2598):

```c
if (bytes_read < 0) {
  if (bytes_read == -2) {
    coap_address_copy(&session->addr_info.remote, &remote);
    coap_session_disconnected_lkd(session, COAP_NACK_ICMP_ISSUE);
  }
}
```

Code description:

- A datagram read result of `-2` is treated as an ICMP-related delivery failure.
- libcoap immediately converts that condition into `COAP_NACK_ICMP_ISSUE`.
- There is no validation step here that checks a quoted CoAP header from the original datagram before acting.

### Missing Validation Logic

No reviewed path was found that does the following before issuing `COAP_NACK_ICMP_ISSUE`:

- parse the ICMP payload and extract the quoted original UDP/CoAP datagram
- decode the quoted CoAP header
- compare quoted `type`
- compare quoted `code`
- compare quoted `Message ID`
- compare quoted `Token`
- reject or ignore the ICMP indication when those fields do not match the live exchange

Additional negative evidence from source review:

- No `MSG_ERRQUEUE`-based receive path was found in `coap_dgrm_posix.c`.
- No `IP_RECVERR` or `SO_EE_ORIGIN_ICMP` handling was found in the reviewed POSIX datagram path.
- The normal CoAP parsing path in [coap_net.c](D:/project/conditionFuzzing/libcoap-develop/src/coap_net.c:2638) uses `coap_pdu_parse()` for actual received CoAP datagrams, but there is no analogous parser path for ICMP-quoted original CoAP messages before `COAP_NACK_ICMP_ISSUE` is raised.

So, the current implementation has:

- ICMP/socket error recognition: yes
- original-datagram CoAP field vetting: no

## Dynamic Test Evidence

### Test Goal

The purpose of the dynamic test was to distinguish between these two possibilities:

1. libcoap validates the quoted original CoAP fields inside the ICMP payload before acting.
2. libcoap does not validate them and reacts only to the generic ICMP/socket error indication.

### Test Method

A dedicated WSL repro was executed using:

- [repro_libcoap_id357_wsl_client.c](D:/project/conditionFuzzing/test-libcoap/351-400/repro_libcoap_id357_wsl_client.c)
- [repro_libcoap_id357_inject_icmp.py](D:/project/conditionFuzzing/test-libcoap/351-400/repro_libcoap_id357_inject_icmp.py)
- [repro_libcoap_id357_wsl_runner.sh](D:/project/conditionFuzzing/test-libcoap/351-400/repro_libcoap_id357_wsl_runner.sh)

The client sent a real UDP CoAP CON GET request with:

- actual `MID = 0xcd56`
- actual `Token = 11223344`

The injector then sent a forged ICMP destination-unreachable message back to the client, but the ICMP payload deliberately quoted a different CoAP request:

- forged quoted `MID = 0xbeef`
- forged quoted `Token = deadbeef`

In other words, the ICMP indication did not quote the same CoAP identity fields as the live request.

### Runtime Result

Observed output:

```text
LOCAL_ADDR=127.0.0.1:42118
REMOTE_ADDR=127.0.0.1:56831
REQUEST_MID=0xcd56
REQUEST_TOKEN=11223344
INJECT real_mid=0xcd56 quoted_mid=0xbeef quoted_token=deadbeef
May 06 14:51:31.744  1 WARN ** 127.0.0.1:42118 <-> 127.0.0.1:56831 UDP : coap_socket_recv: ICMP: Connection refused
NACK reason=4 name=127.0.0.1:42118 <-> 127.0.0.1:56831 UDP  mid=0xcd56 sent_mid=0xcd56 token=11223344
SAW_ICMP_NACK=1
```

What this proves:

- libcoap accepted the ICMP indication as relevant to the live session.
- libcoap raised `COAP_NACK_ICMP_ISSUE`.
- It did so even though the quoted CoAP `MID` and `Token` inside the forged ICMP payload were intentionally mismatched.

This is strong runtime evidence that the implementation is not validating the quoted original CoAP `type/code/MID/Token` before acting.

## Why the Implementation Is Inconsistent with the Standard

The inconsistency is not that libcoap ignores ICMP entirely. In fact, it does react to ICMP-related socket errors.

The inconsistency is more specific:

- RFC 7252 says that if ICMP errors are taken into account, the implementation should check the quoted original datagram information, including CoAP header fields such as `type`, `code`, `Message ID`, and `Token`.
- libcoap currently reacts at the socket-error level and turns that directly into `COAP_NACK_ICMP_ISSUE`.
- No reviewed path validates the ICMP-quoted original CoAP datagram before that action is taken.
- Dynamic testing shows that even a deliberately mismatched quoted `MID` and `Token` still cause libcoap to treat the ICMP indication as belonging to the live exchange.

So the mismatch between standard and implementation is:

- Standard: "check the original datagram fields before acting"
- libcoap: "act on generic ICMP/socket failure without validating quoted CoAP identity fields"

## Decision

`partially_satisfied`

Reason:

- Satisfied part: libcoap can detect and surface ICMP-style delivery failures as `COAP_NACK_ICMP_ISSUE`.
- Unsatisfied part: libcoap does not implement the RFC 7252 vetting step for the quoted original CoAP `type/code/MID/Token`.

## Short Conclusion

ID 357 should remain `partially_satisfied`.

libcoap has basic ICMP issue handling, but it does not implement the RFC-recommended anti-spoofing validation over the ICMP-embedded original CoAP datagram. Static code review and dynamic mismatch injection both support that conclusion.
