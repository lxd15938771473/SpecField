# Wrong Certificate Identity Can Be Accepted When CN/Authority Matching Is Left To Callback Logic

## Summary

RFC7252 Section 9.1.3.3 requires that when a certificate does not contain a
SubjectAltName, the authority of the request URI must match the certificate
Common Name, and wildcard matching is not allowed for this CoAP rule.

libcoap does not enforce this authority-match rule as a built-in invariant.
Instead, it exposes the derived certificate name to an application callback.
That design is security-relevant, not merely semantic: in local DTLS runtime
testing, a client configured for `victim.example` successfully accepted a server
certificate for `attacker.example` when the callback unconditionally returned
success.


## Standard Requirement

CoAP standard: RFC7252, Section 9.1.3.3, "X.509 Certificates".

Online source: [https://www.rfc-editor.org/rfc/rfc7252#section-9.1.3.3](https://www.rfc-editor.org/rfc/rfc7252#section-9.1.3.3)

Original English requirement excerpt:

```text
authority of the request URI MUST match the Common Name
```

The same section also states that wildcard certificates are excluded for this
certificate matching rule.

## Source Code Behavior

libcoap exposes the validated certificate name through a callback:

```c
/* libcoap-develop/include/coap3/coap_dtls.h */
/**
 * CN Validation callback that can be set up by coap_context_set_pki().
 * Invoked when libcoap has done the validation checks at the TLS level,
 * but the application needs to check that the CN is allowed.
 * CN is the SubjectAltName in the cert, if not present, then the leftmost
 * Common Name (CN) component of the subject name.
 */
typedef int (*coap_dtls_cn_callback_t)(const char *cn,
                                       const uint8_t *asn1_public_cert,
                                       size_t asn1_length,
                                       coap_session_t *coap_session,
                                       unsigned int depth,
```

The shipped client example accepts the presented name unconditionally:

```c
/* libcoap-develop/examples/coap-client.c */
static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert COAP_UNUSED,
                   size_t asn1_length COAP_UNUSED,
                   coap_session_t *session COAP_UNUSED,
                   unsigned depth,
                   int validated COAP_UNUSED,
                   void *arg COAP_UNUSED) {
  coap_log_info("CN '%s' presented by server (%s)\n",
                cn, depth ? "CA" : "Certificate");
  return 1;
}
```

This means libcoap makes the name available to the application, but does not
itself compare the request authority against the certificate name or reject
wildcards by default in the reviewed path.

## Runtime Reproduction

This item was rechecked with a dedicated local DTLS/OpenSSL build and a custom
reproduction harness:

- build: `build-libcoap-id061-dtls` with `ENABLE_DTLS=ON` and `DTLS_BACKEND=openssl`
- repro program: `test-libcoap/051-100/repro_id061_certificate_cn_authority_match.c`
- repro log: `test-libcoap/051-100/repro_id061_certificate_cn_authority_match.log`
- cert generation: `test-libcoap/051-100/repro_id061_generate_certs.ps1`

The test environment used:

- a trusted local CA
- a server certificate with `CN=attacker.example`
- a client SNI / intended authority of `victim.example`
- no SubjectAltName override that would satisfy the RFC authority check

### Case 1: callback unconditionally accepts the certificate name

This models the same security posture as the shipped example callback.

```text
BEGIN allow_all_callback
CLIENT_CN_CALLBACK cn=attacker.example depth=0 validated=1 allow_all=1
CLIENT_EVENT 0x01de
CLIENT_RESPONSE code=2.05
CLIENT_RESPONSE_PAYLOAD hello
SCENARIO allow_all=1 sent=1 cn_called=1 cn_accepted=1 client_connected=1 client_dtls_error=0 response=1 server_connected=1
```

Observed behavior:

- the certificate chain was trusted
- the leaf certificate name presented to the callback was `attacker.example`
- the client DTLS session connected successfully
- the client accepted an application response payload

In other words, the client intended to talk to `victim.example`, but a trusted
certificate for `attacker.example` was accepted and the session still
progressed to application data.

### Case 2: callback enforces `victim.example` on the leaf certificate  

The same harness was rerun with a callback that allows the CA certificate but
rejects the server certificate unless the leaf CN equals `victim.example`.

```text
BEGIN strict_victim_match
CLIENT_CN_CALLBACK cn=attacker.example depth=0 validated=1 allow_all=0
CLIENT_EVENT 0x0200
SCENARIO allow_all=0 sent=1 cn_called=1 cn_accepted=0 client_connected=0 client_dtls_error=1 response=0 server_connected=0
```

Observed behavior:

- the callback still saw the trusted CA
- the leaf certificate name `attacker.example` was rejected
- the DTLS connection failed
- no application response was accepted

This confirms that the runtime acceptance in Case 1 depends on the missing
authority check rather than on some unrelated trust-store or transport issue.

## Inconsistency

| Expected by RFC7252                                                            | Observed in libcoap                                                                                                                                 |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| URI authority must match CN when SAN is absent.                                | Matching is delegated to callback logic and is not enforced by default.                                                                             |
| Wildcards are excluded for this CoAP certificate rule.                         | No reviewed built-in default wildcard rejection was found on the same path.                                                                         |
| Wrong-name server identities must not be accepted for the requested authority. | A trusted `CN=attacker.example` certificate was accepted at runtime for intended authority `victim.example` when the callback returned success. |

## Security Impact

This behavior weakens DTLS server authentication. If an application uses
libcoap's callback surface but does not implement strict authority/name
verification itself, a wrong server identity can be accepted despite the
certificate chain being otherwise valid.

The local reproduction demonstrates the concrete risk:

- intended target: `coaps://victim.example`
- presented server certificate: `CN=attacker.example`
- callback behavior: unconditional accept
- result: DTLS handshake succeeds and the client accepts a `2.05` response

This can enable:

- acceptance of the wrong authenticated server identity
- man-in-the-middle style downgrade of endpoint identity checking when an attacker can present another trusted certificate
- over-trust of CA-valid certificates that do not belong to the requested authority

So this is not just an API ergonomics issue or a minor semantic mismatch. It
directly affects the security of TLS/DTLS peer authentication.

## Decision

libcoap provides the callback hook and enough certificate-name information for
an application to enforce RFC7252's authority-match rule, so the capability to
implement the requirement exists. However, libcoap does not enforce the rule by
default, and the shipped callback pattern can lead to successful runtime
acceptance of a trusted certificate for the wrong authority.
