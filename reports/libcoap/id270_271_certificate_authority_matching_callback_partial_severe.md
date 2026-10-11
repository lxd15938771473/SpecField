# Certificate Authority Matching Is Delegated To Callback, and Runtime Acceptance Depends On Application Policy

## Result

Status: partial.

The RFC requires the request URI authority to be checked against the certificate identity. libcoap exposes certificate identity material and a validation callback, but the audited core code does not perform an unconditional built-in comparison between the CoAP request URI authority and the certificate SubjectAltName CoAP URI authority or Common Name.

A dedicated DTLS/X.509 runtime reproduction confirms both the security consequence of that design and the RFC SubjectAltName priority rule:

- with a permissive callback, a client using request authority and SNI `victim.example` completes a DTLS session and receives a `2.05` response from a server presenting a CA-valid certificate whose identity is `CN=attacker.example` and has no matching SubjectAltName
- with a strict callback, the same CN-only mismatch is rejected before application data
- with `SAN=coaps://victim.example` and `CN=attacker.example`, the strict callback accepts
- with `SAN=coaps://attacker.example` and `CN=victim.example`, the strict callback rejects

This shows that compliant behavior can be implemented in the callback, including SAN-over-CN priority, but it is not enforced by libcoap itself as a generic invariant.

## Standard Basis

RFC link: [RFC 7252 Section 9.1.3.3, X.509 Certificates](https://www.rfc-editor.org/rfc/rfc7252#section-9.1.3.3)

```text
When a new connection is formed, the certificate from the remote device
needs to be verified. If the CoAP node has a source of absolute time, then
the node SHOULD check that the validity dates of the certificate are within
range. The certificate MUST be validated as appropriate for the security
requirements, using functionality equivalent to the algorithm specified in
Section 6 of [RFC5280]. If the certificate contains a SubjectAltName, then
the authority of the request URI MUST match at least one of the authorities
of any CoAP URI found in a field of URI type in the SubjectAltName set. If
there is no SubjectAltName in the certificate, then the authority of the
request URI MUST match the Common Name (CN) found in the certificate using
the matching rules defined in [RFC3280] with the exception that certificates
with wildcards are not allowed.
```

The critical priority rule is explicit:

- if SubjectAltName is present, authority matching must use SAN
- only if SAN is absent does the check fall back to CN

## Source Evidence

Source file: `include/coap3/coap_dtls.h`

```c
/**
 * CN check callback function.
 *
 * Invoked when libcoap has done the validation checks at the TLS level,
 * but the application needs to check that the CN is allowed.
 * CN is the SubjectAltName in the cert, if not present, then the leftmost
 * Common Name (CN) component of the subject name.
 *
 * @return 1 if accepted, else 0 if to be rejected.
 */
typedef int (*coap_dtls_cn_callback_t)(const char *cn,
                                       const uint8_t *asn1_public_cert,
                                       size_t asn1_length,
                                       coap_session_t *coap_session,
                                       unsigned int depth,
                                       int validated,
                                       void *arg);
```

Source file: `include/coap3/coap_dtls.h`

```c
/** CN check callback function.
 * If not NULL, is called when the TLS connection has passed the configured
 * TLS options above for the application to verify if the CN is valid.
 */
coap_dtls_cn_callback_t validate_cn_call_back;
```

Source file: `src/coap_openssl.c`

```c
/* Certificate - depth == 0 is the Client Cert */
if (setup_data->validate_cn_call_back && keep_preverify_ok) {
  int length = i2d_X509(x509, NULL);
  uint8_t *base_buf;
  uint8_t *base_buf2 = base_buf = length > 0 ? OPENSSL_malloc(length) : NULL;
  int ret;

  if (base_buf) {
    assert(i2d_X509(x509, &base_buf2) > 0);
    coap_lock_callback_ret(ret,
                           setup_data->validate_cn_call_back(cn, base_buf,
                                                             length, session,
                                                             depth,
                                                             preverify_ok,
                                                             setup_data->cn_call_back_arg));
    if (!ret) {
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
      preverify_ok = 0;
    }
    OPENSSL_free(base_buf);
  }
}
```

## Runtime Reproduction

The static review conclusion was rechecked with a dedicated DTLS/OpenSSL runtime harness:

- build: `build-libcoap-id061-dtls`
- DTLS backend: OpenSSL (`DTLS_BACKEND=openssl`, `ENABLE_DTLS=ON`)
- repro program: `test-libcoap/251-300/repro_id270_271_certificate_authority_callback_runtime.c`
- repro log: `test-libcoap/251-300/repro_id270_271_certificate_authority_callback_runtime.log`
- cert generation: `test-libcoap/251-300/repro_id270_271_generate_certs.ps1`

The client always requests:

- request URI: `coaps://victim.example/hello`
- request authority: `victim.example`
- DTLS SNI: `victim.example`

The server receives `Uri-Host: victim.example` when the handshake succeeds.

### Certificate Set

Three server leaf certificates were generated under the same trusted local CA:

1. `server_cn_only_attacker`
   CN = `attacker.example`
   no SAN

2. `server_san_victim_cn_attacker`
   SAN = `coaps://victim.example`
   CN = `attacker.example`

3. `server_san_attacker_cn_victim`
   SAN = `coaps://attacker.example`
   CN = `victim.example`

### Case 1: permissive callback accepts wrong CN

The first callback models the example-style permissive pattern and simply returns `1` for the leaf certificate.

```text
BEGIN allow_all_cn_only_attacker
SCENARIO_BEGIN label=allow_all_cn_only_attacker strict=0 cert=server_cn_only_attacker request_uri=coaps://victim.example/hello client_sni=victim.example
CLIENT_CN_CALLBACK scenario=allow_all_cn_only_attacker cn=attacker.example depth=0 validated=1 strict=0 expected=victim.example
SERVER_REQUEST_URI_HOST scenario=allow_all_cn_only_attacker host=victim.example
CLIENT_RESPONSE scenario=allow_all_cn_only_attacker code=2.05
CLIENT_RESPONSE_PAYLOAD scenario=allow_all_cn_only_attacker hello
SCENARIO label=allow_all_cn_only_attacker strict=0 sent=1 uri_host_seen=1 cn_called=1 cn_accepted=1 client_connected=1 client_dtls_error=0 response=1 server_connected=1
```

Observed behavior:

- the request authority was `victim.example`
- the DTLS SNI was `victim.example`
- the certificate presented to the callback was `attacker.example`
- the DTLS handshake succeeded
- the client received `2.05 Content`

This demonstrates successful runtime acceptance of the wrong authenticated server identity when the application callback is overly permissive.

### Case 2: strict callback rejects CN-only mismatch

The strict callback implements the RFC7252 priority rule:

- if URI-type SAN entries are present, match authority only against SAN
- if URI-type SAN entries are absent, fall back to CN

For the CN-only mismatch certificate, the strict callback rejects:

```text
BEGIN strict_cn_only_attacker
SCENARIO_BEGIN label=strict_cn_only_attacker strict=1 cert=server_cn_only_attacker request_uri=coaps://victim.example/hello client_sni=victim.example
CLIENT_CN_CALLBACK scenario=strict_cn_only_attacker cn=attacker.example depth=0 validated=1 strict=1 expected=victim.example
CLIENT_EVENT scenario=strict_cn_only_attacker event=0x0200
SCENARIO label=strict_cn_only_attacker strict=1 sent=1 uri_host_seen=0 cn_called=1 cn_accepted=0 client_connected=0 client_dtls_error=1 response=0 server_connected=0
```

Observed behavior:

- there was no SAN to consult
- CN `attacker.example` did not match `victim.example`
- the DTLS connection failed
- no application response was delivered

### Case 3: SAN match overrides wrong CN

This is the SubjectAltName priority test you requested.

Certificate:

- SAN = `coaps://victim.example`
- CN = `attacker.example`

Strict callback result:

```text
BEGIN strict_san_victim_cn_attacker
SCENARIO_BEGIN label=strict_san_victim_cn_attacker strict=1 cert=server_san_victim_cn_attacker request_uri=coaps://victim.example/hello client_sni=victim.example
CLIENT_CN_CALLBACK scenario=strict_san_victim_cn_attacker cn=attacker.example depth=0 validated=1 strict=1 expected=victim.example
SERVER_REQUEST_URI_HOST scenario=strict_san_victim_cn_attacker host=victim.example
CLIENT_RESPONSE scenario=strict_san_victim_cn_attacker code=2.05
CLIENT_RESPONSE_PAYLOAD scenario=strict_san_victim_cn_attacker hello
SCENARIO label=strict_san_victim_cn_attacker strict=1 sent=1 uri_host_seen=1 cn_called=1 cn_accepted=1 client_connected=1 client_dtls_error=0 response=1 server_connected=1
```

Observed behavior:

- the callback still received derived name text `attacker.example`
- the strict authority check inspected the DER certificate SAN entries
- SAN authority `victim.example` matched the request authority
- the DTLS connection succeeded and the client received `2.05`

This proves the strict callback is not merely checking CN. It accepts based on SAN when SAN is present, exactly as RFC7252 requires.

### Case 4: SAN mismatch rejects even when CN matches

This is the reverse-priority test.

Certificate:

- SAN = `coaps://attacker.example`
- CN = `victim.example`

Strict callback result:

```text
BEGIN strict_san_attacker_cn_victim
SCENARIO_BEGIN label=strict_san_attacker_cn_victim strict=1 cert=server_san_attacker_cn_victim request_uri=coaps://victim.example/hello client_sni=victim.example
CLIENT_CN_CALLBACK scenario=strict_san_attacker_cn_victim cn=victim.example depth=0 validated=1 strict=1 expected=victim.example
CLIENT_EVENT scenario=strict_san_attacker_cn_victim event=0x0200
SCENARIO label=strict_san_attacker_cn_victim strict=1 sent=1 uri_host_seen=0 cn_called=1 cn_accepted=0 client_connected=0 client_dtls_error=1 response=0 server_connected=0
```

Observed behavior:

- the callback-visible leaf name text was `victim.example`
- however, the certificate also contained a URI-type SAN
- the SAN authority was `attacker.example`, not `victim.example`
- the strict callback rejected the certificate
- the DTLS connection failed and no application response was delivered

This proves the strict callback honors SAN priority over CN. Even a matching CN is not enough when SAN is present and points elsewhere.

### What This Confirms

The runtime split is now stronger than the original CN-only test:

- permissive callback: wrong-name CN-only certificate is accepted
- strict callback: wrong-name CN-only certificate is rejected
- strict callback: matching SAN plus wrong CN is accepted
- strict callback: mismatching SAN plus matching CN is rejected

So the test coverage now explicitly includes the RFC SubjectAltName priority rule, not just CN matching.

## Comparison

The standard check is mandatory: the authority from the CoAP request URI must match the certificate identity source described by the RFC. The code check shows that libcoap validates the certificate chain at the TLS layer and then calls an application-supplied callback to decide whether the certificate name is acceptable.

The runtime checks confirm the practical effect of that architecture:

- a trusted but wrong-name certificate is accepted when the callback returns success unconditionally
- a strict callback can enforce CN fallback when SAN is absent
- a strict callback can also enforce SAN-over-CN priority exactly as RFC7252 requires

That means the RFC-mandated authority comparison is not a built-in invariant of generic libcoap usage; it is application policy implemented through the callback.

This remains a partial implementation at the library boundary: the required hook exists, but the mandatory authority comparison is delegated rather than enforced by the generic stack.

## Security Impact

If an application uses a permissive callback like the shipped example pattern, a CA-valid certificate for the wrong server identity can be accepted for the requested authority.

The CN-only mismatch reproduction demonstrates the concrete risk:

- requested authority: `victim.example`
- DTLS SNI: `victim.example`
- presented server certificate identity: `CN=attacker.example`
- callback behavior: unconditional accept
- outcome: DTLS handshake succeeds and the client accepts a `2.05` response

The SAN priority tests also show the other side of the story: safe behavior is achievable, but only if the application callback implements the RFC rule correctly. The library does not guarantee that by default.

## Test Result

```text
source_assertions_251_300.py
PASS payload_marker_followed_by_zero_length_rejected
PASS nonzero_payload_encoder_adds_marker
PASS payload_pointer_derived_after_marker
PASS proxy_uri_parser_uses_proxy_mode
PASS uri_split_options_supported
PASS proxy_unavailable_returns_505
PASS proxy_endpoint_authority_can_be_local
PASS delete_unknown_resource_returns_202
PASS bad_option_error_response_path
PASS reserved_response_class_3_accepted
PASS etag_match_large_response_sets_203_without_payload
PASS proxy_forward_response_uses_large_response_helper
PASS proxy_observe_cache_insertion_present
PASS proxy_observe_cache_has_no_response_code_guard
PASS proxy_cleanup_uses_502_not_504
PASS gateway_timeout_code_defined
PASS cn_authority_validation_delegated_to_application
ALL ASSERTIONS PASSED

repro_id270_271_certificate_authority_callback_runtime.exe
BEGIN allow_all_cn_only_attacker
SCENARIO label=allow_all_cn_only_attacker strict=0 sent=1 uri_host_seen=1 cn_called=1 cn_accepted=1 client_connected=1 client_dtls_error=0 response=1 server_connected=1
BEGIN strict_cn_only_attacker
SCENARIO label=strict_cn_only_attacker strict=1 sent=1 uri_host_seen=0 cn_called=1 cn_accepted=0 client_connected=0 client_dtls_error=1 response=0 server_connected=0
BEGIN strict_san_victim_cn_attacker
SCENARIO label=strict_san_victim_cn_attacker strict=1 sent=1 uri_host_seen=1 cn_called=1 cn_accepted=1 client_connected=1 client_dtls_error=0 response=1 server_connected=1
BEGIN strict_san_attacker_cn_victim
SCENARIO label=strict_san_attacker_cn_victim strict=1 sent=1 uri_host_seen=0 cn_called=1 cn_accepted=0 client_connected=0 client_dtls_error=1 response=0 server_connected=0
```
