# openHiTLS ID 205: Inconsistent `unsupported_certificate` Alert Mapping

- date: 2026-04-18
- target: `openhitls-main/openhitls-main`
- related id: `205`
- related rule: `a certificate was of an unsupported type`

## Issue Overview

RFC 8446 makes a clear semantic distinction between certificate-related alerts:

- `bad_certificate`: a corrupt certificate, signature verification failure, or similar problem
- `unsupported_certificate`: an unsupported certificate type

The current openHiTLS implementation has paths that send `ALERT_UNSUPPORTED_CERTIFICATE`. However, errors involving an unsupported certificate type or incompatible certificate capabilities do not consistently produce that alert. Some failure paths are converted to `ALERT_BAD_CERTIFICATE` by the outer layer.

The inconsistency is therefore not a missing implementation of unsupported_certificate, but the following:

```text
Alert mapping for unsupported-type errors is inconsistent; some paths generalize the error to bad_certificate.
```

## Specification Text

The specification is in [TLS1.3.txt](/d:/project/conditionFuzzing/document/TLS1.3.txt:4925).

The original text at lines 4925-4935 of `document/TLS1.3.txt` is:

```text
bad_certificate:  A certificate was corrupt, contained signatures
   that did not verify correctly, etc.

unsupported_certificate:  A certificate was of an unsupported type.
```

The key distinction is:

- `bad_certificate` covers more general errors such as certificate corruption, signature failure, or malformed encoding.
- `unsupported_certificate` specifically denotes an unsupported certificate type.

For an unsupported-type error, `unsupported_certificate` should therefore be the more precise alert.

## Relevant openHiTLS Code

### 1. Some Error Codes Map to `ALERT_UNSUPPORTED_CERTIFICATE`

The PKI-error-to-alert mapping table in [recv_certificate.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/recv/src/recv_certificate.c:37) includes:

```c
{HITLS_X509_ERR_PROCESS_CRITICALEXT, ALERT_UNSUPPORTED_CERTIFICATE},
{HITLS_X509_ERR_CERT_INVALID_PUBKEY, ALERT_UNSUPPORTED_CERTIFICATE},
```

This shows that openHiTLS does implement `unsupported_certificate` on some paths.

It also sends this alert directly when the key-usage check fails:

```c
if (... && !CheckCertKeyUsage(ctx, peerCert)) {
    ...
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_CERTIFICATE);
    ...
}
```

See [recv_certificate.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/recv/src/recv_certificate.c:248) for the corresponding location.

### 2. Certificate-Type Check Failures Do Not Always Produce `unsupported_certificate`

In [hs_cert.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/common/src/hs_cert.c:48):

```c
static int32_t CheckCertType(CERT_Type expectCertType, HITLS_CERT_KeyType checkedKeyType)
{
    ...
    if (expectCertType != checkedCertType) {
        ...
        return HITLS_MSG_HANDLE_UNSUPPORT_CERT;
    }
    return HITLS_SUCCESS;
}
```

This shows that:

- The lower layer of openHiTLS can identify an incompatible or unsupported certificate type.
- A dedicated error code, `HITLS_MSG_HANDLE_UNSUPPORT_CERT`, also exists.

### 3. The Outer Layer Sends `ALERT_BAD_CERTIFICATE` for These Failures

In [recv_certificate.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/recv/src/recv_certificate.c:257):

```c
if (ctx->isClient) {
    ret = ClientCheckCert(ctx, peerCert);
} else {
    ret = ServerCheckCert(ctx, peerCert);
}
if (ret != HITLS_SUCCESS) {
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_CERTIFICATE);
    ...
    return ret;
}
```

In other words:

- Even if the lower-level `CheckCertType()` identifies an unsupported certificate type,
- when the error returns through `ClientCheckCert/ServerCheckCert -> ProcessPeerCertificate`,
- the outer layer may still send the generic `ALERT_BAD_CERTIFICATE` alert.

## Cause of the Inconsistency

The core cause is:

- RFC 8446 distinguishes the semantics of `unsupported_certificate` and `bad_certificate`.
- Some branches within openHiTLS preserve that distinction.
- Other, more general certificate-check failure paths are collapsed into `ALERT_BAD_CERTIFICATE` by the outer layer.

More precisely, the inconsistency in ID 205 is:

```text
Specification semantics: certificate was of an unsupported type -> unsupported_certificate
openHiTLS implementation: some paths send unsupported_certificate, but some unsupported-type or capability-mismatch errors are mapped to the generic bad_certificate alert
```

## Why This Is Not Completely Unsatisfied

openHiTLS still has the following capabilities:

- It defines `ALERT_UNSUPPORTED_CERTIFICATE`.
- It sends that alert on some explicit certificate-capability check failure paths.
- It identifies errors involving certificate type, usage, and public-key capabilities.

Thus, the behavior is implemented, but the specificity of its alert mapping is inconsistent.

## Conclusion

ID 205 is therefore better classified as:

- A difference in the specificity of certificate-alert mapping
- Partially satisfied

Rather than simply:

- Satisfied

This is because openHiTLS does not consistently map unsupported-type errors to `unsupported_certificate`; some implementation paths still generalize them to `bad_certificate`.
