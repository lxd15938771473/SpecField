# ID 201: Inconsistency Between `missing_extension` and `handshake_failure` When SNI Is Missing

## Issue Overview

The `TLS 1.3` specification recommends an alert description for the case where the server requires the client to send `server_name`, but that extension is absent from the client's `ClientHello`.  
`wolfSSL` aborts the handshake on the corresponding path, but sends `handshake_failure` rather than `missing_extension`.

The inconsistency concerns the alert value relative to the specification's recommendation; it is not a complete failure to reject this error condition.

## Specification Text

Specification file: [TLS1.3.txt](/d:/project/conditionFuzzing/document/TLS1.3.txt:5793)

The original text is:

```text
Servers MAY require clients to send a valid "server_name" extension.
Servers requiring this extension SHOULD respond to a ClientHello
lacking a "server_name" extension by terminating the connection with
a "missing_extension" alert.
```

### Meaning of the Requirement

- The server may require the client to send the `server_name` extension.
- If the server requires it and the client does not send it, the specification recommends terminating the connection with a `missing_extension` alert.
- The requirement uses `SHOULD`, not `MUST`.

## wolfSSL Code Behavior

The relevant code is in [tls.c](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:2573):

```c
if (ctx_sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) {
    sni = TLSX_SNI_Find(ssl_sni, ctx_sni->type);

    if (sni) {
        if (sni->status != WOLFSSL_SNI_NO_MATCH)
            continue;

        /* if ssl level overrides ctx level, it is ok. */
        if ((sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) == 0)
            continue;
    }

    SendAlert(ssl, alert_fatal, handshake_failure);
    WOLFSSL_ERROR_VERBOSE(SNI_ABSENT_ERROR);
    return SNI_ABSENT_ERROR;
}
```

The same logic also appears on the SSL-level path; see [tls.c](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:2592).

### Meaning of the Code

- `wolfSSL` treats a missing `server_name` as a fatal error only when `WOLFSSL_SNI_ABORT_ON_ABSENCE` is enabled.
- Once this branch is entered, the code directly performs the following:
  - `SendAlert(..., handshake_failure)`
  - Returns `SNI_ABSENT_ERROR`

Thus, the alert sent on this path is `handshake_failure`.


## Specification and Code Comparison

### Specification

- Condition: the server requires `server_name`.
- Client behavior: `server_name` is absent from `ClientHello`.
- Recommended alert: `missing_extension`

### wolfSSL

- Condition: `WOLFSSL_SNI_ABORT_ON_ABSENCE` is enabled.
- Client behavior: `server_name` is absent from `ClientHello`.
- Actual alert: `handshake_failure`

## Cause of the Inconsistency

The main cause is that `wolfSSL` handles missing SNI through a generic handshake-policy failure branch, rather than using TLS 1.3's more specific `missing_extension` semantics for an absent extension.

More specifically:

- The logic resides in generic SNI handling rather than a TLS 1.3-specific path for detecting missing extensions.
- `wolfSSL` treats required SNI that the client did not provide as an unmet handshake prerequisite and directly sends `handshake_failure`.
- The specification says `SHOULD use missing_extension`, not `MUST use missing_extension`, so this is a deviation from a recommendation rather than an unconditional violation of a mandatory requirement.

## Conclusion

In this scenario, `wolfSSL` behaves as follows:

- It rejects a `ClientHello` that lacks `server_name`.
- It uses `handshake_failure`.
- It does not use the specification's recommended `missing_extension`.

This item is therefore more accurately classified as:

- Behavior that partially matches the specification's intent
- An alert value inconsistent with the specification's recommendation
- A deviation from a recommendation, rather than a complete absence of validation
