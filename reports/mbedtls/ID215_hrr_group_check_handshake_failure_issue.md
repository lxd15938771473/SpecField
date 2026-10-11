# ID 215: HRR Group Check Failure Uses `handshake_failure` Instead of `illegal_parameter`

- ID: `215`
- Status: `Partially Satisfied`
- Category: `Alert semantic and policy difference`
- Variable: `alert`
- Change action: `set to constant`
- Change condition: `when the HRR-selected group check fails`

## 1. Specification Description (Original English)

### 1.1 Relevant TLS 1.3 requirement

Source: `document/TLS1.3.txt:2772`

```text
If using
(EC)DHE key establishment and a HelloRetryRequest containing a
"key_share" extension was received by the client, the client MUST
verify that the selected NamedGroup in the ServerHello is the same as
that in the HelloRetryRequest.  If this check fails, the client MUST
abort the handshake with an "illegal_parameter" alert.
```

The key point for ID `215` is the last sentence:

- after receiving a `HelloRetryRequest` with a `key_share` extension
- the client must compare the selected group in `ServerHello` with the one requested by `HelloRetryRequest`
- if they differ, the client must abort with `illegal_parameter`

This is a `MUST` requirement.

## 2. Code Description (Original Code / Direct Evidence)

### 2.1 Client-side HRR follow-up group check

Source: `mbedtls-development/library/ssl_tls13_client.c:482`

```c
/* Check that the chosen group matches the one we offered. */
offered_group = ssl->handshake->offered_group_id;
if (offered_group != group) {
    MBEDTLS_SSL_DEBUG_MSG(
        1, ("Invalid server key share, our group %u, their group %u",
            (unsigned) offered_group, (unsigned) group));
    MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                 MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
    return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
}
```

This branch shows that mbedTLS does perform the semantic check:

- it compares the server-selected group with `ssl->handshake->offered_group_id`
- it aborts when the two groups differ

So the implementation does detect the condition required by the RFC.

### 2.2 The alert that is actually queued is `handshake_failure`

Source: `mbedtls-development/include/mbedtls/ssl.h:539`

```c
#define MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE     40  /* 0x28 */
```

Source: `mbedtls-development/include/mbedtls/ssl.h:546`

```c
#define MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER     47  /* 0x2F */
```

The code above therefore queues alert `40` (`handshake_failure`) rather than alert `47` (`illegal_parameter`).

### 2.3 The queued alert is sent as-is

Source: `mbedtls-development/library/ssl_msg.c:6236`

```c
ret = mbedtls_ssl_send_alert_message(ssl,
                                     MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                     ssl->alert_type);
```

The pending-alert mechanism sends `ssl->alert_type` directly.

This matters because:

- `MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE` is the internal return code
- `MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE` is the protocol alert queued in this branch
- the alert is not re-mapped later to `illegal_parameter`

## 3. Inconsistency

The inconsistency is narrow but real:

- the RFC requires the client to abort with `illegal_parameter`
- mbedTLS aborts with `handshake_failure`

So the problem is not that the check is missing.

The problem is that:

- the condition is detected correctly
- but the resulting alert constant does not match the RFC-mandated alert

## 4. Why This Is Only Partially Satisfied

This issue is classified as `Partially Satisfied` rather than a total failure because mbedTLS still enforces the core safety property:

- it detects that the `ServerHello` group is inconsistent with the HRR-selected group
- it aborts the handshake immediately

However, the RFC is stricter than "abort somehow":

- it requires a specific alert: `illegal_parameter`
- mbedTLS uses `handshake_failure` instead

So the behavioral check is present, but the alert mapping is not RFC-accurate.

## 5. Conclusion

For ID `215`, TLS 1.3 requires that if the group selected in `ServerHello` does not match the group indicated by `HelloRetryRequest`, the client must abort with an `illegal_parameter` alert.

mbedTLS does implement the comparison and does abort on mismatch, which means the core verification logic exists.
But the implementation queues and sends `handshake_failure` rather than `illegal_parameter`.

Therefore, this is a genuine alert-mapping inconsistency, and classifying ID `215` as `Partially Satisfied` is reasonable.
