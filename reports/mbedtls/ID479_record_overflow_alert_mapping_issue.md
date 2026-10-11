# mbedTLS Does Not Map Oversized TLS 1.3 Records to `record_overflow`

## 1. Summary

This issue concerns TLS 1.3 record length validation and the required alert for oversized records.

The core mismatch is:

- TLS 1.3 requires endpoints to terminate the connection with a `record_overflow` alert when a received record exceeds the record-layer size limits.
- mbedTLS does reject oversized record content.
- However, the observed mbedTLS path returns `MBEDTLS_ERR_SSL_INVALID_RECORD` and does not send or pend the `record_overflow` alert.

So the length check exists, but the alert mapping is incomplete.

This is the issue described in this document.

## 2. RFC Original Text

### 2.1 TLSPlaintext length limit

From [RFC 8446, Section 5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1):

```text
   length:  The length (in bytes) of the following
      TLSPlaintext.fragment.  The length MUST NOT exceed 2^14 bytes.  An
      endpoint that receives a record that exceeds this length MUST
      terminate the connection with a "record_overflow" alert.
```

This means a plaintext record with length greater than `16384` must be rejected with `record_overflow`.

### 2.2 TLSCiphertext length limit

From [RFC 8446, Section 5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2):

```text
      MUST NOT exceed 2^14 + 256 bytes.  An endpoint that receives a
      record that exceeds this length MUST terminate the connection with
      a "record_overflow" alert.
```

The same rule is repeated in [RFC 8446, Section 5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2):

```text
   peer with TLSCiphertext.length larger than 2^14 + 256 octets MUST
   terminate the connection with a "record_overflow" alert.
```

### 2.3 Alert definition

From [RFC 8446, Section 6.2](https://www.rfc-editor.org/rfc/rfc8446#section-6.2):

```text
   record_overflow:  A TLSCiphertext record was received that had a
      length more than 2^14 + 256 bytes, or a record decrypted to a
      TLSPlaintext record with more than 2^14 bytes (or some other
      negotiated limit).
```

So the expected behavior is not merely "fail the record". The required alert is specifically `record_overflow`.

## 3. Relevant mbedTLS Code

### 3.1 mbedTLS defines the `record_overflow` alert

mbedTLS has the alert constant in [ssl.h](../mbedtls-development/include/mbedtls/ssl.h:537):

```c
#define MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW       22  /* 0x16 */
```

The default plaintext content limit is also `16384` in [ssl.h](../mbedtls-development/include/mbedtls/ssl.h:405):

```c
#define MBEDTLS_SSL_IN_CONTENT_LEN 16384
```

So mbedTLS has both the RFC-sized content limit and the alert code available.

### 3.2 Record header length is parsed

The input record length is parsed in [ssl_msg.c](../mbedtls-development/library/ssl_msg.c:3700):

```c
/*
 * Parse record length.
 */

rec->data_offset = rec_hdr_len_offset + rec_hdr_len_len;
rec->data_len    = MBEDTLS_GET_UINT16_BE(buf, rec_hdr_len_offset);
```

Relevant lines:

- [ssl_msg.c:3700](../mbedtls-development/library/ssl_msg.c:3700)
- [ssl_msg.c:3704](../mbedtls-development/library/ssl_msg.c:3704)

For TLS stream transport, this parsed length is then used to fetch the record content.

### 3.3 Oversized decrypted/plaintext content is rejected as `INVALID_RECORD`

After record content is prepared, mbedTLS checks the actual content length in [ssl_msg.c](../mbedtls-development/library/ssl_msg.c:4009):

```c
/* Check actual (decrypted) record content length against
 * configured maximum. */
if (rec->data_len > MBEDTLS_SSL_IN_CONTENT_LEN) {
    MBEDTLS_SSL_DEBUG_MSG(1, ("bad message length"));
    return MBEDTLS_ERR_SSL_INVALID_RECORD;
}
```

Relevant lines:

- [ssl_msg.c:4009](../mbedtls-development/library/ssl_msg.c:4009)
- [ssl_msg.c:4011](../mbedtls-development/library/ssl_msg.c:4011)
- [ssl_msg.c:4013](../mbedtls-development/library/ssl_msg.c:4013)

This is the important mismatch: the oversized record is rejected, but the function returns:

```c
MBEDTLS_ERR_SSL_INVALID_RECORD
```

It does not call:

```c
MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW, ...)
```

and it does not directly send:

```c
MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW
```

### 3.4 Generic invalid-record handling does not map to `record_overflow`

When `ssl_prepare_record_content()` returns an error, TLS stream transport reaches the error path in [ssl_msg.c](../mbedtls-development/library/ssl_msg.c:4877):

```c
/* Error out (and send alert) on invalid records */
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
if (ret == MBEDTLS_ERR_SSL_INVALID_MAC) {
    mbedtls_ssl_send_alert_message(ssl,
                                   MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                   MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC);
}
#endif
return ret;
```

Relevant lines:

- [ssl_msg.c:4877](../mbedtls-development/library/ssl_msg.c:4877)
- [ssl_msg.c:4879](../mbedtls-development/library/ssl_msg.c:4879)
- [ssl_msg.c:4880](../mbedtls-development/library/ssl_msg.c:4880)
- [ssl_msg.c:4885](../mbedtls-development/library/ssl_msg.c:4885)

This path only maps `MBEDTLS_ERR_SSL_INVALID_MAC` to `bad_record_mac` under `MBEDTLS_SSL_ALL_ALERT_MESSAGES`.

There is no corresponding mapping such as:

```c
if (ret == MBEDTLS_ERR_SSL_INVALID_RECORD &&
    reason_was_record_length_overflow) {
    mbedtls_ssl_send_alert_message(ssl,
                                   MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                   MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW);
}
```

Because `MBEDTLS_ERR_SSL_INVALID_RECORD` is generic, once the length overflow has been collapsed into this return code, the later layer cannot distinguish it from other invalid-record causes.

## 4. Dynamic Test Result

A runtime check was performed against `ssl_server2` built from this tree.

The test sent a TLS 1.3 plaintext handshake record with:

```text
record type = handshake
record version = 0x0303
record length = 16385
```

`16385` is one byte larger than the TLS 1.3 plaintext record limit `2^14 = 16384`.

Observed mbedTLS server log:

```text
input record: msgtype = 22, version = [0x303], msglen = 16385
bad message length
ssl_get_next_record() returned -29184 (-0x7200)
mbedtls_ssl_handshake returned -0x7200
```

`-0x7200` is:

```c
MBEDTLS_ERR_SSL_INVALID_RECORD
```

The peer did not receive a fatal alert record:

```text
response_hex =
```

The expected wire-level fatal alert would have been:

```text
15 03 03 00 02 02 16
```

where:

- `15` = alert record content type
- `02` = fatal alert level
- `16` = `record_overflow`

No such alert was observed.

## 5. Why This Is Inconsistent with the Specification

The RFC requirement is specific:

```text
MUST terminate the connection with a "record_overflow" alert
```

The observed mbedTLS behavior is:

```text
return MBEDTLS_ERR_SSL_INVALID_RECORD
close/fail the handshake without record_overflow alert
```

The implementation therefore satisfies only part of the requirement:

- it detects and rejects the oversized record
- it does not map the condition to the required `record_overflow` alert

This is why the original classification as "partial" is understandable if the criterion includes local rejection. However, if the finding specifically tracks the RFC alert behavior, then the alert portion is not satisfied.

## 6. Impact

The practical impact is mostly interoperability and standards conformance:

- A peer expecting RFC-compliant error signaling will not receive the required `record_overflow` alert.
- Different invalid-record conditions are collapsed into `MBEDTLS_ERR_SSL_INVALID_RECORD`.
- The implementation loses the ability to distinguish "record length overflow" from other malformed record errors at the alert-sending layer.

This does not mean mbedTLS accepts oversized records. It rejects them. The issue is the missing RFC-mandated alert.

## 7. Conclusion

mbedTLS implements the size check for oversized record content, but it does not emit the TLS 1.3 required `record_overflow` alert for the tested oversized plaintext record path.

The RFC-mandated behavior is:

```text
oversized record -> fatal record_overflow alert
```

The observed mbedTLS behavior is:

```text
oversized record -> MBEDTLS_ERR_SSL_INVALID_RECORD, no record_overflow alert
```


