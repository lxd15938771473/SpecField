# CRYPTO buffer exceeded uses the wrong transport error

## Decision

Status: not satisfied.

QUICHE enforces a receive-buffer limit for CRYPTO frame data, but the close path uses the internal error `QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA`. That internal error maps to the RFC transport error `FLOW_CONTROL_ERROR`, not `CRYPTO_BUFFER_EXCEEDED`. For a handshake-time CRYPTO buffer overflow, RFC 9000 requires `CRYPTO_BUFFER_EXCEEDED` if the endpoint closes instead of expanding the buffer.

## Original Standard Text

Standard: QUIC RFC 9000, Section 7.5, "Cryptographic Message Buffering"; Section 20.1, "Transport Error Codes".

Online sources:

- [https://www.rfc-editor.org/rfc/rfc9000#section-7.5](https://www.rfc-editor.org/rfc/rfc9000#section-7.5)
- [https://www.rfc-editor.org/rfc/rfc9000#section-20.1](https://www.rfc-editor.org/rfc/rfc9000#section-20.1)

Relevant original RFC excerpts:

```text
Implementations need to maintain a buffer of CRYPTO data received out of order.
```

```text
If an endpoint does not expand its buffer, it MUST close the connection with a CRYPTO_BUFFER_EXCEEDED error code.
```

```text
An endpoint has received more data in CRYPTO frames than it can buffer.
```

Interpretation: during the handshake, if received CRYPTO data exceeds the available buffer and the endpoint chooses not to expand the buffer, the connection close must use `CRYPTO_BUFFER_EXCEEDED`.

## Source Code Excerpts

### CRYPTO receive overflow closes with a flow-control internal error

File: `quiche-main/quiche-main/quiche/quic/core/quic_crypto_stream.cc:102-110`

```c
CryptoSubstream& substream =
    substreams_[QuicUtils::GetPacketNumberSpace(level)];
substream.sequencer.OnCryptoFrame(frame);
EncryptionLevel frame_level = level;
if (substream.sequencer.NumBytesBuffered() >
    BufferSizeLimitForLevel(frame_level)) {
  OnUnrecoverableError(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
                       "Too much crypto data received");
}
```

The receive path detects that buffered CRYPTO data exceeds `BufferSizeLimitForLevel()`, but it reports `QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA`.

### The CRYPTO buffer limit is explicit

File: `quiche-main/quiche-main/quiche/quic/core/quic_crypto_stream.cc:222-224`

```c
size_t QuicCryptoStream::BufferSizeLimitForLevel(EncryptionLevel) const {
  return GetQuicFlag(quic_max_buffered_crypto_bytes);
}
```

This confirms that the overflow condition is a CRYPTO buffering limit, not stream flow control.

### The internal error maps to FLOW_CONTROL_ERROR

File: `quiche-main/quiche-main/quiche/quic/core/quic_error_codes.cc:351-356, 454-455`

```c
QuicErrorCodeToIetfMapping QuicErrorCodeToTransportErrorCode(
    QuicErrorCode error) {
  switch (error) {
    case QUIC_NO_ERROR:
      return {true, static_cast<uint64_t>(NO_IETF_QUIC_ERROR)};
```

```c
case QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA:
  return {true, static_cast<uint64_t>(FLOW_CONTROL_ERROR)};
```

Therefore, the actual transport error sent for this CRYPTO buffer overflow is `FLOW_CONTROL_ERROR`.

### The close path does not override the IETF transport error

File: `quiche-main/quiche-main/quiche/quic/core/quic_stream.cc:772-780`

```c
void QuicStream::OnUnrecoverableError(QuicErrorCode error,
                                      const std::string& details) {
  stream_delegate_->OnStreamError(error, details);
}

void QuicStream::OnUnrecoverableError(QuicErrorCode error,
                                      QuicIetfTransportErrorCodes ietf_error,
                                      const std::string& details) {
  stream_delegate_->OnStreamError(error, ietf_error, details);
}
```

The CRYPTO overflow branch calls the first overload, so it supplies only the internal `QuicErrorCode` and does not explicitly pass `CRYPTO_BUFFER_EXCEEDED`.

File: `quiche-main/quiche-main/quiche/quic/core/quic_connection.cc:4769-4773`

```c
void QuicConnection::CloseConnection(
    QuicErrorCode error, const std::string& details,
    ConnectionCloseBehavior connection_close_behavior) {
  CloseConnection(error, NO_IETF_QUIC_ERROR, details,
                  connection_close_behavior);
}
```

When no explicit IETF transport error is supplied, the close path uses `NO_IETF_QUIC_ERROR`, which means the later `QuicConnectionCloseFrame` constructor must derive the wire error from `QuicErrorCodeToTransportErrorCode()`.

File: `quiche-main/quiche-main/quiche/quic/core/frames/quic_connection_close_frame.cc:28-34`

```c
QuicErrorCodeToIetfMapping mapping =
    QuicErrorCodeToTransportErrorCode(error_code);
if (ietf_error != NO_IETF_QUIC_ERROR) {
  wire_error_code = ietf_error;
} else {
  wire_error_code = mapping.error_code;
}
```

This confirms that the peer-visible wire error is the mapped error, which is `FLOW_CONTROL_ERROR` for `QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA`.

### CRYPTO_BUFFER_EXCEEDED exists but is not used by this path

File: `quiche-main/quiche-main/quiche/quic/core/quic_error_codes.h:746-760`

```c
enum QuicIetfTransportErrorCodes : uint64_t {
  NO_IETF_QUIC_ERROR = 0x0,
  INTERNAL_ERROR = 0x1,
  SERVER_BUSY_ERROR = 0x2,
  FLOW_CONTROL_ERROR = 0x3,
  STREAM_LIMIT_ERROR = 0x4,
  STREAM_STATE_ERROR = 0x5,
  FINAL_SIZE_ERROR = 0x6,
  FRAME_ENCODING_ERROR = 0x7,
  TRANSPORT_PARAMETER_ERROR = 0x8,
  CONNECTION_ID_LIMIT_ERROR = 0x9,
  PROTOCOL_VIOLATION = 0xA,
  INVALID_TOKEN = 0xB,
  CRYPTO_BUFFER_EXCEEDED = 0xD,
```

The correct RFC transport error is defined, but the reviewed overflow branch does not select it.

### Existing test expects the flow-control internal error

File: `quiche-main/quiche-main/quiche/quic/core/quic_crypto_stream_test.cc:743-750`

```c
TEST_F(QuicCryptoStreamTest, LimitBufferedCryptoData) {
  if (!VersionIsIetfQuic(connection_->transport_version())) {
    return;
  }

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _));
```

The test locks in the current internal close code, which later maps to `FLOW_CONTROL_ERROR`.

## Reason for the Mismatch

RFC 9000 treats CRYPTO buffering overflow as a dedicated transport error condition: `CRYPTO_BUFFER_EXCEEDED`.

QUICHE detects the overflow, but reports it as generic flow-control excess:

| Step                                                 | RFC expectation                                                     | QUICHE behavior                                                               |
| ---------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| CRYPTO receive buffer exceeds limit during handshake | close with `CRYPTO_BUFFER_EXCEEDED` if the buffer is not expanded | calls `OnUnrecoverableError(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, ...)` |
| Transport error mapping                              | `CRYPTO_BUFFER_EXCEEDED` (`0x0d`)                               | `FLOW_CONTROL_ERROR` (`0x03`)                                             |

This is a real inconsistency because the required buffer-limit behavior is present, but the transport error code is different from the RFC-required one.
