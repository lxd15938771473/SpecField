# MAX_STREAMS Upper-Bound Handling

## Result

quiche prevents over-large stream counts from producing unrepresentable stream IDs, but it enforces a `uint32` implementation limit rather than RFC 9000's exact `2^60` boundary.

## Standard Reference

Standard: [RFC 9000 Section 4.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6), [RFC 9000 Section 18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2), and [RFC 9000 Section 19.11](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11)

## Standard Original Text

```text
An endpoint limits the cumulative number of incoming streams a peer can open.
Only streams with a stream ID less than
(max_streams * 4 + first_stream_id_of_type) can be opened; see Table 1.
Initial limits are set in the transport parameters; see Section 18.2.
Subsequent limits are advertised using MAX_STREAMS frames; see Section 19.11.
Separate limits apply to unidirectional and bidirectional streams.

If a max_streams transport parameter or a MAX_STREAMS frame is received with a
value greater than 2^60, this would allow a maximum stream ID that cannot be
expressed as a variable-length integer; see Section 16. If either is received,
the connection MUST be closed immediately with a connection error of type
TRANSPORT_PARAMETER_ERROR if the offending value was received in a transport
parameter or of type FRAME_ENCODING_ERROR if it was received in a frame; see
Section 10.2.

The MAX_STREAMS frames inform the peer of the cumulative number of streams of
a given type it is permitted to open. A MAX_STREAMS frame with a stream count
greater than 2^60 is invalid.
```

## Standard Requirement

`max_streams` values are valid up to `2^60`. Values greater than `2^60` are invalid because they could produce a stream ID that cannot be represented as a QUIC variable-length integer. A transport-parameter violation should use `TRANSPORT_PARAMETER_ERROR`; a frame violation should use `FRAME_ENCODING_ERROR`.

## Relevant Source Code

MAX_STREAMS frame parsing:

Source: `quiche-main/quiche-main/quiche/quic/core/quic_framer.cc:6229-6237`

```cpp
bool QuicFramer::ProcessMaxStreamsFrame(QuicDataReader* reader,
                                        QuicMaxStreamsFrame* frame,
                                        uint64_t frame_type) {
  if (!ReadUint32FromVarint62(reader,
                              static_cast<QuicIetfFrameType>(frame_type),
                              &frame->stream_count)) {
    return false;
  }
  frame->unidirectional = (frame_type == IETF_MAX_STREAMS_UNIDIRECTIONAL);
```

Source: `quiche-main/quiche-main/quiche/quic/core/quic_framer.cc:6402-6415`

```cpp
bool QuicFramer::ReadUint32FromVarint62(QuicDataReader* reader,
                                        QuicIetfFrameType type,
                                        QuicStreamId* id) {
  uint64_t temp_uint64;
  if (!reader->ReadVarInt62(&temp_uint64)) {
    set_detailed_error("Unable to read " + QuicIetfFrameTypeString(type) +
                       " frame stream id/count.");
    return false;
  }
  if (temp_uint64 > kMaxQuicStreamId) {
    set_detailed_error("Stream id/count of " + QuicIetfFrameTypeString(type) +
                       "frame is too large.");
    return false;
  }
  *id = static_cast<uint32_t>(temp_uint64);
```

Implementation limit:

Source: `quiche-main/quiche-main/quiche/quic/core/quic_constants.h:261-264`

```cpp
inline constexpr QuicStreamId kMaxQuicStreamId = 0xffffffff;

// The maximum value that can be stored in a 32-bit QuicStreamCount.
inline constexpr QuicStreamCount kMaxQuicStreamCount = 0xffffffff;
```

Transport-parameter clamping:

Source: `quiche-main/quiche-main/quiche/quic/core/quic_config.cc:1362-1369`

```cpp
// IETF QUIC specifies stream IDs and stream counts as 62-bit integers but
// our implementation uses uint32_t to represent them to save memory.
max_bidirectional_streams_.SetReceivedValue(
    std::min<uint64_t>(params.initial_max_streams_bidi.value(),
                       std::numeric_limits<uint32_t>::max()));
max_unidirectional_streams_.SetReceivedValue(
    std::min<uint64_t>(params.initial_max_streams_uni.value(),
                       std::numeric_limits<uint32_t>::max()));
```

## Inconsistency Reason

The RFC permits `max_streams` values up to `2^60` and only marks values greater than `2^60` invalid. quiche instead routes frame counts through `ReadUint32FromVarint62` and rejects anything above `0xffffffff`. For transport parameters, it clamps received values to `uint32_t::max()`. This is conservative, but it changes the acceptance boundary: values between `0xffffffff + 1` and `2^60` are valid under the RFC but rejected or reduced by the implementation.

## Conclusion

The implementation blocks unsafe oversized stream counts, but the enforced bound is an internal `uint32` limit rather than the RFC's `2^60` boundary. The result is partially satisfied.
