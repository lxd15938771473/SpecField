# AUTH Remaining Length 0 Success Packet Is Rejected by the Client Parser

## Conclusion

MQTT v5.0 allows an `AUTH` packet with `Remaining Length` equal to `0` when the Authenticate Reason Code is `0x00` (`Success`) and there are no properties.

Mosquitto's broker-side AUTH parser handles this form correctly, but the libmosquitto client-side AUTH parser always tries to read the Authenticate Reason Code byte. As a result, a valid server-to-client `AUTH` packet encoded as `F0 00` is treated as malformed by the client library.

## MQTT Standard Requirement

- Standard: [MQTT Version 5.0 OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- Section 3.15.2.1, Authenticate Reason Code
- Related context: Section 3.15.2, AUTH Variable Header

The normative rule for this issue is small but precise:

```text
The Reason Code and Property Length can be omitted if the Reason Code
is 0x00 (Success) and there are no Properties.

In this case the AUTH has a Remaining Length of 0.
```

That means:

- MQTT v5.0 allows a compact `AUTH` encoding
- the compact form is valid only when Reason Code is `0x00` (`Success`)
- the compact form is valid only when there are no properties
- when those conditions hold, the packet may omit both the Reason Code field and the Property Length field
- a receiver must not require extra variable-header bytes when `Remaining Length = 0`

This means the following packet is a valid MQTT v5.0 AUTH packet:

```text
F0 00
```

where:

```text
F0 = AUTH control packet type
00 = Remaining Length 0

Reason Code field: omitted, therefore interpreted as 0x00 (Success)
Property Length field: omitted, therefore there are no properties
```

That means:

- `F0 00` is a complete and valid MQTT v5.0 `AUTH` packet
- the omitted Reason Code is semantically `Success`
- the omitted Property Length means the Properties set is empty
- rejecting `F0 00` as malformed is stricter than the specification allows

## Relevant Code Description

### Broker Receive Path

`mosquitto-master/src/handle_auth.c` initializes `reason_code` to `0`:

```c
uint8_t reason_code = 0;
```

It only reads an Authenticate Reason Code byte when the incoming packet has a non-zero Remaining Length:

```c
if(context->in_packet.remaining_length > 0){
	if(packet__read_byte(&context->in_packet, &reason_code)){
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	...
}
```

This matches the standard: when `Remaining Length` is `0`, the omitted reason code is treated as `Success`.

### Client Receive Path

`mosquitto-master/lib/handle_auth.c` does not perform the same `remaining_length > 0` check. It always attempts to read a reason code byte:

```c
if(packet__read_byte(&mosq->in_packet, &reason_code)){
	return 1;
}
```

The low-level byte reader in `mosquitto-master/lib/packet_datatypes.c` rejects reads past the declared Remaining Length:

```c
if(packet->pos+1 > packet->remaining_length){
	return MOSQ_ERR_MALFORMED_PACKET;
}
```

For `AUTH` encoded as `F0 00`, `remaining_length` is `0`, so the client-side parser immediately fails before it can interpret the omitted reason code as `Success`.

## Runtime Evidence

Reproduction target:

```text
client-side handle__auth() parser logic
```

A minimal direct parser test was run against the client-side `handle__auth()`
logic with two packets:

```text
AUTH RL=0: rc=1 pos=0 remaining_length=0
callback__on_ext_auth called
AUTH rc=0 props=0: rc=0 pos=2 remaining_length=2
```

The first case corresponds to the valid compact encoding:

```text
F0 00
```

The client parser returned an error and did not call the extended-auth callback.

The second case corresponds to the non-compact encoding:

```text
F0 02 00 00
```

This includes an explicit `0x00` reason code and a zero property length. The same parser accepted it and called the extended-auth callback.

That means:

- the compact MQTT v5 form fails at runtime in the client parser
- the explicit non-compact form succeeds at runtime in the same parser
- the behavioral difference is caused by packet shape, not by AUTH semantics
- the runtime result matches the code-path analysis that `Remaining Length = 0` is rejected too early

## Why This Is Inconsistent

The MQTT v5.0 standard defines two valid encodings for a successful AUTH packet with no properties:

- Compact form: omit Reason Code and Property Length, resulting in `Remaining Length = 0`.
- Explicit form: include Reason Code `0x00` and Property Length `0`, resulting in `Remaining Length = 2`.

Mosquitto's client library accepts only the explicit form. It rejects the compact form because it unconditionally reads a reason code byte even when the packet declares no variable header bytes.

This creates an interoperability problem: a conforming MQTT v5.0 server can legally send `F0 00`, but a libmosquitto client will treat that packet as malformed.

## Suggested Fix

The client-side parser should mirror the broker-side handling:

```c
uint8_t reason_code = MQTT_RC_SUCCESS;

if(mosq->in_packet.remaining_length > 0){
	if(packet__read_byte(&mosq->in_packet, &reason_code)){
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	rc = property__read_all(CMD_AUTH, &mosq->in_packet, &properties);
	...
}
```

The implementation should also ensure that any non-zero Remaining Length still contains a well-formed AUTH variable header and that all remaining bytes are consumed.
