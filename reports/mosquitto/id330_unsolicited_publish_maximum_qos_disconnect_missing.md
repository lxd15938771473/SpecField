# Mosquitto Client Missing DISCONNECT 0x9B for Unsolicited PUBLISH Above Maximum QoS

## Summary

MQTT 5.0 includes a specific client-side rule for unsolicited incoming Application Messages.

If a client receives an Application Message that does not result from a subscription, and that message uses a QoS above the `Maximum QoS` announced by the server, the client is required to send `DISCONNECT` with reason code `0x9B (QoS not supported)`.

In libmosquitto, the `Maximum QoS` value received in `CONNACK` is stored and used to restrict the client's own outbound `PUBLISH` operations. However, the inbound `PUBLISH` receive path does not implement the corresponding unsolicited-message check. Runtime testing confirms that libmosquitto accepts such a message, acknowledges it with `PUBACK`, and delivers it to the application callback instead of sending `DISCONNECT 0x9B`.

## MQTT v5 Requirement

MQTT standard: [MQTT Version 5.0, OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

Relevant sections:

| Section | Requirement |
|---|---|
| `3.2.2.3.4 Maximum QoS` | The server can announce its supported maximum QoS in `CONNACK`. A client that receives this property must not send higher-QoS `PUBLISH` packets. |
| `3.3.4 PUBLISH Actions` | If a client receives an unsolicited Application Message, not resulting from a subscription, whose QoS is greater than `Maximum QoS`, it uses `DISCONNECT 0x9B`. |
| `4.13 Handling errors` | Protocol violations are handled by sending an appropriate `DISCONNECT` reason code when possible. |

Key original English text from section `3.3.4`:

```text
If a Client receives an unsolicited Application Message
(not resulting from a subscription) which has a QoS greater
than Maximum QoS, it uses a DISCONNECT packet with Reason
Code 0x9B (QoS not supported)
```

The important point is that this rule is narrower than a general inbound QoS check:

```text
ordinary subscribed PUBLISH from server -> not covered by this rule
unsolicited PUBLISH not resulting from a subscription -> covered by this rule
```

## Expected Behavior

Expected flow under the rule above:

```text
Server sends CONNACK with Maximum QoS = 0
Client does not subscribe to any topic
Server sends unsolicited QoS 1 PUBLISH
Client detects that the message is not resulting from a subscription
Client sends DISCONNECT 0x9B
Client does not acknowledge the message as normal QoS 1 traffic
Client does not deliver the message to the application callback
```

## Code Behavior

### CONNACK Maximum QoS Is Stored

libmosquitto stores the `Maximum QoS` received from the server in `mosquitto-master/lib/handle_connack.c`:

```c
mosquitto_property_read_byte(properties, MQTT_PROP_MAXIMUM_QOS, &mosq->max_qos, false);
```

This means the library is aware of the server-advertised maximum.

### Outbound Client Publish Is Restricted

The client send path checks the requested outbound QoS in `mosquitto-master/lib/actions_publish.c`:

```c
if(qos > mosq->max_qos){
	return MOSQ_ERR_QOS_NOT_SUPPORTED;
}
```

So libmosquitto enforces the server's `Maximum QoS` for client-to-server `PUBLISH`.

### Inbound Publish Path Does Not Apply the Unsolicited Rule

The inbound client receive path is implemented in `mosquitto-master/lib/handle_publish.c`.

It parses the incoming QoS directly from the fixed header:

```c
message->msg.qos = (header & 0x06)>>1;
```

But there is no check for either of the conditions required by the MQTT rule:

```text
1. whether the message is unsolicited / not resulting from a subscription
2. whether inbound QoS is greater than mosq->max_qos in that situation
```

Instead, QoS 1 and QoS 2 messages are processed as ordinary inbound publishes:

```c
case 1:
	util__decrement_receive_quota(mosq);
	rc = send__puback(mosq, mid, 0, NULL);
	callback__on_message(mosq, &message->msg, properties);
	return rc;

case 2:
	util__decrement_receive_quota(mosq);
	rc = send__pubrec(mosq, mid, 0, NULL);
	message__queue(mosq, message, mosq_md_in);
	return rc;
```

This means the receive path acknowledges and dispatches the message instead of rejecting it with `DISCONNECT 0x9B`.

### The DISCONNECT Mapping Exists But Is Never Triggered Here

The client read dispatcher in `mosquitto-master/lib/read_handle.c` already contains the correct mapping:

```c
}else if(rc == MOSQ_ERR_QOS_NOT_SUPPORTED){
	send__disconnect(mosq, MQTT_RC_QOS_NOT_SUPPORTED, NULL);
}
```

So the missing part is not the reason code definition or the generic disconnect machinery. The missing part is that `handle__publish()` never returns `MOSQ_ERR_QOS_NOT_SUPPORTED` for this unsolicited inbound case.

### Client-Side Subscription State Needed for the Rule Is Not Maintained Here

The MQTT rule depends on whether the message is "not resulting from a subscription".

In the shared internal structure, subscription-tracking fields such as `subs_capacity` and `subs_count` are present only in the broker-side build section of `mosquitto-master/lib/mosquitto_internal.h`:

```c
int subs_capacity;
int subs_count;
```

On the libmosquitto client side, incoming `SUBACK` is parsed and immediately reported through the callback in `mosquitto-master/lib/handle_suback.c`:

```c
callback__on_subscribe(mosq, mid, qos_count, granted_qos, properties);
```

There is no adjacent client-side state update that would let the receive path later determine whether an incoming `PUBLISH` was caused by an active subscription. This matches the observed absence of an unsolicited-message check in the inbound `PUBLISH` handler.

## Runtime Evidence

Two focused repro files were added under `output/`:

```text
output/test_mosquitto_unsolicited_maxqos_client.c
output/test_mosquitto_unsolicited_maxqos_server.py
```

The repro setup is:

```text
1. The fake server sends CONNACK with Maximum QoS = 0.
2. The libmosquitto client does not send any SUBSCRIBE.
3. The fake server immediately sends a QoS 1 PUBLISH.
```

Observed wire behavior:

```text
server:server_publish_hex= 32 12 00 0a 74 65 73 74 2f 74 6f 70 69 63 00 07 00 61 62 63
server:client_packets_hex= ['40 02 00 07']
```

`40 02 00 07` is a normal `PUBACK` for Packet Identifier `7`. The client did not send `DISCONNECT 0x9B`.

Observed client output:

```text
client:on_connect reason=0
client:on_message count=1 topic=test/topic qos=1 payloadlen=3
```

This shows that the client accepted the unsolicited message as ordinary QoS 1 traffic and delivered it to the application callback.

## Inconsistency Reason

The implementation only covers the outbound half of the `Maximum QoS` contract:

```text
CONNACK Maximum QoS received
-> stored in mosq->max_qos
-> checked for client outbound PUBLISH
```

But it does not implement the inbound client-side rule for unsolicited Application Messages:

```text
unsolicited inbound PUBLISH
-> no subscription-origin check
-> no qos > mosq->max_qos check for that case
-> no MOSQ_ERR_QOS_NOT_SUPPORTED
-> no DISCONNECT 0x9B
-> normal PUBACK/PUBREC and callback delivery
```

That is why this is a real protocol inconsistency, but only for the narrower MQTT rule about unsolicited messages. It should not be generalized into a claim that every server-to-client `PUBLISH` above `Maximum QoS` is automatically invalid.

## Impact

A non-compliant or malicious broker can send a client an unsolicited higher-QoS Application Message after advertising a lower `Maximum QoS`, and libmosquitto will accept it as normal inbound traffic.

This can lead to:

```text
missing MQTT 5.0 required DISCONNECT 0x9B
application callbacks receiving unsolicited messages that should have been rejected
wire behavior that looks like ordinary QoS 1 / QoS 2 processing instead of protocol enforcement
```

## Fix Direction

The client receive path should add a targeted MQTT 5.0 check before acknowledging inbound QoS 1 or QoS 2 `PUBLISH` packets.

The fix needs to:

```text
track enough client-side subscription state to determine whether an inbound PUBLISH results from a subscription
when the message is unsolicited and qos > mosq->max_qos, return MOSQ_ERR_QOS_NOT_SUPPORTED
allow read_handle.c to translate that result into DISCONNECT 0x9B
avoid changing the behavior of ordinary subscribed server-to-client publishes unless another rule requires it
```
