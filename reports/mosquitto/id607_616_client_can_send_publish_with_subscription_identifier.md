# Client Can Send Forbidden Subscription Identifier on Client-to-Server PUBLISH

## Conclusion

Mosquitto is only partially compliant for items `607` and `616`.

The broker receive path rejects a client-to-server `PUBLISH` that carries
`Subscription Identifier`, which is correct. However, `libmosquitto` still lets
an application construct such a `PUBLISH` and send it onto the wire.

## MQTT Standard Requirement

- Standard: `MQTT 5.0`
- Section: `3.3.4 PUBLISH Actions`

Normative requirement:

```text
A PUBLISH packet sent from a Client to a Server MUST NOT contain a
Subscription Identifier.
```

That means:

- this is a sender-side prohibition, not just a receiver-side check
- a client library must not help an application emit that property on an
  outbound client-to-server `PUBLISH`
- a server may still reject it defensively, but that does not make the send
  path compliant

## Relevant Code

### Broker Receive Path Correctly Rejects the Property

`src/property_broker.c` explicitly treats `MQTT_PROP_SUBSCRIPTION_IDENTIFIER`
as a protocol error on inbound broker-side `PUBLISH` processing unless the peer
is a bridge:

```c
case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
	if(!is_bridge || mosquitto_property_varint_value(p) == 0){
		return MOSQ_ERR_PROTOCOL;
	}
	p_prev = p;
	p = mosquitto_property_next(p);
	break;
```

Then `src/handle_publish.c` propagates that error as broker-side protocol
failure handling:

```c
rc = property__process_publish(base_msg, &properties, &topic_alias, &message_expiry_interval, context->bridge);
if(rc){
	mosquitto_property_free_all(&properties);
	db__msg_store_free(base_msg);
	return MOSQ_ERR_PROTOCOL;
}
```

So the broker side does implement the prohibition.

### Client Send Path Still Emits the Forbidden Property

The client API lets the application build a `Subscription Identifier` property:

```c
BROKER_EXPORT int mosquitto_property_add_varint(mosquitto_property **proplist, int identifier, uint32_t value)
{
	if(!proplist || value > MQTT_MAX_PAYLOAD){
		return MOSQ_ERR_INVAL;
	}
	if(identifier != MQTT_PROP_SUBSCRIPTION_IDENTIFIER){
		return MOSQ_ERR_INVAL;
	}
	...
	prop->value.varint = value;
	...
}
```

`mosquitto_publish_v5()` accepts outbound `PUBLISH` properties after only
generic property checks:

```c
if(properties){
	...
	rc = mosquitto_property_check_all(CMD_PUBLISH, outgoing_properties);
	if(rc){
		return rc;
	}
}
```

Those generic checks allow `Subscription Identifier` on command `PUBLISH`:

```c
case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
	if(command != CMD_PUBLISH && command != CMD_SUBSCRIBE){
		return MOSQ_ERR_PROTOCOL;
	}
	break;
```

The client send path therefore has no role-sensitive rule saying
"client-to-server PUBLISH must not contain this property".

The reproduction client shows the exact application-facing call sequence:

```c
prc = mosquitto_property_add_varint(&pub_props, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 7);
...
prc = mosquitto_publish_v5(mosq, NULL, "sid/forbidden", 5, "hello", 0, false, pub_props);
```

## Runtime Evidence

Artifacts used:

```text
test-mosquitto/v500/601-650/repro_publish_subscription_id_client.c
test-mosquitto/v500/601-650/repro_publish_subscription_id_server.py
```

Test idea:

```text
1. Start a fake MQTT 5 server.
2. Accept the client's CONNECT and reply with success CONNACK.
3. Let the client publish using a caller-supplied Subscription Identifier.
4. Capture the next packet sent by the client.
```

Observed output:

```text
PUBLISH_RC 0
DISCONNECT_RC 7
CONNECT_HEX 102200044d5154540502001e0321001400127369642d7075626c6973682d636c69656e74
NEXT_HEX 3017000d7369642f666f7262696464656e020b0768656c6c6f
```

What this shows:

- `PUBLISH_RC 0` means `libmosquitto` accepted the outbound request
- `0x0b` inside `NEXT_HEX` is `Subscription Identifier`
- the following value `0x07` shows the client actually sent identifier `7`
- `DISCONNECT_RC 7` is the later connection failure after the peer rejects the
  invalid packet

That means the non-compliance is real on the client send path, not just
theoretical from source inspection.

## Why This Is Partial

Implemented:

- broker receive-side validation rejects the forbidden property

Missing:

- client library send-side validation does not block applications from sending
  the forbidden property

So the implementation is not fully unsatisfied across all components, but it is
also not compliant end-to-end for items `607` and `616`.
