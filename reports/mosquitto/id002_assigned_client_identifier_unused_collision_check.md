# Assigned Client Identifier Lacks an Explicit Unused-Value Collision Check

## Conclusion

Mosquitto handles zero-length MQTT v5 Client Identifiers by generating a random 128-bit identifier and returning it in the CONNACK as the Assigned Client Identifier.

The implementation is practically very unlikely to collide, but it does not explicitly check whether the generated identifier is already used by another current Session. If such a collision occurs, the generic same-ClientID takeover path is used instead of regenerating a different unused identifier. For strict MQTT v5.0 conformance, this is only a partial match.

## MQTT Specification Requirement

Standard reference: [MQTT Version 5.0 OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)

Relevant sections:

- `3.1.3.1 Client Identifier (ClientID)`
- `3.2.2.3.7 Assigned Client Identifier`
- related requirement IDs: `MQTT-3.1.3-6`, `MQTT-3.2.2-16`

The relevant normative requirement can be organized into two parts.

First, MQTT v5.0 allows server-assigned Client Identifiers for the zero-length case:

```text
If the Client supplies a zero-byte Client Identifier, the Server MAY
allow this Client to supply a Client Identifier that it assigns to
that Client. The Server MUST then process the CONNECT packet as if the
Client had provided that unique Client Identifier.
```

That means:

- a zero-byte Client Identifier is not automatically invalid
- the server is allowed to assign an identifier on the client's behalf
- once assigned, that identifier must be treated as the actual Client Identifier for the connection
- the assigned identifier must be unique in the sense required by the specification

Second, if the server accepts that connection, it must also report the assigned value in CONNACK:

```text
If the Server accepts a connection with a zero length Client
Identifier, the Server MUST respond with a CONNACK containing an
Assigned Client Identifier. The Assigned Client Identifier MUST be a
new Client Identifier not used by any other Session currently in the
Server.
```

That means:

- the server must include the `Assigned Client Identifier` property in `CONNACK`
- the assigned value must be new at assignment time
- the assigned value must not already belong to any current Session in the broker
- generating a random identifier is not, by itself, enough for strict conformance
- the implementation must ensure "unused by any other Session" before accepting the identifier

## Relevant Code

### Random Assigned Client Identifier Generation

`mosquitto-master/src/handle_connect.c` generates the automatic Client Identifier
with 16 random bytes:

```c
static char *clientid_gen(uint16_t *idlen, const char *auto_id_prefix, uint16_t auto_id_prefix_len)
{
	char *clientid;
	uint8_t rnd[16];

	if(mosquitto_getrandom(rnd, 16)){
		return NULL;
	}
	...
}
```

When a zero-length Client Identifier is accepted, the generated value is
assigned directly:

```c
*clientid = clientid_gen(&(uint16_t){0}, context->listener->security_options->auto_id_prefix,
		context->listener->security_options->auto_id_prefix_len);
if(*clientid == NULL){
	return MOSQ_ERR_NOMEM;
}
context->assigned_id = true;
```

This code creates a strong random identifier, but it does not perform a lookup
against the current Session table before accepting the generated value.

### CONNACK Assigned Client Identifier Property

Later, if `context->assigned_id` is true, Mosquitto adds the Assigned Client
Identifier property to the CONNACK:

```c
if(context->assigned_id){
	if(mosquitto_property_add_string(&connack_props, MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER, context->id)){
		rc = MOSQ_ERR_NOMEM;
		goto error;
	}
}
```

This satisfies the CONNACK property part of the requirement.

### Generic Same-ClientID Lookup and Takeover

Mosquitto does have a lookup for an existing context with the same Client
Identifier:

```c
HASH_FIND(hh_id, db.contexts_by_id, context->id, strlen(context->id), found_context);
if(found_context){
	...
	if(found_context->protocol == mosq_p_mqtt5){
		send__disconnect(found_context, MQTT_RC_SESSION_TAKEN_OVER, NULL);
	}
	do_disconnect(found_context, MOSQ_ERR_SESSION_TAKEN_OVER);
}
```

This lookup is part of the normal same-ClientID reconnect/takeover logic. It
does not regenerate the automatically assigned identifier when the generated
value is already in use.

## Why This Is Inconsistent

The specification requires the assigned value to be new and not used by any
current Session. That implies the implementation should verify the candidate
identifier against the active Session table, and if it is already present,
generate another one.

Mosquitto instead relies on a 128-bit random value and then processes any
duplicate through the generic ClientID takeover path. In the extremely unlikely
collision case:

- the generated Assigned Client Identifier is already used
- Mosquitto does not retry generation
- the older Session with the same Client Identifier can be taken over
- the generated value was therefore not proven to be unused at assignment time

This is why the implementation is practically safe but not a complete strict
match for the "new and unused" requirement.

## Runtime Evidence

There is currently no stable standalone runtime reproducer in this directory
that deterministically triggers an actual Assigned Client Identifier collision.
That is expected, because the implementation uses a randomly generated 128-bit
identifier and the bug is specifically the absence of an explicit collision
check, not a routinely observable collision event.

The runtime-relevant evidence is therefore the concrete execution path:

```text
zero-byte Client Identifier accepted
-> clientid_gen(...) generates a candidate identifier
-> context->assigned_id = true
-> CONNACK includes Assigned Client Identifier
-> no lookup/retry loop proves the generated identifier is unused
-> any duplicate would fall into the generic same-ClientID takeover path
```

That means:

- the implementation definitely exercises server-assigned Client Identifier handling at runtime
- the missing behavior is the absence of a runtime uniqueness verification step
- this issue is confirmed by control-flow evidence in the live connection path, even though a random collision is not practical to force in an ordinary test run

## Suggested Fix

After generating an automatic Client Identifier, Mosquitto should check
`db.contexts_by_id` before accepting it:

```c
do {
	clientid = clientid_gen(...);
	HASH_FIND(hh_id, db.contexts_by_id, clientid, strlen(clientid), found_context);
} while(found_context);
```

A production fix should also bound the retry loop and handle
allocation/random-source failures cleanly. The important point is that
same-ClientID takeover should not be used as the collision handling mechanism
for a server-assigned identifier.
