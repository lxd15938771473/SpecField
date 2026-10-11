# mbedTLS Does Not Strictly Enforce `PskIdentity.identity<1..>` Inside `OfferedPsks`

## 1. Summary

The inconsistency is not that mbedTLS fails to parse `OfferedPsks`.

The real issue is:

- mbedTLS does check the outer lower bound of `PskIdentity identities<7..2^16-1>`
- but it does not explicitly hard-fail when an individual `PskIdentity.identity` has length `0`

So the mismatch is specifically about the inner rule `identity<1..2^16-1>`.

## 2. RFC Original Text

From [RFC 8446, Section 4.2.11](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11):

```text
     struct {
         opaque identity<1..2^16-1>;
         uint32 obfuscated_ticket_age;
     } PskIdentity;

     opaque PskBinderEntry<32..255>;

     struct {
         PskIdentity identities<7..2^16-1>;
         PskBinderEntry binders<33..2^16-1>;
     } OfferedPsks;
```

The key requirements are:

- each `identity` must be at least 1 byte
- the outer `identities` vector must be at least 7 bytes

## 3. Relevant Code

In [ssl_tls13_server.c](../mbedtls-development/library/ssl_tls13_server.c:542), mbedTLS checks the outer lower bound:

```c
MBEDTLS_SSL_CHK_BUF_READ_PTR(identities, pre_shared_key_ext_end, 7 + 2);
identities_len = MBEDTLS_GET_UINT16_BE(identities, 0);
...
MBEDTLS_SSL_CHK_BUF_READ_PTR(p_identity_len, pre_shared_key_ext_end,
                             identities_len);
```

This means `identities<7..>` is checked.

But when parsing each `PskIdentity`, mbedTLS does not explicitly reject `identity_len == 0`:

```c
MBEDTLS_SSL_CHK_BUF_READ_PTR(p_identity_len, identities_end, 2 + 1 + 4);
identity_len = MBEDTLS_GET_UINT16_BE(p_identity_len, 0);
identity = p_identity_len + 2;
MBEDTLS_SSL_CHK_BUF_READ_PTR(identity, identities_end, identity_len + 4);
obfuscated_ticket_age = MBEDTLS_GET_UINT32_BE(identity, identity_len);
```

Relevant lines:

- [ssl_tls13_server.c:579](../mbedtls-development/library/ssl_tls13_server.c:579)
- [ssl_tls13_server.c:580](../mbedtls-development/library/ssl_tls13_server.c:580)
- [ssl_tls13_server.c:582](../mbedtls-development/library/ssl_tls13_server.c:582)

There is no direct check like:

```c
if (identity_len < 1) {
    return MBEDTLS_ERR_SSL_DECODE_ERROR;
}
```

After that, the parsed entry is passed into identity-matching logic instead of being rejected as a syntax error:

```c
ret = ssl_tls13_offered_psks_check_identity_match(
    ssl, identity, identity_len, obfuscated_ticket_age,
    &psk->type, &session);
if (ret != SSL_TLS1_3_PSK_IDENTITY_MATCH) {
    continue;
}
```

See [ssl_tls13_server.c:597](../mbedtls-development/library/ssl_tls13_server.c:597) and [ssl_tls13_server.c:600](../mbedtls-development/library/ssl_tls13_server.c:600).

## 4. Where the Mismatch Is

The RFC requires:

- every `PskIdentity.identity` must satisfy `identity<1..2^16-1>`

mbedTLS actually does:

- check that the overall `identities` vector is large enough
- check that parsing stays within buffer bounds
- but not explicitly reject an individual zero-length `identity` as soon as it is parsed

So the inconsistency is:

- outer size constraint is enforced
- inner per-item lower-bound constraint is not strictly enforced

## 5. Conclusion

This issue should be described precisely as:

- mbedTLS checks `PskIdentity identities<7..2^16-1>`
- mbedTLS does not strictly hard-fail each invalid `PskIdentity.identity<1..2^16-1>`
