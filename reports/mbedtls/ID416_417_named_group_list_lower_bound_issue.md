# mbedTLS Does Not Strictly Enforce the `NamedGroupList` Lower Bound

## 1. Summary

The issue is about the `supported_groups` extension in TLS 1.3, specifically the `NamedGroupList` structure.

The core mismatch is:

- the TLS 1.3 specification requires `named_group_list<2..2^16-1>`
- mbedTLS client-side construction does not generate an empty list
- but mbedTLS server-side parsing accepts `named_group_list_len = 0`

So the implementation does not fully enforce the lower bound `2` on the receiving side.

This is the common underlying issue behind the related findings.

## 2. RFC Original Text

From [RFC 8446, Section 4.2.7](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7):

```text
   When sent by the client, the "supported_groups" extension indicates
   the named groups which the client supports, ordered from most
   preferred to least preferred.
```

The `NamedGroupList` structure is defined in [RFC 8446, Section 4.2.7](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7):

```text
      struct {
          NamedGroup named_group_list<2..2^16-1>;
      } NamedGroupList;
```

This means:

- `named_group_list` is a byte vector
- each `NamedGroup` occupies 2 bytes
- therefore the minimum valid length is 2 bytes, which corresponds to one complete group entry

So:

- `named_group_list_len = 0` is invalid
- `named_group_list_len = 1` is also invalid
- `named_group_list_len = 2` is the minimum valid value

## 3. Relevant mbedTLS Code

### 3.1 Client-side construction does not emit an empty list

In [ssl_client.c](../mbedtls-development/library/ssl_client.c:216), `ssl_write_supported_groups_ext()` constructs the `supported_groups` extension.

After collecting proposed groups, it computes the list length:

```c
    /* Length of named_group_list */
    named_group_list_len = (size_t) (p - named_group_list);
    if (named_group_list_len == 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("No group available."));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
```

Relevant lines:

- [ssl_client.c:286](../mbedtls-development/library/ssl_client.c:286)
- [ssl_client.c:288](../mbedtls-development/library/ssl_client.c:288)

This means the sending side does not deliberately produce an empty `named_group_list`.

### 3.2 Server-side parsing does not explicitly reject `named_group_list_len = 0`

In [ssl_tls13_server.c](../mbedtls-development/library/ssl_tls13_server.c:832), `ssl_tls13_parse_supported_groups_ext()` parses the received list:

```c
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    named_group_list_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, named_group_list_len);
    named_group_list_end = p + named_group_list_len;
    ssl->handshake->hrr_selected_group = 0;

    while (p < named_group_list_end) {
        uint16_t named_group;
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, named_group_list_end, 2);
        named_group = MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        ...
    }
```

Relevant lines:

- [ssl_tls13_server.c:841](../mbedtls-development/library/ssl_tls13_server.c:841)
- [ssl_tls13_server.c:842](../mbedtls-development/library/ssl_tls13_server.c:842)
- [ssl_tls13_server.c:844](../mbedtls-development/library/ssl_tls13_server.c:844)
- [ssl_tls13_server.c:848](../mbedtls-development/library/ssl_tls13_server.c:848)
- [ssl_tls13_server.c:850](../mbedtls-development/library/ssl_tls13_server.c:850)

What is missing is an explicit check such as:

```c
if (named_group_list_len < 2) {
    return MBEDTLS_ERR_SSL_DECODE_ERROR;
}
```

Because there is no such check:

- `named_group_list_len = 0` makes `named_group_list_end == p`
- the loop body is skipped
- the function returns success

So the empty list is accepted.

## 4. Dynamic Test Result

The test script is [test_named_group_list_behavior.py](test_named_group_list_behavior.py:1).

It captures a real TLS 1.3 `ClientHello` and mutates only the `supported_groups` extension:

- case 1: set `named_group_list_len = 0`
- case 2: set `named_group_list_len = 1`

Observed results:

- reference case: handshake succeeds
- `named_group_list_len = 0`: handshake still succeeds
- `named_group_list_len = 1`: handshake fails with `decode_error`

This shows the exact boundary behavior:

- the server accepts an empty list
- the server rejects a one-byte truncated list only when it later tries to read a full 2-byte `NamedGroup`

## 5. Why This Is Inconsistent with the Specification

The RFC lower bound is `named_group_list<2..2^16-1>`.

That means:

- the parser should reject `0`
- the parser should reject `1`
- acceptance should begin only at `2`

mbedTLS does not enforce that rule directly. Instead, it behaves like this:

- `0`: accepted
- `1`: rejected later during element parsing
- `2` and above: parsed normally

So the implementation does not strictly enforce the lower bound at the structure boundary.

The key inconsistency is not that mbedTLS never checks lengths at all. It does check bounds while reading individual elements. The problem is that the structure-level minimum length is not enforced before iteration begins.

## 6. Relationship Between the Related Findings

These two findings are closely related and reflect the same underlying issue from two angles:

- one finding focuses on the missing strict enforcement of the minimum length rule
- the other focuses on the behavioral asymmetry: the sender avoids empty lists, but the receiver accepts them

So they are not independent bugs. They are two descriptions of the same lower-bound enforcement gap.

## 7. Conclusion

mbedTLS does not fully implement the TLS 1.3 lower-bound requirement for `NamedGroupList`:

- the client-side constructor does not emit an empty `named_group_list`
- the server-side parser nevertheless accepts `named_group_list_len = 0`

Therefore, the implementation is more permissive than the RFC structure definition:

```text
NamedGroup named_group_list<2..2^16-1>
```

That is the clearest description of the underlying issue.
