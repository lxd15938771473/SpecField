# ID271 Runtime Recheck: ServerHello Extension Allowlist Constraints

## Summary

This recheck concludes that the current wolfSSL build does not strictly reject **additional unknown extensions** in `ServerHello`. We injected a `ServerHello` containing the unknown extension `0xFAFA` into the client. It did not fail immediately or send a fatal alert; it remained in `WANT_READ`.  

This shows that the `ServerHello MUST only include ...` requirement corresponding to `ID271` is not strictly enforced. Retaining the classification of "partially satisfied" is therefore justified; it should not be upgraded to "satisfied".

## 1. Scope of the Recheck

This recheck concerns the following item in `201-300/compare_wolfssl_201_300.md`:

- `ID271`: `extensions must only include` `in ServerHello`

The question is:

- Whether the wolfSSL client immediately rejects the message and aborts the handshake when `ServerHello` contains an **additional unknown extension outside the allowlist**.

## 2. RFC 8446 Specification Text

Specification source: `document/TLS1.3.txt`

### 2.1 ServerHello Allowlist Requirement

`document/TLS1.3.txt:1743-1751`

> extensions: A list of extensions. The ServerHello MUST only include  
> extensions which are required to establish the cryptographic  
> context and negotiate the protocol version. All TLS 1.3  
> ServerHello messages MUST contain the "supported_versions"  
> extension. Current ServerHello messages additionally contain  
> either the "pre_shared_key" extension or the "key_share"  
> extension, or both (when using a PSK with (EC)DHE key  
> establishment). Other extensions (see Section 4.2) are sent  
> separately in the EncryptedExtensions message.

This passage corresponds to `ID271`. Its meaning is clear: TLS 1.3 `ServerHello` uses a closed allowlist, not an unrestricted extension container.

### 2.2 Handling Responses with Unrequested Extensions

`document/TLS1.3.txt:1988-1992`

> Implementations MUST NOT send extension responses if the remote  
> endpoint did not send the corresponding extension requests, with the  
> exception of the "cookie" extension in the HelloRetryRequest. Upon  
> receiving such an extension, an endpoint MUST abort the handshake  
> with an "unsupported_extension" alert.

This means that if the server returns an extension in `ServerHello` that the client did not request, the receiver must abort the handshake.

### 2.3 Additional Alert Definitions

`document/TLS1.3.txt:4995-4999`

> unsupported_extension: Sent by endpoints receiving any handshake  
> message containing an extension known to be prohibited for  
> inclusion in the given handshake message, or including any  
> extensions in a ServerHello or Certificate not first offered in  
> the corresponding ClientHello or CertificateRequest.

This further establishes that the specification expects rejection when `ServerHello` contains an extension not previously offered in `ClientHello`.

## 3. wolfSSL Source Analysis

Relevant files:

- `wolfssl-master/src/tls.c`
- `wolfssl-master/src/tls13.c`
- `wolfssl-master/src/internal.c`

### 3.1 Parsing Entry Point

`wolfssl-master/src/tls13.c:5428-5430`

```c
if ((ret = TLSX_ParseVersion(ssl, input + args->idx,
    args->totalExtSz, *extMsgType, &foundVersion))) {
    return ret;
}
```

After parsing `supported_versions`, the code proceeds as follows:

`wolfssl-master/src/tls13.c:5505-5507`

```c
if (args->totalExtSz > 0 && IsAtLeastTLSv1_3(ssl->version)) {
    ret = TLSX_Parse(ssl, input + args->idx, args->totalExtSz,
        *extMsgType, NULL);
```

Thus, `ServerHello` extensions ultimately enter the common `TLSX_Parse(...)` function.

### 3.2 Restrictions on Recognized Extensions

For example, `pre_shared_key`:

`wolfssl-master/src/tls.c:17442-17445`

```c
if (msgType != client_hello &&
    msgType != server_hello) {
    WOLFSSL_ERROR_VERBOSE(EXT_NOT_ALLOWED);
    return EXT_NOT_ALLOWED;
}
```

This shows that wolfSSL does impose message-type restrictions on many **recognized extensions**.

### 3.3 Default Handling of Unknown Extensions

The critical code is:

`wolfssl-master/src/tls.c:17668-17670`

```c
default:
    WOLFSSL_MSG("Unknown TLS extension type");
```

This branch does not perform any of the following:

- `return EXT_NOT_ALLOWED`
- `SendAlert(...)`
- Any other action that aborts the handshake

It only logs the event and continues parsing subsequent extensions.  
For **unknown extensions** in `ServerHello`, wolfSSL therefore defaults to ignoring the extension and continuing, rather than rejecting it based on the allowlist.

### 3.4 Alert Mapping

`wolfssl-master/src/internal.c:35347-35361`

```c
int TranslateErrorToAlert(int err)
{
    switch (err) {
        case WC_NO_ERR_TRACE(BUFFER_ERROR):
            return decode_error;
        case WC_NO_ERR_TRACE(EXT_NOT_ALLOWED):
        case WC_NO_ERR_TRACE(PEER_KEY_ERROR):
        case WC_NO_ERR_TRACE(ECC_PEERKEY_ERROR):
        case WC_NO_ERR_TRACE(BAD_KEY_SHARE_DATA):
        case WC_NO_ERR_TRACE(PSK_KEY_ERROR):
        case WC_NO_ERR_TRACE(INVALID_PARAMETER):
        case WC_NO_ERR_TRACE(HRR_COOKIE_ERROR):
        case WC_NO_ERR_TRACE(BAD_BINDER):
        case WC_NO_ERR_TRACE(DUPLICATE_TLS_EXT_E):
            return illegal_parameter;
```

This shows that even when wolfSSL reaches `EXT_NOT_ALLOWED`, it generally maps that error to `illegal_parameter` rather than `unsupported_extension`.  
The more significant finding in this recheck occurs earlier: an unknown extension never enters the rejection path at all.

## 4. Runtime Reproduction

Reproducer: `201-300/test_tls13_ext_whitelist_269_271.c`

Runtime log: `201-300/runtime_269_271_whitelist_check.log`

### 4.1 Constructed Input

`201-300/test_tls13_ext_whitelist_269_271.c:150-170`

```c
static const unsigned char shUnknownExt[] = {
    ...
    0xfa, 0xfa, 0x00, 0x02, 0x03, 0x04
};
```

The test constructs a TLS 1.3 `ServerHello` as follows:

- Insert the unknown extension type `0xFAFA` into the extension block.
- Fix the client's key share to `secp256r1`.

This avoids misclassifying a key-group mismatch as an extension error.

### 4.2 Runtime Results

Executed:

```bash
gcc 201-300/test_tls13_ext_whitelist_269_271.c -Ibuild/wolfssl-weakciphers -Iwolfssl-master -Lbuild/wolfssl-weakciphers -lwolfssl -o 201-300/test_tls13_ext_whitelist_269_271.exe
201-300/test_tls13_ext_whitelist_269_271.exe
```

Relevant log excerpt:

```text
=== ID271-like: ServerHello + unknown extension ===
  wolfSSL_UseKeyShare(secp256r1)=1
  result: pending (want io), lastErr=2
  alert.last_tx: level=-1 code=-1
  alert.last_rx: level=-1 code=-1
```

Interpretation:

- No fatal error occurred.
- No fatal alert was sent.
- The client remained in `WOLFSSL_ERROR_WANT_READ`.

In the current build, the wolfSSL client therefore **continues waiting for subsequent handshake data** after receiving a `ServerHello` with an additional unknown extension, rather than aborting immediately.

## 5. Conclusion

After an additional unknown extension was inserted into `ServerHello`, the wolfSSL client did not reject it immediately.  
This is inconsistent with the closed-allowlist semantics of RFC 8446's `ServerHello MUST only include ...` requirement.

More precisely:

- wolfSSL imposes message-type constraints on many **recognized extensions**.
- For **unknown extensions** in `ServerHello`, however, it defaults to ignoring them and continuing.
- It therefore does not implement the strict extension-allowlist rejection required by RFC 8446.

Retaining the "partially satisfied" classification for `ID271` is therefore appropriate.

