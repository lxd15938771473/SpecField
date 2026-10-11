# ID253: Client Certificate Extensions Do Not Consistently Correspond to the Offered List

## Conclusion

`ID253` asks whether extensions in a client-sent `Certificate` message must correspond to the extension list previously supplied by the server in `CertificateRequest`.

The specification requires this correspondence. Although the current wolfSSL code parses extensions in `CertificateEntry`, the current build does not show a reliably active validation path that rejects an extension if it did not previously appear in `CertificateRequest`. This requirement therefore cannot be considered strictly satisfied.

## Specification Text

The relevant specification passage is in [TLS1.3.txt](/d:/project/conditionFuzzing/document/TLS1.3.txt:3599):

- [TLS1.3.txt:3599](/d:/project/conditionFuzzing/document/TLS1.3.txt:3599)
- [TLS1.3.txt:3600](/d:/project/conditionFuzzing/document/TLS1.3.txt:3600)
- [TLS1.3.txt:3601](/d:/project/conditionFuzzing/document/TLS1.3.txt:3601)
- [TLS1.3.txt:3602](/d:/project/conditionFuzzing/document/TLS1.3.txt:3602)
- [TLS1.3.txt:3603](/d:/project/conditionFuzzing/document/TLS1.3.txt:3603)
- [TLS1.3.txt:3604](/d:/project/conditionFuzzing/document/TLS1.3.txt:3604)
- [TLS1.3.txt:3605](/d:/project/conditionFuzzing/document/TLS1.3.txt:3605)
- [TLS1.3.txt:3606](/d:/project/conditionFuzzing/document/TLS1.3.txt:3606)
- [TLS1.3.txt:3607](/d:/project/conditionFuzzing/document/TLS1.3.txt:3607)
- [TLS1.3.txt:3608](/d:/project/conditionFuzzing/document/TLS1.3.txt:3608)

The surrounding text is as follows:

```text
extensions:  A set of extension values for the CertificateEntry.  The
"Extension" format is defined in Section 4.2.  Valid extensions
for server certificates at present include the OCSP Status
extension [RFC6066] and the SignedCertificateTimestamp extension
[RFC6962]; future extensions may be defined for this message as
well.  Extensions in the Certificate message from the server MUST
correspond to ones from the ClientHello message.  Extensions in
the Certificate message from the client MUST correspond to
extensions in the CertificateRequest message from the server.  If
an extension applies to the entire chain, it SHOULD be included in
the first CertificateEntry.
```

The complete statement directly corresponding to `ID253` is:

`Extensions in the Certificate message from the client MUST correspond to extensions in the CertificateRequest message from the server.`

The key phrase is `MUST correspond`.  
The specification requires more than well-formed extensions: extensions in the client certificate must belong to the set previously supplied by the server in `CertificateRequest`.

## wolfSSL Source Code

### 1. CertificateEntry Extensions Are Parsed

In [internal.c:15920](/d:/project/conditionFuzzing/wolfssl-master/src/internal.c:15920) through [internal.c:15936](/d:/project/conditionFuzzing/wolfssl-master/src/internal.c:15936):

```c
args->exts[args->totalCerts].length = extSz;
args->exts[args->totalCerts].buffer = input + args->idx;
args->idx += extSz;
listSz -= extSz + OPAQUE16_LEN;
WOLFSSL_MSG_EX("\tParsing %d bytes of cert extensions",
    args->exts[args->totalCerts].length);
#if !defined(NO_TLS)
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST)
ssl->response_idx = args->totalCerts;
#endif
ret = TLSX_Parse(ssl, args->exts[args->totalCerts].buffer,
    (word16)args->exts[args->totalCerts].length,
    certificate, NULL);
#endif /* !NO_TLS */
if (ret < 0) {
    WOLFSSL_ERROR_VERBOSE(ret);
    ERROR_OUT(ret, exit_ppc);
}
```

This code shows that:

- Extensions in `CertificateEntry` are not ignored.
- wolfSSL first extracts the extension block from each certificate entry.
- It then passes the block to the common `TLSX_Parse(..., msgType=certificate, ...)` entry point.

The question is therefore whether parsing enforces the required correspondence with the offered list, rather than whether parsing occurs at all.

### 2. TLSX_Parse Is the Common Extension Parsing Entry Point

In [tls.c:16999](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:16999) through [tls.c:17020](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17020):

```c
int TLSX_Parse(WOLFSSL* ssl, const byte* input, word16 length, byte msgType,
                                                                 Suites *suites)
{
    int ret = 0;
    word16 offset = 0;
    byte isRequest = (msgType == client_hello ||
                      msgType == certificate_request);
...
    byte seenType[SEMAPHORE_SIZE];  /* Seen known extensions. */

    if (!ssl || !input || (isRequest && !suites))
        return BAD_FUNC_ARG;

    /* No known extensions seen yet. */
    XMEMSET(seenType, 0, sizeof(seenType));
```

The relevant distinction is:

- `isRequest` treats only `client_hello` and `certificate_request` as request messages.
- `certificate` is not included in `isRequest` here.

This means that wolfSSL follows the response/receiver path when parsing `Certificate` extensions, rather than the request path.

### 3. status_request Is Allowed into the Parsing Branch for certificate Messages

In [tls.c:17230](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17230) through [tls.c:17250](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17250):

```c
case TLSX_STATUS_REQUEST:
    WOLFSSL_MSG("Certificate Status Request extension received");
...
#ifdef WOLFSSL_TLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        if (msgType != client_hello &&
            msgType != certificate_request &&
            msgType != certificate)
            return EXT_NOT_ALLOWED;
    }
    else
#endif
    {
        if (msgType != client_hello &&
            msgType != server_hello)
            return EXT_NOT_ALLOWED;
    }
    ret = CSR_PARSE(ssl, input + offset, size, isRequest);
```

This code shows two things:

- TLS 1.3 permits the `status_request` extension in a `certificate` message.
- Allowing that extension type in this message does not establish that it was checked against the server's earlier `CertificateRequest` list.

This checks whether the extension is allowed in this message, rather than whether it belongs to the offered list.

### 4. With the Relevant Feature Enabled, wolfSSL Has Logic to Reject Unrequested Extensions

In [tls.c:3657](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3657) through [tls.c:3705](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3705):

```c
static int TLSX_CSR_Parse(WOLFSSL* ssl, const byte* input, word16 length,
                          byte isRequest)
{
...
    if (!isRequest) {
#ifndef NO_WOLFSSL_CLIENT
        extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST);
        csr = extension ? (CertificateStatusRequest*)extension->data : NULL;

        if (!csr) {
            /* look at context level */
            extension = TLSX_Find(ssl->ctx->extensions, TLSX_STATUS_REQUEST);
            csr = extension ? (CertificateStatusRequest*)extension->data : NULL;

            if (!csr) /* unexpected extension */
                return TLSX_HandleUnsupportedExtension(ssl);

            /* enable extension at ssl level */
            ret = TLSX_UseCertificateStatusRequest(&ssl->extensions,
                                     csr->status_type, csr->options, ssl,
                                     ssl->heap, ssl->devId);
```

The critical logic is:

- When parsing `status_request` in `Certificate`, wolfSSL first checks whether the local endpoint already has a record of this extension.
- Semantically, that existing record means the extension appeared earlier through negotiation or configuration.
- If no record is found, wolfSSL treats it as an `unexpected extension`.

The actual rejection is defined in [tls.c:1712](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:1712) through [tls.c:1718](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:1718):

```c
int TLSX_HandleUnsupportedExtension(WOLFSSL* ssl)
{
    SendAlert(ssl, alert_fatal, unsupported_extension);
    WOLFSSL_ERROR_VERBOSE(UNSUPPORTED_EXTENSION);
    return UNSUPPORTED_EXTENSION;
}
```

This path is consistent with the specification's intent:

- If the client certificate contains an extension that was not previously requested,
- it should be rejected.

### 5. This Validation Path Is Inactive in the Current Build

In [tls.c:3992](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3992) through [tls.c:3995](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3995):

```c
#define CSR_FREE_ALL(data, heap) WC_DO_NOTHING
#define CSR_GET_SIZE(a, b)    0
#define CSR_WRITE(a, b, c)    0
#define CSR_PARSE(a, b, c, d) 0
```

This shows that in the current default build:

- `CSR_PARSE` is not an actual function.
- It is replaced by a macro that directly returns `0`.
- In other words, it succeeds immediately without performing validation.

The current build configuration also shows this in [options.h:81](/d:/project/conditionFuzzing/build/wolfssl-default/wolfssl/options.h:81) through [options.h:150](/d:/project/conditionFuzzing/build/wolfssl-default/wolfssl/options.h:150):

```c
#undef HAVE_CERTIFICATE_STATUS_REQUEST
/* #undef HAVE_CERTIFICATE_STATUS_REQUEST */
...
#undef HAVE_OCSP
/* #undef HAVE_OCSP */
...
#undef HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS
```

In other words:

- The extension framework is present.
- The dedicated validation logic for `Certificate status request` is not compiled in.

### 6. Unrecognized Extensions Are Logged Rather Than Rejected by Default

In [tls.c:17668](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17668) through [tls.c:17670](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17670):

```c
default:
    WOLFSSL_MSG("Unknown TLS extension type");
```

This means that:

- For an unknown extension, the current implementation only writes a log entry by default.
- It does not automatically reject the extension because it was absent from the `CertificateRequest` list.

## Why the Behavior Is Inconsistent with the Specification

The specification requires:

- Extensions in the client `Certificate` must correspond to the extension list previously supplied by the server in `CertificateRequest`.

The current implementation behaves more like this:

- Extensions in `CertificateEntry` are processed by the common parser.
- Known extensions are checked for whether they may appear in a `certificate` message.
- Whether an extension was previously requested may be checked only when the relevant feature is enabled.
- In the current build, this additional validation path is excluded by macros.
- Unknown extensions are not uniformly rejected for being absent from the preceding list either.

The root cause of the inconsistency is therefore:

- The specification requires checking whether the extension belongs to the list previously supplied by the server.
- In the current build, wolfSSL primarily checks whether the extension type and message location are generally allowed, without making correspondence with the offered list a mandatory condition.

## Scope of the Evidence

The current minimal probe is [test_id253_254_tlsx_parse_runtime.c](/d:/project/conditionFuzzing/201-300/test_id253_254_tlsx_parse_runtime.c:1).

With the current default static build, this probe shows that:

- The client object can be initialized.
- Server object initialization fails.

Therefore:

- `ID254` has direct runtime evidence.
- The assessment of `ID253` here is primarily based on source paths and parsing flow.

This is why the `ID253` analysis focuses on source code rather than drawing a conclusion directly from runtime results as `ID254` does.
