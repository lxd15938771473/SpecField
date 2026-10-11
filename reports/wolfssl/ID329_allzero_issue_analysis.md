# ID329 Issue Analysis: X25519/X448 All-Zero Shared-Secret Check

## Issue Overview

The specification semantics corresponding to ID329 are:

- Variable: `key_exchange`
- Action: `invalid if value check fails`
- Meaning: for X25519/X448, if the computed Diffie-Hellman shared secret is all zeros, the implementation must treat it as invalid and abort processing.

This analysis focuses on whether wolfSSL performs that check unconditionally in the default build.

## Specification Text

Specification file: `document/TLS1.3.txt`

Relevant section: `7.4.2 Elliptic Curve Diffie-Hellman`

The original English text is:

> For these curves, implementations SHOULD use the approach specified
> in [RFC7748] to calculate the Diffie-Hellman shared secret.
> Implementations MUST check whether the computed Diffie-Hellman shared
> secret is the all-zero value and abort if so, as described in
> Section 6 of [RFC7748].

Two points follow directly from this passage:

1. `SHOULD use the approach specified in [RFC7748]` is a recommendation.
2. `MUST check whether ... shared secret is the all-zero value and abort if so` is mandatory.

Checking for an all-zero shared secret is therefore a mandatory specification requirement, not an optional optimization.

## wolfSSL Code Behavior

### 1. X25519 Path

File: `wolfssl-master/wolfcrypt/src/curve25519.c`

The relevant implementation is inside the following conditional compilation block:

- `curve25519.c:754`
- `curve25519.c:762`

The core logic is:

- First compute the shared secret using `curve25519(...)`.
- Iterate over the output bytes and check whether they are all zero only if `WOLFSSL_ECDHX_SHARED_NOT_ZERO` is defined.
- Return `ECC_OUT_OF_RANGE_E` if all bytes are zero.
- If the macro is not defined, copy the result directly into the output buffer and return success.

### 2. X448 Path

File: `wolfssl-master/wolfcrypt/src/curve448.c`

The relevant implementation is:

- `curve448.c:36`
- `curve448.c:179`
- `curve448.c:186`

The file header at `curve448.c:36` explicitly states:

> `WOLFSSL_ECDHX_SHARED_NOT_ZERO: Check ECDH shared secret != 0   default: off`

This shows that wolfSSL's all-zero shared-secret check for X448 is also controlled by `WOLFSSL_ECDHX_SHARED_NOT_ZERO` and is disabled by default.

### 3. Error Code

File: `wolfssl-master/wolfssl/wolfcrypt/error-crypt.h:199`

The corresponding error code is defined as:

- `ECC_OUT_OF_RANGE_E = -217`

This matches the runtime result when the check is enabled.

## Runtime Verification Results

Runtime reproduction records:

- `301-400/ID329_allzero_runtime_recheck.md`
- `301-400/id329_allzero_poc.c`

The reproduction results are as follows.

### Default Build: `WOLFSSL_ECDHX_SHARED_NOT_ZERO` Disabled

Runtime output:

```text
X25519 ret=0, out_len=32, all_zero=1
X448 ret=0, out_len=56, all_zero=1
```

Interpretation:

- wolfSSL returned success.
- The output shared secret was indeed all zeros.
- The default build did not reject this case.

### `WOLFSSL_ECDHX_SHARED_NOT_ZERO` Enabled

Runtime output:

```text
X25519 ret=-217, out_len=32, all_zero=1
X448 ret=-217, out_len=56, all_zero=1
```

Interpretation:

- With the same input, wolfSSL returned `-217`.
- This is `ECC_OUT_OF_RANGE_E`.
- The check exists, but takes effect only when the macro is explicitly enabled.

## Analysis of the Inconsistency

The root cause of the inconsistency between wolfSSL and the TLS 1.3 specification is:

1. The specification requires an unconditional `MUST` check.
2. wolfSSL places the check inside the `WOLFSSL_ECDHX_SHARED_NOT_ZERO` conditional compilation path.
3. The macro is disabled by default, so the default build does not perform this mandatory check.

In other words, wolfSSL implements the check but makes a mandatory specification requirement an optional build setting.

This has two direct consequences:

1. The default behavior is inconsistent with the TLS 1.3 specification.
2. Only users who know about the macro and explicitly enable it obtain compliant behavior.

## Risk Assessment

The risks primarily concern protocol conformance and cryptographic robustness:

1. For specification conformance, the default implementation violates the mandatory TLS 1.3 requirement for X25519/X448.
2. For implementation security, an all-zero shared secret should be treated as invalid input; if accepted, subsequent key derivation continues using that invalid secret.
3. For deployment, users are unlikely to recognize from the default build alone that this check is disabled. The implementation may therefore appear to support TLS 1.3 while not fully satisfying this requirement.

## Recommendations

The recommendations address implementation, documentation, and testing.

### Implementation Recommendations

1. Enable the all-zero shared-secret check for X25519/X448 by default.
2. A more robust approach is to make the check unconditional so that it always runs, matching the TLS 1.3 `MUST` requirement.
3. If compatibility concerns temporarily prevent enabling it by default, require the macro in TLS 1.3 builds rather than leaving the decision to ordinary users.

### Documentation and Testing Recommendations

1. State clearly in the build documentation that X25519/X448 all-zero shared-secret checks do not run unless `WOLFSSL_ECDHX_SHARED_NOT_ZERO` is enabled.
2. Add regression coverage for:
   - X25519 inputs that produce an all-zero shared secret must fail.
   - X448 inputs that produce an all-zero shared secret must fail.
3. In the TLS 1.3 conformance documentation, identify this as a required check rather than a general enhancement.

## Conclusion

The specification text, source analysis, and runtime reproduction results establish that:

- TLS 1.3 explicitly requires a `MUST`-level check for all-zero shared secrets in X25519/X448.
- The current default wolfSSL build does not perform this check.
- wolfSSL rejects this invalid case only when `WOLFSSL_ECDHX_SHARED_NOT_ZERO` is enabled.

The "partially satisfied" classification for ID329 is therefore supported. Under a strict assessment of TLS 1.3 conformance in the default implementation, this behavior should at least be classified as "mandatory requirement not satisfied in the default configuration".
