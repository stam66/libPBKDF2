# libPBKDF2

PBKDF2 (RFC 8018) and HMAC (RFC 2104) in pure xTalk, as one script-only stack.

Works unchanged in the HyperXTalk and OpenXTalk IDEs, in LiveCode 9 and later,
in standalones, and under the LiveCode / HyperXTalk **server** engine. No
externals, no LCB, nothing native to install: it needs only `messageDigest`,
`randomBytes`, `binaryEncode` and `binaryDecode`, which every one of those
engines has.

## When you want PBKDF2 rather than Argon2id

Argon2id is the better password hash when you control both ends and a native
library (for example SodiumXT) is available. PBKDF2 is what you need when you
have to match something you do not control, or when nothing native can be
installed: it runs everywhere an engine runs, the server engine included.

## Use cases, ranked by what the library buys you

1. **Server-side password storage in an xTalk API.** Any HyperXTalk or
   LiveCode Server endpoint with a users table needs salted, slow hashing.
   `pbkdf2HashPassword` and `pbkdf2VerifyPassword` give a self-describing
   string, a fresh salt each time, and `pbkdf2NeedsRehash` to raise the cost
   later. The 100,000 round default is a usable baseline on a VPS.

2. **Verifying hashes another system wrote.** A users table shared with a
   Xojo (`Crypto.PBKDF2`), .NET (`Rfc2898DeriveBytes`), Java
   (`PBKDF2WithHmacSHA256`), Python (`hashlib.pbkdf2_hmac`, passlib) or PHP
   (`hash_pbkdf2`) application, or a migration from one. Those runtimes all
   ship PBKDF2 and most do not ship Argon2id, so PBKDF2 is the format you
   inherit. `pbkdf2DeriveHex` with the same digest, count, salt bytes and
   length reproduces their output exactly; passlib strings verify directly.

3. **Passphrase to encryption key in a desktop app.** The engine's own
   `encrypt ... with password` derives its key with a single weak hash. Derive
   a 32-byte key with `pbkdf2Derive`, store the salt and round count beside
   the ciphertext, and use `encrypt ... with key`. This is the main desktop
   use, and the one where the library fixes a real weakness in the stock
   engine.

4. **Formats that mandate PBKDF2.** Encrypted ZIP and PDF, WPA2 passphrases,
   older KeePass databases, iOS and Android backup containers, LUKS1. A tool
   that opens or produces any of those needs the exact algorithm with a chosen
   PRF and count, not a hash of its own design.

5. **HMAC for everything else.** `pbkdf2Hmac` is a general RFC 2104 HMAC,
   which the engine does not offer. That covers JWT HS256 signing, webhook
   signature checks (Stripe, GitHub, Slack), request signing for cloud APIs,
   and integrity tags on files you write. It is likely the most-called
   handler once the library is in a project.

6. **Compliance.** Where a checklist says NIST SP 800-132 or a FIPS-approved
   key derivation function, PBKDF2 qualifies and Argon2id does not.

The weakest use is a high-value password store where you control both ends
and can install a native library: there Argon2id is the better hash. For an Argon2id xTalk extension see https://github.com/SethMorrowSoftware/SodiumXT

### A note on JWTs in desktop apps

`pbkdf2Hmac` makes HS256 JWTs easy, so it is worth saying where they belong.
In a desktop app the sound uses are as a *client* of a remote API (store the
token the server issued, send it in the Authorization header, check `exp`),
or as a short-lived handshake between components you both own. An HMAC secret
compiled into a distributed app can be extracted, so a desktop app must never
be the verifier of tokens it also holds the secret for: licence files need an
asymmetric signature (RS256, ES256 or ed25519), which this library does not
provide. Local login should use a password hash, not a token, and a cached
JWT cannot be revoked without a round trip to the server.

## Install

Copy `libPBKDF2.livecodescript` into your project and load it:

```livecode
start using stack "libPBKDF2.livecodescript"
```

That one line is the same in a stack script, a standalone, and a server
`.lc` script (relative to the script's folder, or give a full path).

## Quick start

Store and check a password:

```livecode
-- sign-up: store tStored (ASCII text, about 100 characters)
put pbkdf2HashPassword(tPassword) into tStored
-- e.g. $pbkdf2-sha256$100000$2RVzm2QTAykBtb.fKoeA.g$ZDZi4HJHtCwRVXTRErPmtQODai1PQNgELD4P92OYNJ8

-- login
if pbkdf2VerifyPassword(tAttempt, tStored) then
   -- access granted; upgrade old records on the way in
   if pbkdf2NeedsRehash(tStored) then
      put pbkdf2HashPassword(tAttempt) into tStored   -- and save it
   end if
end if
```

Derive a key or match another system's raw PBKDF2:

```livecode
-- 32-byte key, 10,000 rounds of HMAC-SHA256, hex output
put pbkdf2DeriveHex(textEncode(tPassword, "UTF-8"), tSalt, 10000, 32, "sha-256") into tHex

-- raw bytes for use as an encryption key
put pbkdf2Derive(textEncode(tPassphrase, "UTF-8"), tSalt, 200000, 32) into tKey
```

## API

Bytes in, bytes out. `pbkdf2Derive` and `pbkdf2Hmac` take passwords, salts and
keys as binary data; pass text through `textEncode(tText, "UTF-8")` first
(ASCII-only text is safe as-is). The password helpers take text and encode it
for you. Bad arguments throw; wrap in `try ... catch` where input is untrusted.

| Handler | Returns | Notes |
|---|---|---|
| `pbkdf2Derive(pPassword, pSalt, pIterations, pKeyLen, pDigest)` | binary | RFC 8018 PBKDF2. Defaults: `pbkdf2DefaultIterations()`, the digest length, `"sha-256"`. |
| `pbkdf2DeriveHex(...)` | hex text | Same, lowercase hex (the form most database columns hold). |
| `pbkdf2Hmac(pDigest, pKey, pMessage)` | binary | RFC 2104 HMAC with any supported digest. |
| `pbkdf2HashPassword(pPassword, pIterations, pDigest, pSaltBytes)` | text | Self-describing `$pbkdf2-<digest>$<iter>$<salt>$<hash>` string. Fresh random salt every call (default 16 bytes). |
| `pbkdf2VerifyPassword(pPassword, pHashString)` | boolean | Constant-time check. Returns false, never throws, on a malformed string. |
| `pbkdf2ParseHash(pHashString)` | array or empty | Keys `digest`, `iterations`, `salt` (binary), `hash` (binary). |
| `pbkdf2NeedsRehash(pHashString, pIterations, pDigest)` | boolean | True when the stored string is weaker than the policy or unreadable. |
| `pbkdf2ConstantTimeEqual(pA, pB)` | boolean | Compare hashes, MACs or tokens without leaking where they differ. |
| `pbkdf2RandomBytes(pCount)` | binary | From the engine's cryptographic generator (`randomBytes`). |
| `pbkdf2RandomText(pLength, pAlphabet)` | text | Unbiased random text (default A-Z a-z 0-9) for schemas with a text salt column. |
| `pbkdf2ToHex(pData)`, `pbkdf2FromHex(pHex)` | | Hex helpers. |
| `pbkdf2Ab64Encode(pData)`, `pbkdf2Ab64Decode(pText)` | | passlib's adapted base64 (`+` as `.`, no padding). Decode also accepts standard and URL-safe base64. |
| `pbkdf2DefaultIterations()`, `pbkdf2Version()` | | 100,000 and the library version. |

Digest names: `sha-1`, `sha-224`, `sha-256`, `sha-384`, `sha-512`, `md5`.
Case, hyphens and underscores are ignored, and a `pbkdf2-` prefix is accepted,
so `SHA256`, `sha_256` and `pbkdf2-sha256` all work.

## Interoperability

The `pbkdf2HashPassword` string is the format used by Python's
[passlib](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html)
`pbkdf2_sha256`, `pbkdf2_sha1` and `pbkdf2_sha512` hashers. Strings made by
passlib verify here and strings made here verify in passlib; the test suite
checks four of them.

Systems that store the raw output in their own layout (a salt column plus a hex
hash, for example) use `pbkdf2Derive` or `pbkdf2DeriveHex` with the same
digest, iteration count, salt bytes and key length. The salt must be the exact
bytes the other side used: a text salt stays text, a binary salt stays binary.

Example, matching a LiveCode Server API and a Xojo web app that share a users
table with a 32-character text salt column, a 64-character hex hash column, and
`Crypto.PBKDF2(salt, password, 10000, 32, SHA2_256)` on the Xojo side:

```livecode
-- new user
put pbkdf2RandomText(32) into tSalt
put pbkdf2DeriveHex(textEncode(tPassword, "UTF-8"), tSalt, 10000, 32, "sha-256") into tHash
-- store tSalt and tHash

-- login
put pbkdf2DeriveHex(textEncode(tAttempt, "UTF-8"), tStoredSalt, 10000, 32, "sha-256") into tCheck
if pbkdf2ConstantTimeEqual(tCheck, toLower(tStoredHash)) then ...
```

## Performance

Measured on an Apple Silicon Mac with the test suite's timing step:

| Derivation | HyperXTalk 0.9.16 | LiveCode 11.0.1 |
|---|---|---|
| PBKDF2-SHA256, 10,000 rounds, 32 bytes | 55 ms | 40 ms |
| PBKDF2-SHA512, 10,000 rounds, 64 bytes | 95 ms | 60 ms |
| PBKDF2-SHA1, 10,000 rounds, 20 bytes | 80 ms | 63 ms |
| `pbkdf2HashPassword` at the default 100,000 rounds | 540 ms | 400 ms |

The inner loop is two `messageDigest` calls and a 32-bit-word XOR per round.
The HMAC key padding is computed once per derivation, not once per round.
OWASP's current recommendation for PBKDF2-SHA256 is 600,000 rounds, which costs
about three seconds here; the default of 100,000 is a compromise for an
interpreted implementation. Raise it where the server can afford it, and let
`pbkdf2NeedsRehash` upgrade stored hashes on login. A native `pbkdf2` in the
engine (OpenSSL's `PKCS5_PBKDF2_HMAC` is already linked) would be the way to
reach the recommended count at no cost; the library's handler names are
designed so such a function could sit behind them.

## Security notes

- Salts come from `randomBytes`, the engine's cryptographic generator. Never
  use `random()` for a salt.
- Compare with `pbkdf2ConstantTimeEqual` or `pbkdf2VerifyPassword`, not `is`.
- Store the iteration count and digest with the hash (the string format does
  this) so the cost can be raised later without breaking old records.
- The engine keeps script values in managed memory, so a password or derived
  key cannot be reliably zeroed after use. Keep such values short-lived.
- SHA-1 and MD5 are included for compatibility with existing data only.

## Tests

`tests/vectors.txt` holds known-answer vectors generated by
`tools/gen-vectors.py` from Python's `hashlib` and `hmac` (RFC 6070, RFC 7914
and RFC 4231 cases among them), plus passlib-format strings. The xTalk test
stack reads that file and adds behaviour tests (encoding, constant-time
compare, random text, round trips, parsing, error handling, timing).

Headless, with an IDE or standalone engine:

```bash
"/Applications/HyperXTalk.app/Contents/MacOS/HyperXTalk" -ui tests/run-tests.livecodescript
```

Under a server engine, from the repository root:

```bash
server-community tests/run-tests.lc
```

Inside the IDE:

```livecode
start using stack "libPBKDF2.livecodescript"
start using stack "tests/libPBKDF2Tests.livecodescript"
put pbkdf2RunTests("tests/vectors.txt")
```

The last line of the report is `RESULT: PASS` or `RESULT: FAIL (<n> failed)`.
As of 1.0.0 all 108 checks pass on HyperXTalk 0.9.16 (IDE and server engines)
and LiveCode 11.0.1.

## Engine notes

Two things learned while writing this, worth knowing if you touch the code:

- `binaryDecode` format `N` (32-bit big-endian) is signed in these engines and
  `bitXor` clamps a negative operand to zero. Format `I` is unsigned, so the
  XOR helpers use `I` for both decode and encode (byte order is irrelevant to
  XOR).
- `does not begin with` is not accepted; use `not (x begins with y)`.

## License

MIT. See `LICENSE`.
