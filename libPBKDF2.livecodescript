script "libPBKDF2"
/*
libPBKDF2 - PBKDF2 (RFC 8018 / RFC 2898) and HMAC (RFC 2104) in pure xTalk.

A script-only library stack for HyperXTalk, OpenXTalk, LiveCode 9+ and
LiveCode / HyperXTalk Server. Load it with:

    start using stack "libPBKDF2.livecodescript"

Conventions
  * Bytes in, bytes out. pbkdf2Derive and pbkdf2Hmac take passwords, salts and
    keys as binary data. Text must be encoded first: textEncode(tText, "UTF-8").
    ASCII-only text is safe to pass as-is.
  * The password helpers (pbkdf2HashPassword, pbkdf2VerifyPassword) take text
    and UTF-8 encode it for you. They produce and read the passlib-compatible
    string format  $pbkdf2-sha256$<iterations>$<salt>$<hash>
    with salt and hash in "adapted base64" (standard alphabet, + written as .,
    no padding).
  * Digest names: "sha-1", "sha-224", "sha-256", "sha-384", "sha-512", "md5".
    Case and hyphens do not matter, and a "pbkdf2-" prefix is accepted.
    Default is SHA-256.
  * Failures throw. Wrap in try ... catch if a bad argument is possible.

Public handlers
  pbkdf2Derive(pPassword, pSalt, pIterations, pKeyLen, pDigest)  -> binary
  pbkdf2DeriveHex(pPassword, pSalt, pIterations, pKeyLen, pDigest) -> hex text
  pbkdf2Hmac(pDigest, pKey, pMessage)                             -> binary
  pbkdf2HashPassword(pPassword, pIterations, pDigest, pSaltBytes) -> hash string
  pbkdf2VerifyPassword(pPassword, pHashString)                    -> boolean
  pbkdf2ParseHash(pHashString)                                    -> array or empty
  pbkdf2NeedsRehash(pHashString, pIterations, pDigest)            -> boolean
  pbkdf2ConstantTimeEqual(pA, pB)                                 -> boolean
  pbkdf2RandomBytes(pCount)                                       -> binary
  pbkdf2RandomText(pLength, pAlphabet)                            -> text
  pbkdf2ToHex(pData) / pbkdf2FromHex(pHex)
  pbkdf2Ab64Encode(pData) / pbkdf2Ab64Decode(pText)
  pbkdf2DefaultIterations() / pbkdf2Version()

License: MIT. See LICENSE.
*/

constant kVersion = "1.0.0"
constant kDefaultDigest = "sha-256"
constant kDefaultIterations = 100000
constant kDefaultSaltBytes = 16
constant kAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


-- ---------------------------------------------------------------------------
-- Information
-- ---------------------------------------------------------------------------

function pbkdf2Version
   return kVersion
end pbkdf2Version


function pbkdf2DefaultIterations
   return kDefaultIterations
end pbkdf2DefaultIterations


-- ---------------------------------------------------------------------------
-- Core: PBKDF2
-- ---------------------------------------------------------------------------

/*
pbkdf2Derive
Derive pKeyLen bytes from pPassword and pSalt with pIterations rounds of
HMAC-<pDigest>, as RFC 8018 section 5.2 specifies.

pPassword   binary (textEncode text first)
pSalt       binary
pIterations positive integer, default pbkdf2DefaultIterations()
pKeyLen     bytes wanted, default the digest length
pDigest     see the header; default "sha-256"

Returns binary data of exactly pKeyLen bytes.
*/
function pbkdf2Derive pPassword, pSalt, pIterations, pKeyLen, pDigest
   local tDigest, tHLen, tBlocks, tIPad, tOPad, tU, tF, tDK, tBlock, tRound

   put _pbkdf2Digest(pDigest) into tDigest

   if pIterations is empty then put kDefaultIterations into pIterations
   if pIterations is not an integer or pIterations < 1 then
      throw "libPBKDF2: iterations must be a positive integer"
   end if

   put the number of bytes in messageDigest(empty, tDigest) into tHLen
   if pKeyLen is empty then put tHLen into pKeyLen
   if pKeyLen is not an integer or pKeyLen < 1 then
      throw "libPBKDF2: key length must be a positive integer"
   end if

   -- The password is the HMAC key for every call, so pad it once.
   _pbkdf2HmacPads tDigest, pPassword, tIPad, tOPad

   put (pKeyLen + tHLen - 1) div tHLen into tBlocks
   put empty into tDK

   repeat with tBlock = 1 to tBlocks
      -- U1 = PRF(P, S || INT_32_BE(i))
      put messageDigest(tOPad & messageDigest(tIPad & pSalt & binaryEncode("N", tBlock), tDigest), tDigest) into tU
      put tU into tF
      -- Uj = PRF(P, Uj-1);  F = U1 xor U2 xor ... xor Uc
      if tHLen = 32 then
         repeat pIterations - 1 times
            put messageDigest(tOPad & messageDigest(tIPad & tU, tDigest), tDigest) into tU
            put _pbkdf2Xor32(tF, tU) into tF
         end repeat
      else if tHLen = 64 then
         repeat pIterations - 1 times
            put messageDigest(tOPad & messageDigest(tIPad & tU, tDigest), tDigest) into tU
            put _pbkdf2Xor64(tF, tU) into tF
         end repeat
      else
         repeat pIterations - 1 times
            put messageDigest(tOPad & messageDigest(tIPad & tU, tDigest), tDigest) into tU
            put _pbkdf2Xor(tF, tU) into tF
         end repeat
      end if
      put tF after tDK
   end repeat

   return byte 1 to pKeyLen of tDK
end pbkdf2Derive


/*
pbkdf2DeriveHex
As pbkdf2Derive, returning lowercase hex text. This is the form most
database schemas store (for example a 64-character hex column for a 32-byte
SHA-256 key).
*/
function pbkdf2DeriveHex pPassword, pSalt, pIterations, pKeyLen, pDigest
   return pbkdf2ToHex(pbkdf2Derive(pPassword, pSalt, pIterations, pKeyLen, pDigest))
end pbkdf2DeriveHex


-- ---------------------------------------------------------------------------
-- Core: HMAC
-- ---------------------------------------------------------------------------

/*
pbkdf2Hmac
HMAC (RFC 2104) of pMessage under pKey with the named digest. Both pKey and
pMessage are binary. Returns the raw MAC as binary data.
*/
function pbkdf2Hmac pDigest, pKey, pMessage
   local tDigest, tIPad, tOPad

   put _pbkdf2Digest(pDigest) into tDigest
   _pbkdf2HmacPads tDigest, pKey, tIPad, tOPad
   return messageDigest(tOPad & messageDigest(tIPad & pMessage, tDigest), tDigest)
end pbkdf2Hmac


-- ---------------------------------------------------------------------------
-- Password storage helpers (passlib / Python / PHP compatible string)
-- ---------------------------------------------------------------------------

/*
pbkdf2HashPassword
Hash a text password for storage. Returns a self-describing string:

    $pbkdf2-sha256$100000$<salt ab64>$<hash ab64>

pPassword   text (UTF-8 encoded internally)
pIterations default pbkdf2DefaultIterations()
pDigest     default "sha-256"
pSaltBytes  default 16 random bytes from the engine CSPRNG
*/
function pbkdf2HashPassword pPassword, pIterations, pDigest, pSaltBytes
   local tDigest, tSalt, tHash

   put _pbkdf2Digest(pDigest) into tDigest
   if pIterations is empty then put kDefaultIterations into pIterations
   if pSaltBytes is empty then put kDefaultSaltBytes into pSaltBytes
   if pSaltBytes is not an integer or pSaltBytes < 8 then
      throw "libPBKDF2: salt must be at least 8 bytes"
   end if

   put randomBytes(pSaltBytes) into tSalt
   put pbkdf2Derive(textEncode(pPassword, "UTF-8"), tSalt, pIterations, empty, tDigest) into tHash

   return "$pbkdf2-" & _pbkdf2SchemeName(tDigest) & "$" & pIterations & \
         "$" & pbkdf2Ab64Encode(tSalt) & "$" & pbkdf2Ab64Encode(tHash)
end pbkdf2HashPassword


/*
pbkdf2VerifyPassword
Check a text password against a string made by pbkdf2HashPassword (or by
passlib's pbkdf2_sha256 family, which uses the same format). Constant time.
Returns false, never throws, for a malformed string.
*/
function pbkdf2VerifyPassword pPassword, pHashString
   local tParts, tComputed

   put pbkdf2ParseHash(pHashString) into tParts
   if tParts is not an array then return false

   put pbkdf2Derive(textEncode(pPassword, "UTF-8"), tParts["salt"], \
         tParts["iterations"], the number of bytes in tParts["hash"], tParts["digest"]) into tComputed
   return pbkdf2ConstantTimeEqual(tComputed, tParts["hash"])
end pbkdf2VerifyPassword


/*
pbkdf2ParseHash
Split a $pbkdf2-<digest>$<iterations>$<salt>$<hash> string into an array
with keys "digest" (engine name, e.g. "sha-256"), "iterations", "salt"
(binary) and "hash" (binary). Returns empty if the string is not valid.
*/
function pbkdf2ParseHash pHashString
   local tParts, tScheme, tDigest, tIterations, tSalt, tHash

   if pHashString is empty then return empty
   set the itemDelimiter to "$"
   if char 1 of pHashString is not "$" or the number of items of pHashString is not 5 then return empty

   put item 2 of pHashString into tScheme
   if not (tScheme begins with "pbkdf2-") then return empty
   try
      put _pbkdf2Digest(char 8 to -1 of tScheme) into tDigest
   catch tError
      return empty
   end try

   put item 3 of pHashString into tIterations
   if tIterations is not an integer or tIterations < 1 then return empty

   try
      put pbkdf2Ab64Decode(item 4 of pHashString) into tSalt
      put pbkdf2Ab64Decode(item 5 of pHashString) into tHash
   catch tError
      return empty
   end try
   if tSalt is empty or tHash is empty then return empty

   put tDigest into tParts["digest"]
   put tIterations + 0 into tParts["iterations"]
   put tSalt into tParts["salt"]
   put tHash into tParts["hash"]
   return tParts
end pbkdf2ParseHash


/*
pbkdf2NeedsRehash
True if a stored hash string uses fewer iterations or a different digest
than the policy given (defaults: pbkdf2DefaultIterations(), "sha-256"), or
cannot be parsed. Call after a successful login to upgrade old records.
*/
function pbkdf2NeedsRehash pHashString, pIterations, pDigest
   local tParts

   if pIterations is empty then put kDefaultIterations into pIterations
   put pbkdf2ParseHash(pHashString) into tParts
   if tParts is not an array then return true
   if tParts["iterations"] < pIterations then return true
   if tParts["digest"] is not _pbkdf2Digest(pDigest) then return true
   return false
end pbkdf2NeedsRehash


-- ---------------------------------------------------------------------------
-- Comparison and randomness
-- ---------------------------------------------------------------------------

/*
pbkdf2ConstantTimeEqual
Compare two binary values without leaking where they first differ. The time
taken depends only on the length of pA. Use this for hashes, MACs and
tokens instead of "is" or "=".
*/
function pbkdf2ConstantTimeEqual pA, pB
   local tLenA, tLenB, tDiff, i

   put the number of bytes in pA into tLenA
   put the number of bytes in pB into tLenB
   put tLenA bitXor tLenB into tDiff
   if tLenB = 0 then
      put pA into pB
      put tLenA into tLenB
   end if
   repeat with i = 1 to tLenA
      put tDiff bitOr (byteToNum(byte i of pA) bitXor byteToNum(byte ((i - 1) mod tLenB + 1) of pB)) into tDiff
   end repeat
   return tDiff = 0
end pbkdf2ConstantTimeEqual


/*
pbkdf2RandomBytes
pCount bytes from the engine's cryptographic generator (randomBytes).
*/
function pbkdf2RandomBytes pCount
   if pCount is not an integer or pCount < 1 then
      throw "libPBKDF2: byte count must be a positive integer"
   end if
   return randomBytes(pCount)
end pbkdf2RandomBytes


/*
pbkdf2RandomText
pLength characters drawn uniformly (rejection sampling, no modulo bias) from
pAlphabet, default A-Z a-z 0-9, using the engine's cryptographic generator.
For schemas that store the salt in a text column.
*/
function pbkdf2RandomText pLength, pAlphabet
   local tCount, tLimit, tOut, tBytes, i, tByte

   if pAlphabet is empty then put kAlphanumeric into pAlphabet
   if pLength is not an integer or pLength < 1 then
      throw "libPBKDF2: length must be a positive integer"
   end if
   put the number of chars in pAlphabet into tCount
   if tCount < 2 or tCount > 256 then
      throw "libPBKDF2: alphabet must have 2 to 256 characters"
   end if

   put (256 div tCount) * tCount into tLimit
   put empty into tOut
   repeat until the number of chars in tOut = pLength
      put randomBytes(pLength) into tBytes
      repeat with i = 1 to pLength
         put byteToNum(byte i of tBytes) into tByte
         if tByte >= tLimit then next repeat
         put char (tByte mod tCount + 1) of pAlphabet after tOut
         if the number of chars in tOut = pLength then exit repeat
      end repeat
   end repeat
   return tOut
end pbkdf2RandomText


-- ---------------------------------------------------------------------------
-- Encoding helpers
-- ---------------------------------------------------------------------------

function pbkdf2ToHex pData
   local tHex
   get binaryDecode("H*", pData, tHex)
   return tHex
end pbkdf2ToHex


function pbkdf2FromHex pHex
   if the number of chars in pHex mod 2 is not 0 or matchText(pHex, "[^0-9A-Fa-f]") then
      throw "libPBKDF2: malformed hex"
   end if
   return binaryEncode("H*", pHex)
end pbkdf2FromHex


/*
pbkdf2Ab64Encode / pbkdf2Ab64Decode
passlib's "adapted base64": standard alphabet with "+" written as ".", no
padding, no line breaks. Decode also accepts ordinary base64 with "+" and "="
and URL-safe base64 with "-" and "_".
*/
function pbkdf2Ab64Encode pData
   local tText
   put base64Encode(pData) into tText
   replace return with empty in tText
   replace "=" with empty in tText
   replace "+" with "." in tText
   return tText
end pbkdf2Ab64Encode


function pbkdf2Ab64Decode pText
   replace "." with "+" in pText
   replace "-" with "+" in pText
   replace "_" with "/" in pText
   replace "=" with empty in pText
   if matchText(pText, "[^A-Za-z0-9+/]") then throw "libPBKDF2: malformed base64"
   repeat while the number of chars in pText mod 4 is not 0
      put "=" after pText
   end repeat
   return base64Decode(pText)
end pbkdf2Ab64Decode


-- ---------------------------------------------------------------------------
-- Private helpers
-- ---------------------------------------------------------------------------

-- Normalise a digest name to what messageDigest expects.
private function _pbkdf2Digest pName
   put toLower(pName) into pName
   if pName begins with "pbkdf2-" then delete char 1 to 7 of pName
   replace "-" with empty in pName
   replace "_" with empty in pName
   switch pName
      case empty
      case "sha256"
         return "sha-256"
      case "sha1"
         return "sha-1"
      case "sha224"
         return "sha-224"
      case "sha384"
         return "sha-384"
      case "sha512"
         return "sha-512"
      case "md5"
         return "md5"
      default
         throw "libPBKDF2: unsupported digest" && pName
   end switch
end _pbkdf2Digest


-- The digest name as it appears in the $pbkdf2-xxx$ scheme field.
private function _pbkdf2SchemeName pDigest
   replace "-" with empty in pDigest
   return pDigest
end _pbkdf2SchemeName


-- Build the inner and outer padded keys for HMAC (RFC 2104 steps 1-3).
private command _pbkdf2HmacPads pDigest, pKey, @rInner, @rOuter
   local tBlockSize, tKey, i, tByte

   if pDigest is among the items of "sha-384,sha-512" then
      put 128 into tBlockSize
   else
      put 64 into tBlockSize
   end if

   put pKey into tKey
   if the number of bytes in tKey > tBlockSize then
      put messageDigest(tKey, pDigest) into tKey
   end if

   put empty into rInner
   put empty into rOuter
   repeat with i = 1 to the number of bytes in tKey
      put byteToNum(byte i of tKey) into tByte
      put numToByte(tByte bitXor 54) after rInner   -- 0x36
      put numToByte(tByte bitXor 92) after rOuter   -- 0x5C
   end repeat
   repeat tBlockSize - the number of bytes in tKey times
      put numToByte(54) after rInner
      put numToByte(92) after rOuter
   end repeat
end _pbkdf2HmacPads


-- XOR two equal-length binary values, four bytes at a time.
-- Format "I" (unsigned 32-bit, host order) is used for both decode and
-- encode: byte order does not matter for XOR, and unlike "N" it is unsigned
-- in this engine, which matters because bitXor clamps negative operands.
private function _pbkdf2Xor pA, pB
   local tOut, k, tWA, tWB, tLen

   put empty into tOut
   put the number of bytes in pA into tLen
   repeat with k = 1 to tLen - 3 step 4
      get binaryDecode("I", byte k to (k + 3) of pA, tWA)
      get binaryDecode("I", byte k to (k + 3) of pB, tWB)
      put binaryEncode("I", tWA bitXor tWB) after tOut
   end repeat
   -- trailing bytes if the length is not a multiple of four
   repeat with k = (tLen div 4) * 4 + 1 to tLen
      put numToByte(byteToNum(byte k of pA) bitXor byteToNum(byte k of pB)) after tOut
   end repeat
   return tOut
end _pbkdf2Xor


-- Fast path for 32-byte values (SHA-256).
private function _pbkdf2Xor32 pA, pB
   local a1, a2, a3, a4, a5, a6, a7, a8, b1, b2, b3, b4, b5, b6, b7, b8
   get binaryDecode("I8", pA, a1, a2, a3, a4, a5, a6, a7, a8)
   get binaryDecode("I8", pB, b1, b2, b3, b4, b5, b6, b7, b8)
   return binaryEncode("I8", a1 bitXor b1, a2 bitXor b2, a3 bitXor b3, a4 bitXor b4, \
         a5 bitXor b5, a6 bitXor b6, a7 bitXor b7, a8 bitXor b8)
end _pbkdf2Xor32


-- Fast path for 64-byte values (SHA-512).
private function _pbkdf2Xor64 pA, pB
   local a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16
   local b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16
   get binaryDecode("I16", pA, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16)
   get binaryDecode("I16", pB, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16)
   return binaryEncode("I16", a1 bitXor b1, a2 bitXor b2, a3 bitXor b3, a4 bitXor b4, \
         a5 bitXor b5, a6 bitXor b6, a7 bitXor b7, a8 bitXor b8, \
         a9 bitXor b9, a10 bitXor b10, a11 bitXor b11, a12 bitXor b12, \
         a13 bitXor b13, a14 bitXor b14, a15 bitXor b15, a16 bitXor b16)
end _pbkdf2Xor64
