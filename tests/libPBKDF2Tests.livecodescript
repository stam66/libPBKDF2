script "libPBKDF2Tests"
/*
Known-answer and behaviour tests for libPBKDF2.

   start using stack "libPBKDF2.livecodescript"
   start using stack "tests/libPBKDF2Tests.livecodescript"
   put pbkdf2RunTests("tests/vectors.txt")

pbkdf2RunTests returns a text report; its last line is "RESULT: PASS" or
"RESULT: FAIL (<n> failed)". pbkdf2TestFailures() returns the failure count.
*/

local sPassed, sFailed, sReport


function pbkdf2TestFailures
   return sFailed
end pbkdf2TestFailures


function pbkdf2RunTests pVectorsPath
   local tVectors, tLine, tStart

   put 0 into sPassed
   put 0 into sFailed
   put empty into sReport

   _note "libPBKDF2" && pbkdf2Version() && "on" && the platform && "engine" && the version

   -- 1. Known-answer vectors from an independent implementation
   put url ("binfile:" & pVectorsPath) into tVectors
   if tVectors is empty then
      _check false, "vectors file readable:" && pVectorsPath
      return _finish()
   end if
   repeat for each line tLine in tVectors
      if tLine is empty or char 1 of tLine is "#" then next repeat
      set the itemDelimiter to tab
      switch item 1 of tLine
         case "pbkdf2"
            _testPbkdf2Vector item 2 of tLine, item 3 of tLine, item 4 of tLine, \
                  item 5 of tLine, item 6 of tLine, item 7 of tLine
            break
         case "hmac"
            _testHmacVector item 2 of tLine, item 3 of tLine, item 4 of tLine, item 5 of tLine
            break
         case "passlib"
            _testPasslibVector item 2 of tLine, item 3 of tLine
            break
         default
            _check false, "unknown vector kind:" && item 1 of tLine
      end switch
   end repeat

   -- 2. Behaviour
   _testDigestNames
   _testEncoding
   _testConstantTimeEqual
   _testRandom
   _testPasswordRoundTrip
   _testParseAndRehash
   _testErrors
   _testTiming

   return _finish()
end pbkdf2RunTests


-- ---------------------------------------------------------------------------

private command _testPbkdf2Vector pDigest, pPwHex, pSaltHex, pIter, pLen, pExpected
   local tGot, tLabel
   put "pbkdf2-" & pDigest && "c=" & pIter && "dkLen=" & pLen into tLabel
   try
      put pbkdf2DeriveHex(pbkdf2FromHex(pPwHex), pbkdf2FromHex(pSaltHex), pIter, pLen, pDigest) into tGot
   catch tError
      put "THREW" && tError into tGot
   end try
   _check tGot is pExpected, tLabel, pExpected, tGot
end _testPbkdf2Vector


private command _testHmacVector pDigest, pKeyHex, pMsgHex, pExpected
   local tGot, tLabel
   put "hmac-" & pDigest && "key" && (the number of chars in pKeyHex div 2) && "bytes" into tLabel
   try
      put pbkdf2ToHex(pbkdf2Hmac(pDigest, pbkdf2FromHex(pKeyHex), pbkdf2FromHex(pMsgHex))) into tGot
   catch tError
      put "THREW" && tError into tGot
   end try
   _check tGot is pExpected, tLabel, pExpected, tGot
end _testHmacVector


private command _testPasslibVector pPwHex, pHashString
   local tPassword
   put textDecode(pbkdf2FromHex(pPwHex), "UTF-8") into tPassword
   set the itemDelimiter to "$"
   _check pbkdf2VerifyPassword(tPassword, pHashString), "passlib verify" && item 2 of pHashString
   _check not pbkdf2VerifyPassword(tPassword & "x", pHashString), "passlib reject wrong password" && item 2 of pHashString
end _testPasslibVector


private command _testDigestNames
   local tRef, tName
   put pbkdf2DeriveHex("password", "salt", 2, 20, "sha-1") into tRef
   repeat for each item tName in "sha1,SHA1,Sha-1,pbkdf2-sha1,PBKDF2-SHA1,sha_1"
      _check pbkdf2DeriveHex("password", "salt", 2, 20, tName) is tRef, "digest alias" && tName
   end repeat
   _check pbkdf2DeriveHex("password", "salt", 2, 32) is pbkdf2DeriveHex("password", "salt", 2, 32, "sha-256"), "default digest is sha-256"
   _check the number of bytes in pbkdf2Derive("password", "salt", 1, empty, "sha-512") is 64, "default key length is the digest length"
end _testDigestNames


private command _testEncoding
   local tBytes, i, tEnc
   put empty into tBytes
   repeat with i = 0 to 255
      put numToByte(i) after tBytes
   end repeat
   _check pbkdf2FromHex(pbkdf2ToHex(tBytes)) is tBytes, "hex round trip over all 256 byte values"
   _check pbkdf2ToHex(numToByte(0) & numToByte(255)) is "00ff", "hex is lowercase and zero padded"
   put pbkdf2Ab64Encode(tBytes) into tEnc
   _check "=" is not in tEnc and "+" is not in tEnc and return is not in tEnc, "ab64 has no padding, plus or line breaks"
   _check pbkdf2Ab64Decode(tEnc) is tBytes, "ab64 round trip over all 256 byte values"
   _check pbkdf2Ab64Decode("AQIDBAUGBwgJCgsMDQ4PEA") is pbkdf2FromHex("0102030405060708090a0b0c0d0e0f10"), "ab64 decode of a passlib salt"
   _check pbkdf2Ab64Decode("/+8=") is pbkdf2Ab64Decode("_-8") and pbkdf2Ab64Decode("/+8=") is pbkdf2FromHex("ffef"), "ab64 decode accepts standard and url-safe alphabets"
   _check pbkdf2Ab64Decode(empty) is empty, "ab64 decode of empty"
end _testEncoding


private command _testConstantTimeEqual
   _check pbkdf2ConstantTimeEqual("abc", "abc"), "cte equal"
   _check not pbkdf2ConstantTimeEqual("abc", "abd"), "cte differ last byte"
   _check not pbkdf2ConstantTimeEqual("abc", "abcd"), "cte differ length (longer)"
   _check not pbkdf2ConstantTimeEqual("abcd", "abc"), "cte differ length (shorter)"
   _check not pbkdf2ConstantTimeEqual("abc", empty), "cte against empty"
   _check not pbkdf2ConstantTimeEqual(empty, "abc"), "cte empty against value"
   _check pbkdf2ConstantTimeEqual(empty, empty), "cte both empty"
   _check pbkdf2ConstantTimeEqual(numToByte(0) & numToByte(200), numToByte(0) & numToByte(200)), "cte binary with high byte"
   _check not pbkdf2ConstantTimeEqual("abcabc", "abc"), "cte repeated prefix is not equal"
end _testConstantTimeEqual


private command _testRandom
   local tA, tB, tText, i, tOK
   put pbkdf2RandomBytes(16) into tA
   put pbkdf2RandomBytes(16) into tB
   _check the number of bytes in tA is 16, "random bytes length"
   _check tA is not tB, "random bytes differ between calls"
   put pbkdf2RandomText(32) into tText
   _check the number of chars in tText is 32, "random text length"
   _check matchText(tText, "^[A-Za-z0-9]{32}$"), "random text is alphanumeric"
   _check pbkdf2RandomText(32) is not tText, "random text differs between calls"
   put true into tOK
   repeat with i = 1 to 50
      if matchText(pbkdf2RandomText(7, "01"), "^[01]{7}$") is false then put false into tOK
   end repeat
   _check tOK, "random text with a two-character alphabet"
   put true into tOK
   repeat with i = 1 to 20
      if matchText(pbkdf2RandomText(5, "abc"), "^[abc]{5}$") is false then put false into tOK
   end repeat
   _check tOK, "random text with a three-character alphabet (rejection sampling path)"
end _testRandom


private command _testPasswordRoundTrip
   local tHash, tHash2, tParts
   put pbkdf2HashPassword("correct horse battery staple", 1000) into tHash
   _check tHash begins with "$pbkdf2-sha256$1000$", "hash string prefix:" && tHash
   set the itemDelimiter to "$"
   _check the number of items of tHash is 5, "hash string has five $ fields"
   _check pbkdf2VerifyPassword("correct horse battery staple", tHash), "verify own hash"
   _check not pbkdf2VerifyPassword("correct horse battery stapler", tHash), "reject wrong password"
   _check not pbkdf2VerifyPassword(empty, tHash), "reject empty password"
   put pbkdf2HashPassword("correct horse battery staple", 1000) into tHash2
   _check tHash is not tHash2, "fresh salt every hash"
   put pbkdf2HashPassword("pässwörd€", 500, "sha-512", 24) into tHash
   _check tHash begins with "$pbkdf2-sha512$500$", "sha-512 hash string prefix"
   _check pbkdf2VerifyPassword("pässwörd€", tHash), "verify utf-8 password"
   _check not pbkdf2VerifyPassword("pässwörd", tHash), "reject truncated utf-8 password"
   put pbkdf2ParseHash(tHash) into tParts
   _check the number of bytes in tParts["salt"] is 24, "custom salt length honoured"
   _check the number of bytes in tParts["hash"] is 64, "sha-512 hash is 64 bytes"
end _testPasswordRoundTrip


private command _testParseAndRehash
   local tHash, tParts
   put "$pbkdf2-sha256$29000$AQIDBAUGBwgJCgsMDQ4PEA$o5w3b/ksUkeM8Zc.uEtDsblOwJJw9gdVOPvvnjK2Hlg" into tHash
   put pbkdf2ParseHash(tHash) into tParts
   _check tParts is an array, "parse valid string"
   _check tParts["digest"] is "sha-256", "parsed digest"
   _check tParts["iterations"] is 29000, "parsed iterations"
   _check pbkdf2ToHex(tParts["salt"]) is "0102030405060708090a0b0c0d0e0f10", "parsed salt"
   _check the number of bytes in tParts["hash"] is 32, "parsed hash length"

   _check pbkdf2ParseHash(empty) is empty, "parse empty"
   _check pbkdf2ParseHash("not a hash") is empty, "parse garbage"
   _check pbkdf2ParseHash("$argon2id$v=19$m=65536,t=2,p=1$abc$def") is empty, "parse other scheme"
   _check pbkdf2ParseHash("$pbkdf2-sha256$abc$AQID$AQID") is empty, "parse non-numeric iterations"
   _check pbkdf2ParseHash("$pbkdf2-sha256$0$AQID$AQID") is empty, "parse zero iterations"
   _check pbkdf2ParseHash("$pbkdf2-sha3$1000$AQID$AQID") is empty, "parse unsupported digest"
   _check pbkdf2ParseHash("$pbkdf2-sha256$1000$$AQID") is empty, "parse empty salt"
   _check pbkdf2ParseHash("$pbkdf2-sha256$1000$AQ!D$AQID") is empty, "parse malformed base64"
   _check pbkdf2ParseHash("$pbkdf2-sha256$1000$AQID") is empty, "parse missing field"
   _check not pbkdf2VerifyPassword("x", "garbage"), "verify never throws on garbage"

   _check pbkdf2NeedsRehash(tHash, 29000, "sha-256") is false, "no rehash when policy matches"
   _check pbkdf2NeedsRehash(tHash, 30000, "sha-256"), "rehash when iterations raised"
   _check pbkdf2NeedsRehash(tHash, 29000, "sha-512"), "rehash when digest changed"
   _check pbkdf2NeedsRehash(tHash, 1000, "sha-256") is false, "no rehash when stored exceeds policy"
   _check pbkdf2NeedsRehash("garbage"), "rehash when unparseable"
   _check pbkdf2NeedsRehash(tHash) is (29000 < pbkdf2DefaultIterations()), "rehash against default iterations"
end _testParseAndRehash


private command _testErrors
   _checkThrows "pbkdf2Derive(" & quote & "p" & quote & "," && quote & "s" & quote & ", 0, 32)", "iterations 0 throws"
   _checkThrows "pbkdf2Derive(" & quote & "p" & quote & "," && quote & "s" & quote & ", 1, 0)", "key length 0 throws"
   _checkThrows "pbkdf2Derive(" & quote & "p" & quote & "," && quote & "s" & quote & ", 1, 32, " & quote & "sha3" & quote & ")", "unsupported digest throws"
   _checkThrows "pbkdf2FromHex(" & quote & "abc" & quote & ")", "odd-length hex throws"
   _checkThrows "pbkdf2FromHex(" & quote & "zz" & quote & ")", "non-hex throws"
   _checkThrows "pbkdf2Ab64Decode(" & quote & "a*b" & quote & ")", "malformed ab64 throws"
   _checkThrows "pbkdf2HashPassword(" & quote & "p" & quote & ", 10, empty, 4)", "short salt throws"
   _checkThrows "pbkdf2RandomText(0)", "random text length 0 throws"
   _checkThrows "pbkdf2RandomText(4," && quote & "a" & quote & ")", "one-character alphabet throws"
   _checkThrows "pbkdf2RandomBytes(0)", "random bytes 0 throws"
end _testErrors


private command _testTiming
   local tStart, tMs, tSteps, tLabel
   put the milliseconds into tStart
   get pbkdf2Derive("password", "salt", 10000, 32, "sha-256")
   put the milliseconds - tStart into tMs
   _note "timing: pbkdf2-sha256 10,000 rounds, 32 bytes:" && tMs && "ms"
   put the milliseconds into tStart
   get pbkdf2Derive("password", "salt", 10000, 64, "sha-512")
   put the milliseconds - tStart into tMs
   _note "timing: pbkdf2-sha512 10,000 rounds, 64 bytes:" && tMs && "ms"
   put the milliseconds into tStart
   get pbkdf2Derive("password", "salt", 10000, 20, "sha-1")
   put the milliseconds - tStart into tMs
   _note "timing: pbkdf2-sha1 10,000 rounds, 20 bytes:" && tMs && "ms"
   put the milliseconds into tStart
   get pbkdf2HashPassword("password")
   put the milliseconds - tStart into tMs
   _note "timing: pbkdf2HashPassword at default" && pbkdf2DefaultIterations() && "rounds:" && tMs && "ms"
end _testTiming


-- ---------------------------------------------------------------------------

private command _check pCondition, pLabel, pExpected, pGot
   if pCondition is true then
      add 1 to sPassed
      put "  ok  " & pLabel & return after sReport
   else
      add 1 to sFailed
      put "FAIL  " & pLabel & return after sReport
      if pExpected is not empty or pGot is not empty then
         put "        expected:" && pExpected & return & "        got:     " && pGot & return after sReport
      end if
   end if
end _check


private command _checkThrows pExpression, pLabel
   local tThrew
   put false into tThrew
   try
      do "get" && pExpression
   catch tError
      put true into tThrew
   end try
   _check tThrew, pLabel
end _checkThrows


private command _note pText
   put "      " & pText & return after sReport
end _note


private function _finish
   put return & sPassed && "passed," && sFailed && "failed" & return after sReport
   if sFailed = 0 then
      put "RESULT: PASS" after sReport
   else
      put "RESULT: FAIL (" & sFailed && "failed)" after sReport
   end if
   return sReport
end _finish
