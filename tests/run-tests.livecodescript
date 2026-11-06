script "libPBKDF2TestRunner"
/*
Headless runner for the IDE or standalone engine:

   <engine> -ui tests/run-tests.livecodescript

Loads the library and the test stack from the repository this file sits in,
prints the report to stdout and quits. Compile errors in either stack are
surfaced rather than hanging the engine.
*/

local sRan

on startup
   _runOnce
end startup

on openStack
   _runOnce
end openStack

private command _runOnce
   local tRoot, tReport

   if sRan is true then exit _runOnce
   put true into sRan

   set the itemDelimiter to "/"
   put item 1 to -3 of the filename of me into tRoot

   try
      start using stack (tRoot & "/libPBKDF2.livecodescript")
      start using stack (tRoot & "/tests/libPBKDF2Tests.livecodescript")
      -- re-set the scripts so a compile error throws here instead of hanging
      set the script of stack "libPBKDF2" to the script of stack "libPBKDF2"
      set the script of stack "libPBKDF2Tests" to the script of stack "libPBKDF2Tests"
   catch tError
      put "LOAD ERROR:" && tError & return
      put "RESULT: FAIL (load error)" & return
      quit
   end try

   put pbkdf2RunTests(tRoot & "/tests/vectors.txt") into tReport
   put tReport & return
   quit
end _runOnce
