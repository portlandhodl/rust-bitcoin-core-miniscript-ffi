// Force-included first in every C++ translation unit on MSVC (/FI).
//
// Root cause being shimmed: the Windows SDK's <nb30.h> (pulled in by
// <winsock2.h>, which Bitcoin Core's <compat/compat.h> includes on WIN32)
// contains `#define UNIQUE_NAME 0x00` — a NetBIOS name-flag constant that
// collides with Bitcoin Core's util/macros.h
// `UNIQUE_NAME(name) = PASTE2(name, __COUNTER__)`. Macro redefinition is
// last-one-wins, so when a TU includes sync.h (via some header) BEFORE
// compat/compat.h, sync.h's include guard keeps util/macros.h from
// re-defining UNIQUE_NAME afterwards, and the NetBIOS constant stays active:
// LOCK()/REVERSE_LOCK() then mis-expand to `UniqueLock 0x00(criticalblock)(...)`
// (MSVC C3878 "unexpected token 'constant'" / C2065 "'criticalblock':
// undeclared identifier", seen in common/args.h LockSettings).
//
// Including the Windows socket headers here FIRST and sync.h LAST makes the
// correct (function-like) UNIQUE_NAME definition the final one for the whole
// translation unit, whatever the TU's own include order. No vendored Bitcoin
// Core source is modified.
#pragma once

#ifdef _MSC_VER
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sync.h>
// Silence C4005 ("macro redefinition") for UNIQUE_NAME for the rest of the
// TU; the redefinition ordering above is deliberate.
#pragma warning(disable : 4005)
#endif
