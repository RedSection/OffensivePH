#pragma once
#include "base.h"
#include "kphuser.h"
#include "kphapi.h"

NTSTATUS PhOpenProcess(PHANDLE phProc, DWORD pid);
NTSTATUS PhOpenThread(PHANDLE phThread, DWORD tid);

