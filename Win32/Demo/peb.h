#pragma once
#include "pch.h"


HMODULE  GetKernelHandle();
HMODULE  GetNtHandle();
FARPROC  FindGetProcAddress(HMODULE ker32);