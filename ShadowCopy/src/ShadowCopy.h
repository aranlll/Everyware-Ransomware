#pragma once
#include <Windows.h>
#include <stdio.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <vsmgmt.h>
#include <atlcomcli.h>

#pragma comment (lib, "VssApi.lib")

#define WSTR_GUID_FMT  L"{%.8x-%.4x-%.4x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x}"

#define GUID_PRINTF_ARG( X )                                    \
    (X).Data1,                                                  \
    (X).Data2,                                                  \
    (X).Data3,                                                  \
    (X).Data4[0], (X).Data4[1], (X).Data4[2], (X).Data4[3], \
    (X).Data4[4], (X).Data4[5], (X).Data4[6], (X).Data4[7]

HRESULT DeleteShadowCopy();