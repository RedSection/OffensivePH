/*
 * Process Hacker -
 *   KProcessHacker API
 *
 * Copyright (C) 2009-2016 wj32
 * Copyright (C) 2018-2020 dmex
 *
 * This file is part of Process Hacker.
 *
 * Process Hacker is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Process Hacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pch.h"
#include "kphuser.h"

FORCEINLINE NTSTATUS PhGetLastWin32ErrorAsNtStatus(
    VOID
)
{
    ULONG win32Result;

    // This is needed because NTSTATUS_FROM_WIN32 uses the argument multiple times.
    win32Result = GetLastError();

    return NTSTATUS_FROM_WIN32(win32Result);
}

NTSTATUS KphpDeviceIoControl(
    _In_ ULONG KphControlCode,
    _In_ PVOID InBuffer,
    _In_ ULONG InBufferLength
    );

HANDLE PhKphHandle = NULL;

NTSTATUS KphConnect(
    )
{
    NTSTATUS status;
    HANDLE kphHandle;
    UNICODE_STRING objectName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK isb;
    OBJECT_HANDLE_FLAG_INFORMATION handleFlagInfo;

    if (PhKphHandle)
        return STATUS_ADDRESS_ALREADY_EXISTS;

    RtlInitUnicodeString(&objectName, KPH_DEVICE_NAME);

    InitializeObjectAttributes(
        &objectAttributes,
        &objectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
        );

    status = NtOpenFile(
        &kphHandle,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        &objectAttributes,
        &isb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_NON_DIRECTORY_FILE
        );

    if (NT_SUCCESS(status))
    {
        // Protect the handle from being closed.

        handleFlagInfo.Inherit = FALSE;
        handleFlagInfo.ProtectFromClose = TRUE;

        NtSetInformationObject(
            kphHandle,
            ObjectHandleFlagInformation,
            &handleFlagInfo,
            sizeof(OBJECT_HANDLE_FLAG_INFORMATION)
            );

        PhKphHandle = kphHandle;
    }

    return status;
}

NTSTATUS KphConnect2Ex(
    _In_opt_ PWSTR DeviceName,
    _In_ PWSTR FileName
    )
{
    NTSTATUS status;
    WCHAR fullDeviceName[256];
    SC_HANDLE scmHandle;
    SC_HANDLE serviceHandle = INVALID_HANDLE_VALUE;
    BOOLEAN started = FALSE;
    BOOLEAN created = FALSE;

    // Try to open the device.
    status = KphConnect();

    if (NT_SUCCESS(status) || status == STATUS_ADDRESS_ALREADY_EXISTS)
        return status;

    if (
        status != STATUS_NO_SUCH_DEVICE &&
        status != STATUS_NO_SUCH_FILE &&
        status != STATUS_OBJECT_NAME_NOT_FOUND &&
        status != STATUS_OBJECT_PATH_NOT_FOUND
        )
        return status;

    // Load the driver, and try again.

    // Try to start the service, if it exists.

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

    if (scmHandle)
    {
        serviceHandle = OpenService(scmHandle, DeviceName, SERVICE_START);

        if (serviceHandle)
        {
            if (StartService(serviceHandle, 0, NULL))
                started = TRUE;

            CloseServiceHandle(serviceHandle);
        }

        CloseServiceHandle(scmHandle);
    }

    if (!started && RtlDoesFileExists_U(FileName))
    {
        // Try to create the service.

        scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

        if (scmHandle)
        {
            serviceHandle = CreateService(
                scmHandle,
                DeviceName,
                DeviceName,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                FileName,
                NULL,
                NULL,
                NULL,
                NULL,
                L""
                );

            if (serviceHandle)
            {
                created = TRUE;

                if (StartService(serviceHandle, 0, NULL))
                    started = TRUE;
            }

            CloseServiceHandle(scmHandle);
        }
    }

    if (started)
    {
        // Try to open the device again.
        status = KphConnect();
    }

CreateAndConnectEnd:
    if (created)
    {
        // "Delete" the service. Since we (may) have a handle to
        // the device, the SCM will delete the service automatically
        // when it is stopped (upon reboot). If we don't have a
        // handle to the device, the service will get deleted immediately,
        // which is a good thing anyway.
        DeleteService(serviceHandle);
        CloseServiceHandle(serviceHandle);
    }

    return status;
}

NTSTATUS KphDisconnect(
    VOID
    )
{
    NTSTATUS status;
    OBJECT_HANDLE_FLAG_INFORMATION handleFlagInfo;

    if (!PhKphHandle)
        return STATUS_ALREADY_DISCONNECTED;

    // Unprotect the handle.

    handleFlagInfo.Inherit = FALSE;
    handleFlagInfo.ProtectFromClose = FALSE;

    NtSetInformationObject(
        PhKphHandle,
        ObjectHandleFlagInformation,
        &handleFlagInfo,
        sizeof(OBJECT_HANDLE_FLAG_INFORMATION)
        );

    status = NtClose(PhKphHandle);
    PhKphHandle = NULL;

    return status;
}

BOOLEAN KphIsConnected(
    VOID
    )
{
    return PhKphHandle != NULL;
}

NTSTATUS KphUninstall(
    _In_opt_ PWSTR DeviceName
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    SC_HANDLE scmHandle;
    SC_HANDLE serviceHandle;
    OBJECT_HANDLE_FLAG_INFORMATION handleFlagInfo;

    if (!DeviceName)
        DeviceName = KPH_DEVICE_SHORT_NAME;

    //Change handle protection
    handleFlagInfo.Inherit = FALSE;
    handleFlagInfo.ProtectFromClose = FALSE;

    NtSetInformationObject(
        PhKphHandle,
        ObjectHandleFlagInformation,
        &handleFlagInfo,
        sizeof(OBJECT_HANDLE_FLAG_INFORMATION)
    );

    CloseHandle(PhKphHandle);

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

    if (!scmHandle)
        return PhGetLastWin32ErrorAsNtStatus();

    serviceHandle = OpenService(scmHandle, DeviceName, SERVICE_STOP | DELETE);

    if (serviceHandle)
    {
        SERVICE_STATUS serviceStatus;

        ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus);

        if (!DeleteService(serviceHandle))
            status = PhGetLastWin32ErrorAsNtStatus();

        CloseServiceHandle(serviceHandle);
    }
    else
    {
        status = PhGetLastWin32ErrorAsNtStatus();
    }

    CloseServiceHandle(scmHandle);

    return status;
}

NTSTATUS KphpDeviceIoControl(
    _In_ ULONG KphControlCode,
    _In_ PVOID InBuffer,
    _In_ ULONG InBufferLength
    )
{
    IO_STATUS_BLOCK isb;

    return NtDeviceIoControlFile(
        PhKphHandle,
        NULL,
        NULL,
        NULL,
        &isb,
        KphControlCode,
        InBuffer,
        InBufferLength,
        NULL,
        0
        );
}

NTSTATUS KphGetFeatures(
    _Out_ PULONG Features
    )
{
    struct
    {
        PULONG Features;
    } input = { Features };

    return KphpDeviceIoControl(
        KPH_GETFEATURES,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCLIENT_ID ClientId
    )
{
    struct
    {
        PHANDLE ProcessHandle;
        ACCESS_MASK DesiredAccess;
        PCLIENT_ID ClientId;
    } input = { ProcessHandle, DesiredAccess, ClientId };

    return KphpDeviceIoControl(
        KPH_OPENPROCESS,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphOpenProcessToken(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE TokenHandle
    )
{
    struct
    {
        HANDLE ProcessHandle;
        ACCESS_MASK DesiredAccess;
        PHANDLE TokenHandle;
    } input = { ProcessHandle, DesiredAccess, TokenHandle };

    return KphpDeviceIoControl(
        KPH_OPENPROCESSTOKEN,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphOpenProcessJob(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE JobHandle
    )
{
    struct
    {
        HANDLE ProcessHandle;
        ACCESS_MASK DesiredAccess;
        PHANDLE JobHandle;
    } input = { ProcessHandle, DesiredAccess, JobHandle };

    return KphpDeviceIoControl(
        KPH_OPENPROCESSJOB,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphSuspendProcess(
    _In_ HANDLE ProcessHandle
    )
{
    struct
    {
        HANDLE ProcessHandle;
    } input = { ProcessHandle };

    return KphpDeviceIoControl(
        KPH_SUSPENDPROCESS,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphResumeProcess(
    _In_ HANDLE ProcessHandle
    )
{
    struct
    {
        HANDLE ProcessHandle;
    } input = { ProcessHandle };

    return KphpDeviceIoControl(
        KPH_RESUMEPROCESS,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphTerminateProcess(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
    )
{
    NTSTATUS status;
    struct
    {
        HANDLE ProcessHandle;
        NTSTATUS ExitStatus;
    } input = { ProcessHandle, ExitStatus };

    status = KphpDeviceIoControl(
        KPH_TERMINATEPROCESS,
        &input,
        sizeof(input)
        );

    // Check if we're trying to terminate the current process,
    // because kernel-mode can't do it.
    if (status == STATUS_CANT_TERMINATE_SELF)
    {
        RtlExitUserProcess(ExitStatus);
    }

    return status;
}

NTSTATUS KphReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
    )
{
    struct
    {
        HANDLE ProcessHandle;
        PVOID BaseAddress;
        PVOID Buffer;
        SIZE_T BufferSize;
        PSIZE_T NumberOfBytesRead;
    } input = { ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead };

    return KphpDeviceIoControl(
        KPH_READVIRTUALMEMORY,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    )
{
    struct
    {
        HANDLE ProcessHandle;
        PVOID BaseAddress;
        PVOID Buffer;
        SIZE_T BufferSize;
        PSIZE_T NumberOfBytesWritten;
    } input = { ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten };

    return KphpDeviceIoControl(
        KPH_WRITEVIRTUALMEMORY,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphReadVirtualMemoryUnsafe(
    _In_opt_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
    )
{
    struct
    {
        HANDLE ProcessHandle;
        PVOID BaseAddress;
        PVOID Buffer;
        SIZE_T BufferSize;
        PSIZE_T NumberOfBytesRead;
    } input = { ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead };

    return KphpDeviceIoControl(
        KPH_READVIRTUALMEMORYUNSAFE,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ KPH_PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    struct
    {
        HANDLE ProcessHandle;
        KPH_PROCESS_INFORMATION_CLASS ProcessInformationClass;
        PVOID ProcessInformation;
        ULONG ProcessInformationLength;
        PULONG ReturnLength;
    } input = { ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength };

    return KphpDeviceIoControl(
        KPH_QUERYINFORMATIONPROCESS,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ KPH_PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
    )
{
    struct
    {
        HANDLE ProcessHandle;
        KPH_PROCESS_INFORMATION_CLASS ProcessInformationClass;
        PVOID ProcessInformation;
        ULONG ProcessInformationLength;
    } input = { ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength };

    return KphpDeviceIoControl(
        KPH_SETINFORMATIONPROCESS,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCLIENT_ID ClientId
    )
{
    struct
    {
        PHANDLE ThreadHandle;
        ACCESS_MASK DesiredAccess;
        PCLIENT_ID ClientId;
    } input = { ThreadHandle, DesiredAccess, ClientId };

    return KphpDeviceIoControl(
        KPH_OPENTHREAD,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphOpenThreadProcess(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
    )
{
    struct
    {
        HANDLE ThreadHandle;
        ACCESS_MASK DesiredAccess;
        PHANDLE ProcessHandle;
    } input = { ThreadHandle, DesiredAccess, ProcessHandle };

    return KphpDeviceIoControl(
        KPH_OPENTHREADPROCESS,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphTerminateThread(
    _In_ HANDLE ThreadHandle,
    _In_ NTSTATUS ExitStatus
    )
{
    NTSTATUS status;
    struct
    {
        HANDLE ThreadHandle;
        NTSTATUS ExitStatus;
    } input = { ThreadHandle, ExitStatus };

    status = KphpDeviceIoControl(
        KPH_TERMINATETHREAD,
        &input,
        sizeof(input)
        );

    if (status == STATUS_CANT_TERMINATE_SELF)
    {
        RtlExitUserThread(ExitStatus);
    }

    return status;
}

NTSTATUS KphTerminateThreadUnsafe(
    _In_ HANDLE ThreadHandle,
    _In_ NTSTATUS ExitStatus
    )
{
    struct
    {
        HANDLE ThreadHandle;
        NTSTATUS ExitStatus;
    } input = { ThreadHandle, ExitStatus };

    return KphpDeviceIoControl(
        KPH_TERMINATETHREADUNSAFE,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphGetContextThread(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
    )
{
    struct
    {
        HANDLE ThreadHandle;
        PCONTEXT ThreadContext;
    } input = { ThreadHandle, ThreadContext };

    return KphpDeviceIoControl(
        KPH_GETCONTEXTTHREAD,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphSetContextThread(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext
    )
{
    struct
    {
        HANDLE ThreadHandle;
        PCONTEXT ThreadContext;
    } input = { ThreadHandle, ThreadContext };

    return KphpDeviceIoControl(
        KPH_SETCONTEXTTHREAD,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphCaptureStackBackTraceThread(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG FramesToSkip,
    _In_ ULONG FramesToCapture,
    _Out_writes_(FramesToCapture) PVOID *BackTrace,
    _Out_opt_ PULONG CapturedFrames,
    _Out_opt_ PULONG BackTraceHash
    )
{
    struct
    {
        HANDLE ThreadHandle;
        ULONG FramesToSkip;
        ULONG FramesToCapture;
        PVOID *BackTrace;
        PULONG CapturedFrames;
        PULONG BackTraceHash;
    } input = { ThreadHandle, FramesToSkip, FramesToCapture, BackTrace, CapturedFrames, BackTraceHash };

    return KphpDeviceIoControl(
        KPH_CAPTURESTACKBACKTRACETHREAD,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ KPH_THREAD_INFORMATION_CLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    struct
    {
        HANDLE ThreadHandle;
        KPH_THREAD_INFORMATION_CLASS ThreadInformationClass;
        PVOID ThreadInformation;
        ULONG ThreadInformationLength;
        PULONG ReturnLength;
    } input = { ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength };

    return KphpDeviceIoControl(
        KPH_QUERYINFORMATIONTHREAD,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ KPH_THREAD_INFORMATION_CLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
    )
{
    struct
    {
        HANDLE ThreadHandle;
        KPH_THREAD_INFORMATION_CLASS ThreadInformationClass;
        PVOID ThreadInformation;
        ULONG ThreadInformationLength;
    } input = { ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength };

    return KphpDeviceIoControl(
        KPH_SETINFORMATIONTHREAD,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphEnumerateProcessHandles(
    _In_ HANDLE ProcessHandle,
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_opt_ ULONG BufferLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    struct
    {
        HANDLE ProcessHandle;
        PVOID Buffer;
        ULONG BufferLength;
        PULONG ReturnLength;
    } input = { ProcessHandle, Buffer, BufferLength, ReturnLength };

    return KphpDeviceIoControl(
        KPH_ENUMERATEPROCESSHANDLES,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphEnumerateProcessHandles2(
    _In_ HANDLE ProcessHandle,
    _Out_ PKPH_PROCESS_HANDLE_INFORMATION *Handles
    )
{
    NTSTATUS status;
    PVOID buffer;
    ULONG bufferSize = 2048;

    buffer = VirtualAlloc(NULL, bufferSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

    while (TRUE)
    {
        status = KphEnumerateProcessHandles(
            ProcessHandle,
            buffer,
            bufferSize,
            &bufferSize
            );

        if (status == STATUS_BUFFER_TOO_SMALL)
        {
            VirtualFree(buffer, bufferSize, MEM_RELEASE);
            bufferSize = bufferSize * 2;
            buffer = VirtualAlloc(NULL, bufferSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        }
        else
        {
            break;
        }
    }

    if (!NT_SUCCESS(status))
    {
        VirtualFree(buffer, bufferSize, MEM_RELEASE);
        return status;
    }

    *Handles = buffer;

    return status;
}

NTSTATUS KphQueryInformationObject(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE Handle,
    _In_ KPH_OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    struct
    {
        HANDLE ProcessHandle;
        HANDLE Handle;
        KPH_OBJECT_INFORMATION_CLASS ObjectInformationClass;
        PVOID ObjectInformation;
        ULONG ObjectInformationLength;
        PULONG ReturnLength;
    } input = { ProcessHandle, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength };

    return KphpDeviceIoControl(
        KPH_QUERYINFORMATIONOBJECT,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphSetInformationObject(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE Handle,
    _In_ KPH_OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength
    )
{
    struct
    {
        HANDLE ProcessHandle;
        HANDLE Handle;
        KPH_OBJECT_INFORMATION_CLASS ObjectInformationClass;
        PVOID ObjectInformation;
        ULONG ObjectInformationLength;
    } input = { ProcessHandle, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength };

    return KphpDeviceIoControl(
        KPH_SETINFORMATIONOBJECT,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphDuplicateObject(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
    )
{
    NTSTATUS status;
    struct
    {
        HANDLE SourceProcessHandle;
        HANDLE SourceHandle;
        HANDLE TargetProcessHandle;
        PHANDLE TargetHandle;
        ACCESS_MASK DesiredAccess;
        ULONG HandleAttributes;
        ULONG Options;
    } input = { SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options };

    status = KphpDeviceIoControl(
        KPH_DUPLICATEOBJECT,
        &input,
        sizeof(input)
        );

    if (status == STATUS_CANT_TERMINATE_SELF)
    {
        // We tried to close a handle in the current process.
        if (Options & DUPLICATE_CLOSE_SOURCE)
            status = NtClose(SourceHandle);
    }

    return status;
}

NTSTATUS KphOpenDriver(
    _Out_ PHANDLE DriverHandle,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    struct
    {
        PHANDLE DriverHandle;
        POBJECT_ATTRIBUTES ObjectAttributes;
    } input = { DriverHandle, ObjectAttributes };

    return KphpDeviceIoControl(
        KPH_OPENDRIVER,
        &input,
        sizeof(input)
        );
}

NTSTATUS KphQueryInformationDriver(
    _In_ HANDLE DriverHandle,
    _In_ DRIVER_INFORMATION_CLASS DriverInformationClass,
    _Out_writes_bytes_(DriverInformationLength) PVOID DriverInformation,
    _In_ ULONG DriverInformationLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    struct
    {
        HANDLE DriverHandle;
        DRIVER_INFORMATION_CLASS DriverInformationClass;
        PVOID DriverInformation;
        ULONG DriverInformationLength;
        PULONG ReturnLength;
    } input = { DriverHandle, DriverInformationClass, DriverInformation, DriverInformationLength, ReturnLength };

    return KphpDeviceIoControl(
        KPH_QUERYINFORMATIONDRIVER,
        &input,
        sizeof(input)
        );
}

