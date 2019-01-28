#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <ctime>
#include <fstream>
#include <iterator>
#include <comdef.h>
#include <Wbemidl.h>
#include <VersionHelpers.h>
#include <atlstr.h>
#include <wbemidl.h>
#include <sstream>
#include <vector>

// Request to write to kernel mode
#define IO_SEND_PROCESSID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define IO_SEND_CURRENTPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0709, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define IO_SEND_CURRENT_PROCESS_ID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0706, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define HEARTBEATMAINSTART_FORWARD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define HEARTBEATMAINSTART_RETURN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define HEARTBEATCREATEPROCESS_FORWARD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0704, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define HEARTBEATCREATEPROCESS_RETURN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0705, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define THREADPROTECTION_HEARTBEATFUCNTION_FORWARD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0707, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define THREADPROTECTION_HEARTBEATFUCNTION_RETURN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0708, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define IO_VADPROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define IO_TerminateProcess CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write to kernel mode
#define IO_PROTECTIONT_THREADS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9432, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _HIDE_VAD
{
	ULONGLONG base;             // Region base address
	ULONGLONG size;             // Region size
	ULONG pid;                  // Target process ID
} HIDE_VAD, *PHIDE_VAD;


typedef struct _KERNEL_READ_REQUEST
{
	ULONG UsermodeProgram;
	ULONG GameProcess;

} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;


typedef struct _KERNEL_HEARTBEAT_REQUEST
{
	ULONG Encrypt1;
	ULONG Encrypt2;
	ULONG Encrypt3;
	ULONG Encrypt4;
	ULONG Encrypt5;

} KERNEL_HEARTBEAT_REQUEST, *PKERNEL_HEARTBEAT_REQUEST;

typedef struct _KERNEL_THREAD_REQUEST
{
	ULONG ThreadID;
	ULONG ThreadID2;
	ULONG ThreadID3;
	ULONG ThreadID4;
	ULONG ThreadID5;
	ULONG ThreadID6;
	ULONG ThreadID7;
	ULONG ThreadID8;

} KERNEL_THREAD_REQUEST, *PKERNEL_THREAD_REQUEST;