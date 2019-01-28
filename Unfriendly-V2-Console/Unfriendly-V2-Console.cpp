#include "DLLInjectorDector.h"
#include "AbortFailureDetects.h"
#include "DriverLoader\\driver.h"
#include "DriverIO.h"
#include "openssl\\md5.h"
#include "DriverIORequests.h"
#include "Formulas.h"
#include "Anti Debug.h"
#include "DLLInjectionDetector\Utils.h"
#include "Utlis.h"
#include "NamePipe.h"
#include "DigitalSignatureChecker.h"

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <sys/types.h>  
#include <signal.h> 
#include <vector>

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")


// Varibles
HANDLE hDriver; // Driver
ULONG NamePipe1, NamePipe2, NamePipe3, NamePipe4, NamePipe5;
ULONG FOR1, FOR2, FOR3, FOR4, FOR5;
ULONG CHECK1, CHECK2, CHECK3, CHECK4, CHECK5;
ULONG CHECK_CREATEPROCESS1, CHECK_CREATEPROCESS2, CHECK_CREATEPROCESS3, CHECK_CREATEPROCESS4, CHECK_CREATEPROCESS5;
int GameProcessID = 0;

// Functions
bool CheckTestMode();
int randNum(int min, int max);

DWORD TidHeartBeat = 0;
DWORD TidGameValidChech = 0;
DWORD TidAntiDebug = 0;
DWORD tidDriverScanner = 0;
DWORD TidCommonCheatScanner = 0;
DWORD TidOverlayScanner = 0;
DWORD TidAntiKill = 0;
DWORD TidMainThread = 0;

BOOL HeartBeatThreadAntiKill = FALSE;
HANDLE hHeartBeatThread = NULL;
DWORD WINAPI HeartBeatThread()
{
	AntiDebug::HideThread(GetCurrentThread());
	while (1)
	{
		srand(time(0));
		FOR1 = randNum(2, 63);
		FOR2 = randNum(3, 34);
		FOR3 = randNum(8, 45);
		FOR4 = randNum(5, 67);
		FOR5 = randNum(2, 12);

		if (DriverRequest::HEARTBEATMAINSTART_FORWARD_Function(FOR1, FOR2, FOR3, FOR4, FOR5))
		{
			KERNEL_HEARTBEAT_REQUEST RETURNED_HEARTBEAT_CREATEPROCESS = DriverRequest::HEARTBEATMAINSTART_RETURN_Function();


			if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt1 == HeartbeatFormula::Formula1(FOR1))
			{
				if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt2 == HeartbeatFormula::Formula2(FOR2))
				{
					if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt3 == HeartbeatFormula::Formula3(FOR3))
					{
						if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt4 == HeartbeatFormula::Formula4(FOR4))
						{
							if (RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt5 == HeartbeatFormula::Formula5(FOR5))
							{
								KERNEL_HEARTBEAT_REQUEST RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS = DriverRequest::HEARTBEATCREATEPROCESS_RETURN_Function();

								CHECK_CREATEPROCESS1 = HeartbeatFormula::Formula1(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt1);
								CHECK_CREATEPROCESS2 = HeartbeatFormula::Formula2(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt2);
								CHECK_CREATEPROCESS3 = HeartbeatFormula::Formula3(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt3);
								CHECK_CREATEPROCESS4 = HeartbeatFormula::Formula4(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt4);
								CHECK_CREATEPROCESS5 = HeartbeatFormula::Formula5(RETURNED_HEARTBEAT_CREATEPROCESS_CREATEPROCESS.Encrypt5);
								if (DriverRequest::HEARTBEATCREATEPROCESS_FORWARD_Function(CHECK_CREATEPROCESS1, CHECK_CREATEPROCESS2, CHECK_CREATEPROCESS3, CHECK_CREATEPROCESS4, CHECK_CREATEPROCESS5))
								{
									if ( CUtils::IsSuspendedThread(TidMainThread))
									{
										ErrorHandler::ErrorMessage("63452 ( Thread Mismatched )", 6);
									}

									HeartBeatThreadAntiKill = TRUE;
									Sleep(400);
								}
								else
								{
									ErrorHandler::ErrorMessage("601 ( HeartBeat System Failed )", 5);
									Sleep(3000);
									exit(1);
								}

							}
							else
							{
								ErrorHandler::ErrorMessage("602 ( HeartBeat System Failed )", 5);
								Sleep(3000);
								exit(1);
							}
						}
						else
						{
							ErrorHandler::ErrorMessage("603 ( HeartBeat System Failed )", 5);
							Sleep(3000);
							exit(1);
						}
					}
					else
					{
						ErrorHandler::ErrorMessage("604 ( HeartBeat System Failed )", 5);
						Sleep(3000);
						exit(1);
					}
				}
				else
				{
					ErrorHandler::ErrorMessage("605 ( HeartBeat System Failed )", 5);
					Sleep(3000);
					exit(1);
				}
			}
			else
			{
				ErrorHandler::ErrorMessage("606 ( HeartBeat System Failed )", 5);
				Sleep(3000);
				exit(1);
			}
		}
		else
		{
			ErrorHandler::ErrorMessage("607 ( HeartBeat System Failed )", 5);
			Sleep(3000);
			exit(1);
		}
	}
	return 0;
}


BOOL GameCheckerAntiKill = FALSE;
HANDLE hGameChecker = NULL;
DWORD WINAPI GameValidCheckThread()
{
	AntiDebug::HideThread(GetCurrentThread());
	while (1)
	{
		if (GameProcessID == 0)
		{
			Sleep(200);
		}
		else
		{
			if (!ErrorHandler::isProcessRunning(GameProcessID))
			{
				ErrorHandler::ErrorMessage("901 ( Game Stopped Running )", 3);
			}
		}

		if (CUtils::IsSuspendedThread(TidAntiDebug)
			|| CUtils::IsSuspendedThread(TidAntiKill))
		{
			ErrorHandler::ErrorMessage("32156 ( Thread Mismatched )", 6);
		}

		GameCheckerAntiKill = TRUE;
	}
}


BOOL AntiDebugAntiKill = FALSE;
HANDLE hAntiDebug = NULL;
DWORD WINAPI AntiDebugThread()
{
	AntiDebug::HideThread(GetCurrentThread());
	while (1)
	{
		if (AntiDebug::CheckRemoteDebuggerPresentAPI())
		{
			ErrorHandler::ErrorMessage("701", 6);
		}
		Sleep(200);
		if (AntiDebug::IsDebuggerPresentAPI())
		{
			ErrorHandler::ErrorMessage("702", 6);
		}
		Sleep(200);
		if (AntiDebug::HardwareBreakpoints())
		{
			ErrorHandler::ErrorMessage("703", 6);
		}
		Sleep(200);
		if (AntiDebug::MemoryBreakpoints_PageGuard())
		{
			ErrorHandler::ErrorMessage("704", 6);
		}
		Sleep(200);
		if (AntiDebug::UnhandledExcepFilterTest())
		{
			ErrorHandler::ErrorMessage("706", 6);
		}
		Sleep(200);
		if (AntiDebug::SharedUserData_KernelDebugger())
		{
			ErrorHandler::ErrorMessage("707", 6);
		}
		Sleep(200);

		if (CUtils::IsSuspendedThread(TidAntiDebug)
			|| CUtils::IsSuspendedThread(TidAntiKill))
		{
			ErrorHandler::ErrorMessage("34524 ( Thread Mismatched )", 6);
		}

		AntiDebugAntiKill = TRUE;
	}
}


BOOL DriversScanAntiKill = FALSE;
HANDLE hDriversScan = NULL;
DWORD WINAPI DriversScanThread()
{
	AntiDebug::HideThread(GetCurrentThread());
	while (1)
	{
		LPVOID drivers[1024];
		DWORD cbNeeded;
		int cDrivers, i;

		if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
		{
			/*
			TCHAR szDriver[1024];

			cDrivers = cbNeeded / sizeof(drivers[0]);

			for (i = 0; i < cDrivers; i++)
			{
				if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
				{
					TCHAR szName[MAX_PATH] = { 0 };

					GetDeviceDriverFileName(drivers[i], szName, MAX_PATH);
					//_tprintf(TEXT("%d: %s\n"), i + 1, szName);
					Sleep(10);
				}
			}*/
			Sleep(100);
		}
		else
		{
			ErrorHandler::ErrorMessage("9753 ( Please Restart Your PC )", 5);
		}

		if (CUtils::IsSuspendedThread(TidAntiDebug)
			|| CUtils::IsSuspendedThread(TidAntiKill))
		{
			ErrorHandler::ErrorMessage("565435 ( Thread Mismatched )", 6);
		}
		DriversScanAntiKill = TRUE;
	}
}


BOOL CommonCheatsScannerAntiKill = FALSE;
HANDLE hCommonCheatsScanner = NULL;
DWORD WINAPI CommonCheatsScannerThread()
{
	AntiDebug::HideThread(GetCurrentThread());
	while (1)
	{
		const char DebuggingDrivers[9][20] = {
			"\\\\.\\EXTREM", "\\\\.\\ICEEXT",
			"\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
			"\\\\.\\SIWVID", "\\\\.\\SYSER",
			"\\\\.\\TRW", "\\\\.\\SYSERBOOT",
			"\0"
		};


		for (int i = 0; DebuggingDrivers[i][0] != '\0'; i++) {
			HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
			if (h != INVALID_HANDLE_VALUE)
			{
				CloseHandle(h);
				ErrorHandler::ErrorMessage("2001 ( Debugging Drivers Found )", 6);
			}
			CloseHandle(h);
			Sleep(200);
		}

		const char CheatingDrivers[5][20] = {
			"\\\\.\\kernelhop", "\\\\.\\BlackBone",
			"\\\\.\\VBoxDrv", "\\\\.\\Htsysm72FB",
			"\0"
		};


		for (int i = 0; CheatingDrivers[i][0] != '\0'; i++) {
			HANDLE hCheats = CreateFileA(CheatingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
			if (hCheats != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hCheats);
				ErrorHandler::ErrorMessage("3001 ( Cheating Drivers Found )", 2);
			}
			CloseHandle(hCheats);
			Sleep(200);
		}

		if (CUtils::IsSuspendedThread(TidAntiDebug)
			|| CUtils::IsSuspendedThread(TidAntiKill))
		{
			ErrorHandler::ErrorMessage("34536 ( Thread Mismatched )", 6);
		}

		CommonCheatsScannerAntiKill = TRUE;
		Sleep(200);
	}
}


BOOL OverlayScannerAntiKill = FALSE;
HANDLE hOverlayScanner = NULL;
DWORD WINAPI OverlayScannerThread()
{
	// https://www.unknowncheats.me/forum/anti-cheat-bypass/263403-window-hijacking-dont-overlay-betray.html
	AntiDebug::HideThread(GetCurrentThread());
	while (1)
	{
		OverlayFinderParams params;
		params.style = WS_VISIBLE;
		params.styleEx = WS_EX_LAYERED | WS_EX_TRANSPARENT;
		params.percentMainScreen = 90.0f;
		params.satisfyAllCriteria = true;
		std::vector<HWND> hwnds = Utlis::OverlayFinder(params);

		for (int i(0); i < hwnds.size(); ++i) {
			DWORD ProcessIDForOverlay = 0;
			DWORD tid = GetWindowThreadProcessId(hwnds[i], &ProcessIDForOverlay);
			if (ErrorHandler::isProcessRunning(ProcessIDForOverlay))
			{
				DriverRequest::TerminatePrcoess(ProcessIDForOverlay);
				Sleep(200);
			}
			Sleep(200);
		}

		OverlayScannerAntiKill = TRUE;
		Sleep(200);
	}

}


BOOL AntiKillBool = FALSE;
HANDLE hAntiKill = NULL;
DWORD WINAPI AntiKillThread()
{
	AntiDebug::HideThread(GetCurrentThread());
	while (1)
	{
		if (CUtils::IsSuspendedThread(TidHeartBeat)
			|| CUtils::IsSuspendedThread(tidDriverScanner)
			|| CUtils::IsSuspendedThread(TidCommonCheatScanner)
			|| CUtils::IsSuspendedThread(TidOverlayScanner)
			|| CUtils::IsSuspendedThread(TidGameValidChech)
			|| CUtils::IsSuspendedThread(TidMainThread)
			|| CUtils::IsSuspendedThread(TidAntiDebug))
		{
			ErrorHandler::ErrorMessage("34536 ( Thread Mismatched )", 6);
		}
		else
		{
			Sleep(200);
		}
	}

}


bool IsSystemCodeIntegrityEnabled()
{
	//https://stackoverflow.com/questions/40084077/can-i-have-any-way-to-detect-the-driver-signing-policy-status/50944791
	typedef NTSTATUS(__stdcall* td_NtQuerySystemInformation)(
		ULONG           SystemInformationClass,
		PVOID           SystemInformation,
		ULONG           SystemInformationLength,
		PULONG          ReturnLength
		);

	struct SYSTEM_CODEINTEGRITY_INFORMATION {
		ULONG Length;
		ULONG CodeIntegrityOptions;
	};

	static td_NtQuerySystemInformation NtQuerySystemInformation = (td_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	SYSTEM_CODEINTEGRITY_INFORMATION Integrity = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 0 };
	NTSTATUS status = NtQuerySystemInformation(103, &Integrity, sizeof(Integrity), NULL);

	return (status && (Integrity.CodeIntegrityOptions & 1));
}

void OnExit()
{
	if (GameProcessID != 0)
	{
		if (ErrorHandler::isProcessRunning(GameProcessID))
		{
			DriverRequest::TerminatePrcoess(GameProcessID);
		}
	}
	ErrorHandler::UnloadDriver();

}


int main()
{
	using namespace std;
	//FreeConsole();
	InitializeDLLCheck();
	InitializeThreadCheck();
	TidMainThread = GetCurrentThreadId();

	if (IsSystemCodeIntegrityEnabled())
	{
		ErrorHandler::ErrorMessage("0392 Test Mode Is Enabled. Please Disable It", 6);
	}

	if (Utlis::IsRunAsAdministrator)
	{
		HANDLE CheckHandle = CreateFileA("\\\\.\\UnfriendlyDriver", GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

		if (CheckHandle != INVALID_HANDLE_VALUE)
		{
			ErrorHandler::UnloadDriver();
			CloseHandle(CheckHandle);
		}

		ErrorHandler::LoadDriver();
		Sleep(100);
		hDriver = CreateFileA("\\\\.\\UnfriendlyDriver", GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);


		//printf("File Size: %d \n", WhiteListedDLLs::GetFileSize("Unfriendly-V2-DLL.dll"));

		if (hDriver)
		{
			if (DriverRequest::SendCurrentProcessID())
			{
				hAntiDebug = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiDebugThread, NULL, 0, &TidAntiDebug);

				srand(time(0));
				FOR1 = randNum(1, 35);
				FOR2 = randNum(1, 23);
				FOR3 = randNum(1, 23);
				FOR4 = randNum(1, 23);
				FOR5 = randNum(1, 34);
				if (DriverRequest::HEARTBEATMAINSTART_FORWARD_Function(FOR1, FOR2, FOR3, FOR4, FOR5))
				{
					KERNEL_HEARTBEAT_REQUEST RETURNED_HEARTBEAT = DriverRequest::HEARTBEATMAINSTART_RETURN_Function();

					ULONG TEST1 = HeartbeatFormula::Formula1(FOR1);
					ULONG TEST2 = RETURNED_HEARTBEAT.Encrypt1;

					if (RETURNED_HEARTBEAT.Encrypt1 == HeartbeatFormula::Formula1(FOR1))
					{
						if (RETURNED_HEARTBEAT.Encrypt2 == HeartbeatFormula::Formula2(FOR2))
						{
							if (RETURNED_HEARTBEAT.Encrypt3 == HeartbeatFormula::Formula3(FOR3))
							{
								if (RETURNED_HEARTBEAT.Encrypt4 == HeartbeatFormula::Formula4(FOR4))
								{
									if (RETURNED_HEARTBEAT.Encrypt5 == HeartbeatFormula::Formula5(FOR5))
									{

										KERNEL_HEARTBEAT_REQUEST RETURNED_HEARTBEAT_CREATEPROCESS = DriverRequest::HEARTBEATCREATEPROCESS_RETURN_Function();

										CHECK_CREATEPROCESS1 = HeartbeatFormula::Formula1(RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt1);
										CHECK_CREATEPROCESS2 = HeartbeatFormula::Formula2(RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt2);
										CHECK_CREATEPROCESS3 = HeartbeatFormula::Formula3(RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt3);
										CHECK_CREATEPROCESS4 = HeartbeatFormula::Formula4(RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt4);
										CHECK_CREATEPROCESS5 = HeartbeatFormula::Formula5(RETURNED_HEARTBEAT_CREATEPROCESS.Encrypt5);

										if (DriverRequest::HEARTBEATCREATEPROCESS_FORWARD_Function(CHECK_CREATEPROCESS1, CHECK_CREATEPROCESS2, CHECK_CREATEPROCESS3, CHECK_CREATEPROCESS4, CHECK_CREATEPROCESS5))
										{
											hHeartBeatThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HeartBeatThread, NULL, 0, &TidHeartBeat);
											hDriversScan = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DriversScanThread, NULL, 0, &tidDriverScanner);
											hCommonCheatsScanner = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CommonCheatsScannerThread, NULL, 0, &TidCommonCheatScanner);
											hOverlayScanner = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OverlayScannerThread, NULL, 0, &TidOverlayScanner);


											STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
											PROCESS_INFORMATION ProcessInfo;
											if (CreateProcess("D:\\SteamLibrary\\steamapps\\common\\Fatality\\Fatality.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
											{
												BlockInput(TRUE);
												Utlis::Injection(L"Unfriendly-V2-DLL.dll", ProcessInfo.dwProcessId);
												GameProcessID = ProcessInfo.dwProcessId;
												if (DriverRequest::SendProcessIDs(GameProcessID))
												{
													CloseHandle(ProcessInfo.hProcess);
													CloseHandle(ProcessInfo.hThread);
													

													BlockInput(FALSE);

													hGameChecker = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GameValidCheckThread, NULL, 0, &TidGameValidChech);
													hAntiKill = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AntiKillThread, NULL, 0, &TidAntiKill);

													KERNEL_THREAD_REQUEST Threads;

													Threads.ThreadID = TidAntiDebug;
													Threads.ThreadID2 = TidHeartBeat;
													Threads.ThreadID3 = tidDriverScanner;
													Threads.ThreadID4 = TidCommonCheatScanner;
													Threads.ThreadID5 = TidOverlayScanner;
													Threads.ThreadID6 = TidGameValidChech;
													Threads.ThreadID7 = TidAntiKill;
													Threads.ThreadID8 = TidMainThread;

													if (DriverRequest::SendProtectedThreadID(Threads))
													{
														while (1)
														{
															atexit(OnExit);
															Sleep(4000);
															if (CUtils::IsSuspendedThread(TidHeartBeat)
																|| CUtils::IsSuspendedThread(tidDriverScanner)
																|| CUtils::IsSuspendedThread(TidGameValidChech)
																|| CUtils::IsSuspendedThread(TidCommonCheatScanner)
																|| CUtils::IsSuspendedThread(TidOverlayScanner)
																|| CUtils::IsSuspendedThread(TidAntiDebug)
																|| CUtils::IsSuspendedThread(TidAntiKill))
															{
																ErrorHandler::ErrorMessage("32947 ( Thread Mismatched )", 6);
															}

															if (IsSystemCodeIntegrityEnabled())
															{
																ErrorHandler::ErrorMessage("0392 Test Mode Is Enabled. Please Disable It", 6);
															}

															if (OverlayScannerAntiKill && CommonCheatsScannerAntiKill && DriversScanAntiKill && AntiDebugAntiKill && HeartBeatThreadAntiKill)
															{
																OverlayScannerAntiKill = FALSE;
																CommonCheatsScannerAntiKill = FALSE;
																DriversScanAntiKill = FALSE;
																AntiDebugAntiKill = FALSE;
																HeartBeatThreadAntiKill = FALSE;
															}
															else
															{
																ErrorHandler::ErrorMessage("9452 ( Thread Mismatched )", 5);
															}

														}
													}
													else
													{
														BlockInput(FALSE);
														ErrorHandler::ErrorMessage("43524 ( Thread Mismatched )", 5);
													}
												}
												else
												{
													ErrorHandler::ErrorMessage("202 ( Driver Not Found )", 1);
												}
											}
											else
											{
												ErrorHandler::ErrorMessage("945 ( Failed To Start Game )", 1);
											}

										}
										else
										{
											ErrorHandler::ErrorMessage("207 ( Driver Not Found )", 1);

										}

									}
									else
									{
										ErrorHandler::ErrorMessage("206 ( Driver Not Found )", 1);
									}
								}
								else
								{
									ErrorHandler::ErrorMessage("205 ( Driver Not Found )", 1);
								}
							}
							else
							{
								ErrorHandler::ErrorMessage("204 ( Driver Not Found )", 1);
							}
						}
						else
						{
							ErrorHandler::ErrorMessage("203 ( Driver Not Found )", 1);
						}
					}
					else
					{
						ErrorHandler::ErrorMessage("249 ( Driver Not Found )", 1);
					}

				}
				else
				{
					ErrorHandler::ErrorMessage("201 ( Driver Not Found )", 1);
				}
			}
			else
			{
				ErrorHandler::ErrorMessage("301 ( Driver Not Found )", 1);
			}

		}
		else
		{
			ErrorHandler::ErrorMessage("67 ( Driver Not Found )", 1);
		}

	}
	else
	{
		ErrorHandler::ErrorMessage("1001 ( Run As Admin )", 1);
	}

	return 0;
}


int randNum(int min, int max)
{
	return rand() % max + min;
}
