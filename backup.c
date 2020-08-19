/*
 * Copyright (c) 2020 Karim Kanso. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

/**
 * compile with:
 *  x86_64-w64-mingw32-gcc -Wall -Wpedantic -o backup.exe backup.c -Wl,-s -Os
 */

// https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
) {
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!LookupPrivilegeValueA(
          NULL,           // lookup privilege on local system
          lpszPrivilege,  // privilege to lookup
          &luid)) {       // receives LUID of privilege
    fprintf(stderr, "LookupPrivilegeValue error: %lu\n", GetLastError());
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    tp.Privileges[0].Attributes = 0;

  // Enable the privilege or disable all privileges.
  if (!AdjustTokenPrivileges(
          hToken,
          FALSE,
          &tp,
          sizeof(TOKEN_PRIVILEGES),
          (PTOKEN_PRIVILEGES)NULL,
          (PDWORD)NULL)) {
    fprintf(stderr, "AdjustTokenPrivileges error: %lu\n", GetLastError());
    return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
    fprintf(stderr, "The token does not have the specified privilege. \n");
    return FALSE;
  }

  return TRUE;
}

BOOL enable_privileges(const char** pp_ch_privs) {
  BOOL b_result = TRUE;
  // necerssary to open process token, so CreateProcess works
  HANDLE h_proc = GetCurrentProcess();
  HANDLE h_token = NULL;
  if (h_proc == NULL) {
    fprintf(stderr, "fail to GetCurrentProcess: %lu\n", GetLastError());
    goto DONE;
  }
  if (!OpenProcessToken(
          h_proc,
          TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
          &h_token)) {
    fprintf(stderr, "fail to get token: %lu\n", GetLastError());
    goto DONE;
  }
  for (; pp_ch_privs != NULL && *pp_ch_privs != NULL; pp_ch_privs++) {
    //printf("enabling %s\n", *pp_ch_privs);
    if (!SetPrivilege(h_token, *pp_ch_privs, true)) {
      fprintf(stderr, "failed to enable privilege: %s\n", *pp_ch_privs);
      b_result = FALSE;
    }
  }

 DONE:
  if (h_token) {
    CloseHandle(h_token);
    h_token = NULL;
  }
  if (h_proc) {
    CloseHandle(h_proc);
    h_proc = NULL;
  }
  return b_result;
}

BOOL enable_privileges_va(int i, ...) {
  const char** pp_ch_privs =
    (const char**)LocalAlloc(LPTR, sizeof(const char*) * (i + 1));
  va_list argptr;
  va_start(argptr, i);

  for (int j = 0; j < i; j++) {
    pp_ch_privs[j] = va_arg(argptr, const char*);
  }

  BOOL b = enable_privileges(pp_ch_privs);
  va_end(argptr);
  LocalFree(pp_ch_privs);
  pp_ch_privs = NULL;
  return b;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s dir-or-file\n", argv[0]);
    exit(0);
  }

  if (!enable_privileges_va(1, "SeBackupPrivilege")) {
    fprintf(stderr, "unable to enable privilege\n");
    return 0;
  }

  HANDLE h_file = CreateFileA(
      argv[1],
      GENERIC_READ, FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,
      NULL);
  if (h_file == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "fail to CreateFile: %lu\n", GetLastError());
    return 0;
  }

  BY_HANDLE_FILE_INFORMATION s_file_information;
  if (!GetFileInformationByHandle(h_file, &s_file_information)) {
    fprintf(stderr, "fail GetFileInformationByHandle: %lu\n", GetLastError());
    goto DONE;
  }

  if (s_file_information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    char ch_command[MAX_PATH + 20];
    snprintf(
        ch_command,
        sizeof ch_command / sizeof ch_command[0],
        "cmd /c dir /a \"%s\"",
        argv[1]);
    STARTUPINFOA s_si;
    memset(&s_si, 0, sizeof(s_si));
    s_si.cb = sizeof(s_si);
    PROCESS_INFORMATION s_pi;
    memset(&s_pi, 0, sizeof(s_pi));
    if (!CreateProcessA(
            NULL,
            ch_command,
            NULL,
            NULL,
            TRUE,
            0,
            NULL,
            NULL,
            &s_si,
            &s_pi
        )) {
      fprintf(stderr, "fail to CreateProcess: %lu\n", GetLastError());
      goto DONE;
    }
    WaitForSingleObject(s_pi.hProcess, INFINITE);
  } else {
    fprintf(stderr, "Attempting to cat: %s\n", argv[1]);
    HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    unsigned char ch_buffer[1024];

    DWORD dw_read = 0;
    while (ReadFile(h_file, ch_buffer, sizeof ch_buffer, &dw_read, NULL)) {
      DWORD dw_written = 0;
      if (!WriteFile(h_stdout, ch_buffer, dw_read, &dw_written, NULL)) {
        fprintf(stderr, "fail to WriteFile: %lu\n", GetLastError());
        break;
      }

      if (dw_read != sizeof ch_buffer) {
        goto DONE;
      }
    }
    fprintf(stderr, "fail to ReadFile: %lu\n", GetLastError());
  }

 DONE:
  CloseHandle(h_file);
  h_file = NULL;

  return 0;
}
