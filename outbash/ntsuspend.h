#pragma once
int ImportNtDll(void);
bool NT_Suspend(HANDLE hProcess);
bool NT_Resume (HANDLE hProcess);
