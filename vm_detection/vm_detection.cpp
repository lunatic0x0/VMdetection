#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<psapi.h>
#include<stdio.h>
#include<iphlpapi.h>
#include<stdlib.h>
#include<tlhelp32.h>
#include<tchar.h>
#pragma comment(lib, "IPHLPAPI.lib")

#define ARRAY_SIZE 1024						// For Drivers

void GetErrorMessage(int errorcode) {

	LPWSTR text;
	DWORD error = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,nullptr, errorcode, NULL, (LPWSTR)&text, 0, nullptr);

	if (error > 0) {

		printf("[-] Error: %ws", text);
		::LocalFree(text);
	}
}

char* CheckMacAdress() {
	
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;

	DWORD dwBufLen = sizeof(PIP_ADAPTER_INFO);

	char* mac_addr_buffer = (char*)malloc(18);
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(PIP_ADAPTER_INFO));

	if (pAdapterInfo == NULL) {
		printf("[-] Error while allocating memory for pAdapterInfo\n");
		free(mac_addr_buffer);
		return NULL;
	}


	if (::GetAdaptersInfo(pAdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (pAdapterInfo == NULL) {
			printf("[-] Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr_buffer);
			return NULL;
		}
	}

	if (::GetAdaptersInfo(pAdapterInfo, &dwBufLen) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		do {
			sprintf(mac_addr_buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
			pAdapter->Address[0], pAdapter->Address[1],
			pAdapter->Address[2], pAdapter->Address[3],
			pAdapter->Address[4], pAdapter->Address[5]);
		
			//printf("Address: %s, mac: %s\n", pAdapter->IpAddressList.IpAddress.String, mac_addr_buffer);
			char* vmware_result = strstr(mac_addr_buffer, "00:0C:29");					// Can add more mac address check like 00:05:56
			if (vmware_result) {
				printf("[+] VM Detected using Default VMware Mac Address identifier group: %s\n", vmware_result);
				return NULL;
			}

			char* vbox_result = strstr(mac_addr_buffer, "08:00:27");
			if (vbox_result) {
				printf("[+] VM Detected using Default VBox Mac Address identifier group: %s\n", vbox_result);
				return NULL;
			}
			pAdapter = pAdapter->Next;
		} while (pAdapter);
	}
	printf("[-] VM Detection Failed using Mac Address identifier group\n");
	free(pAdapterInfo);
	return mac_addr_buffer;
}

bool CheckIOCommunicatonPorts() {

	bool io_port_result = true;
	__try {
		__asm {
			
			push edx
			push ecx
			push ebx
			
			mov eax, 'VMXh'			// magic number = 0x564D5868
			mov ebx, 0
			mov ecx, 10
			mov edx, 'VX'

			in eax, dx
			cmp ebx, 'VMXh'
			setz [io_port_result]

			pop ebx
			pop ecx
			pop edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		io_port_result = false;
	}

	return io_port_result;
}

int CheckCPUInstruction() {

	int result = 0;

	__try {
	
		__asm {
		
			push eax
			push ebx
			push edx
			push ecx

			xor eax, eax
			mov eax, 1
			cpuid
			bt ecx, 0x1f
			jb r_dest
			jmp f_dest

			r_dest:
				mov eax, 1
				mov [result], eax

			f_dest:
				pop ecx
				pop edx
				pop ebx
				pop eax

		}
	}__except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}

	return result;
}

int CheckVMwareTools() {

	HKEY hVMToolKey;
	char* vmtool1_buffer;
	DWORD size = 256;
	DWORD type;
	vmtool1_buffer = (char*)malloc(sizeof(char) * size);

	LSTATUS RegOpenStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VMTools", 0, KEY_READ, &hVMToolKey);
	if (RegOpenStatus != ERROR_SUCCESS) {
		printf("Could not open the Key: HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\VmTools\n");
		printf("VMTools is not installed\n");
		free(vmtool1_buffer);
		return 0;
	}

	DWORD RegQueryStatus = RegQueryValueExA(hVMToolKey, "ImagePath", NULL, &type, (LPBYTE)vmtool1_buffer, &size);
	while (RegQueryStatus == ERROR_MORE_DATA) {
		size += 256;
		vmtool1_buffer = (char*)realloc(vmtool1_buffer, size);
		RegQueryStatus = RegQueryValueExA(hVMToolKey, "0", NULL, &type, (LPBYTE)vmtool1_buffer, &size);
	}

	if (RegQueryStatus == ERROR_SUCCESS) {
		char* lower_case_value = CharLowerA((char*)vmtool1_buffer);
		char* result = strstr(lower_case_value, "vmtoolsd.exe");
		if (result) {
			printf("[+] VMware Tools Detected Using Registry Check of HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\VMTools\n");
		}
		else {
			printf("[+] VMware Tools Detection Failed Using Registry Check of HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\VMTools\n");
		}
	}
	RegCloseKey(hVMToolKey);
	free(vmtool1_buffer);
	return 0;
}

int CheckRegistry() {
	
	HKEY hKey;
	char* disk_enum_buffer;
	DWORD size = 256;
	DWORD type;
	disk_enum_buffer = (char*)malloc(sizeof(char)*size);
	
	LSTATUS RegOpenStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\disk\\Enum", 0, KEY_READ, &hKey);
	if (RegOpenStatus != ERROR_SUCCESS) {
		free(disk_enum_buffer);
		return 0;
	}

	DWORD RegQueryStatus = RegQueryValueExA(hKey, "0", NULL, &type, (LPBYTE)disk_enum_buffer, &size);	
	while (RegQueryStatus == ERROR_MORE_DATA) {
		size += 256;
		disk_enum_buffer = (char*)realloc(disk_enum_buffer, size);
		RegQueryStatus = RegQueryValueExA(hKey, "0", NULL, &type, (LPBYTE)disk_enum_buffer, &size);
	}

	if (RegQueryStatus == ERROR_SUCCESS) {
		char* lower_case_value = CharLowerA((char*)disk_enum_buffer);
		char* result = strstr(lower_case_value, "vmware");
		if (result) {
			printf("[+] VM Detected Using Registry Check: HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\disk\\Enum\n");
			printf("[+] Checking if VMware Tools are installed or not .....\n");
			CheckVMwareTools();
		}
		else {
			printf("[-] VM Detection Failed Using Registry Check of HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\disk\\Enum\n");
		}
	}

	RegCloseKey(hKey);
	free(disk_enum_buffer);
	return 0;
}

DWORD CheckRunningVMProcess() {

	DWORD pid = 0;
	PROCESSENTRY32 pe;
	HANDLE hSnap;

	pe.dwSize = sizeof(PROCESSENTRY32);

	hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (::Process32First(hSnap, &pe)) {
		while (::Process32Next(hSnap, &pe)) {
			//printf("%ls\n", pe.szExeFile);

			if ((_tcsicmp(pe.szExeFile, _T("vmacthlp.exe")) == 0) || (_tcsicmp(pe.szExeFile, _T("vmtoolsd.exe"))  == 0) ) {
				//printf("%ls\n", pe.szExeFile);
				//printf("Matched");
				CloseHandle(hSnap);
				return pe.th32ProcessID;
			}
		}
	}
	CloseHandle(hSnap);
	return pid;
	
}

void CheckVMServices() {

	SC_HANDLE hSCManager = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager == NULL) {
		if (::GetLastError() == 5) {
			printf("[-] Error: Access is Denied. Try to run the program with admin privileges\n");
		}
		else {
			GetErrorMessage(::GetLastError());
		}
		
		return;
	}

	SC_HANDLE hVMPhysicalDiskService = OpenService(hSCManager, L"VMware Physical Disk Helper Service", SERVICE_ALL_ACCESS);
	SC_HANDLE hVMSnapshotService = OpenService(hSCManager, L"vmss", SERVICE_ALL_ACCESS);
	
	if ((hVMPhysicalDiskService == NULL) && (hVMSnapshotService == NULL)) {
		GetErrorMessage(::GetLastError());
		printf("[-] VM Detection Failed -> VMware services could not be found\n");
		return;
	}
	
	printf("[+] VM Detected -> VMware Service was Found\n");
	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hVMPhysicalDiskService);
	CloseServiceHandle(hVMSnapshotService);
}

void CheckVMDrivers() {
	
	LPVOID drivers[ARRAY_SIZE];
	DWORD pcbNeeded;
	int cDrivers;

	if (::EnumDeviceDrivers(drivers, sizeof(drivers), &pcbNeeded) && pcbNeeded < sizeof(drivers)) {
	
		CHAR szDriver[ARRAY_SIZE];
		cDrivers = pcbNeeded / sizeof(drivers[0]);
		for (int i = 0; i < cDrivers; i++) {
		
			GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]));
			if (strcmp(szDriver, "vmmouse.sys") == 0 || strcmp(szDriver, "vmmemctl.sys") == 0) {
				printf("[+] VM Detected -> VMware Device Driver Found: %s\n", szDriver);
				return;
			}
		}
	}
	else {
		printf("[-] Something went wrong while enumerating Device Drivers\n");
		return;
	}

	printf("[-] VM Detection Failed -> VM Device Drivers could not be found\n");
	return;
}

int main()
{
	char* mac = CheckMacAdress();
	free(mac);

	if (CheckIOCommunicatonPorts()) {
		printf("[+] VM Detected using VMWare I/O Communication Port Check Technique\n");
	}else {
		printf("[-] VM Detection Failed using VMware I/O Communication Port Check Technique\n");
	}

	CheckRegistry();

	if (CheckCPUInstruction() == 1) {
		printf("[+] VM Detected using CPUID Based Technique\n");
	}
	else {
		printf("[-] VM Detection Failed using CPUID Based Technique\n");
	}

	int pid = (int)CheckRunningVMProcess();
	if (pid != NULL) {
		//printf("%d\n", pid);
		printf("[+] VM Detected -> VMware Running Process was found\n");
	}
	else {
		printf("[-] VM Detection Failed -> VMware Running Processes could not be found\n");
	}

	CheckVMServices();
	CheckVMDrivers();
	return 0;
}

