#include "types.h"
#include "os_windows.h"

#if INTERFACE
#	include <Windows.h>
#	include <sys/types.h>
#	define os_snprintf _sprintf_p // Must support positional arguments
#	define os_vsnprintf _vsprintf_p
#	define os_bzero(p, s) ZeroMemory(p, s)
#	define os_bcopy(s, d, l) CopyMemory(d, s, l)
#	if defined(WIN64)
#		define os_bcmp(a, b, s) RtlCompareMemory(a, b, s)
#	else
#		define os_bcmp(a, b, s) memcmp(a, b, s)
#	endif
#	define OS_SHORTCUT_LKEY TK_SCANCODE_LCTRL
#	define OS_SHORTCUT_RKEY TK_SCANCODE_RCTRL
#	define OS_SHORTCUT_KEY_NAME "Ctrl"

	typedef HANDLE os_file_handle_t;
#	define OS_FILE_HANDLE_INVALID INVALID_HANDLE_VALUE
	typedef HANDLE os_mmap_handle_t;
#	define OS_MMAP_HANDLE_INVALID INVALID_HANDLE_VALUE
	typedef HWND os_win_handle_t;
#	define OS_WIN_HANDLE_INVALID INVALID_HANDLE_VALUE
#endif // INTERFACE

#include <CommCtrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdio.h>
#include <malloc.h>
#include <assert.h>

#if defined _M_IX86
	#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
	#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
	#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
	#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

static LARGE_INTEGER os_ticks_per_sec;

bool
os_init(void)
{
	BOOL result = QueryPerformanceFrequency(&os_ticks_per_sec);
	assert(result);
	return true;
}

void
os_fini(void)
{
}

static CHAR progname[MAX_PATH] = { '\0' };
const char *
os_getprogname(void)
{
	if (progname[0] == 0 && GetModuleFileNameA(NULL, progname, sizeof(progname)) == 0)
	{
		char err[256];
		os_snprintf(err, sizeof(err), "GetModuleFileNameA() failed: error = %ld\n", GetLastError());
		OutputDebugString(err);
		return "(unknown)";
	}
	return progname;
}

const char *
_getprogname(void)
{
	return os_getprogname();
}

u_int64_t
os_get_usec(void)
{
	LARGE_INTEGER count;
	BOOL success = QueryPerformanceCounter(&count);
	assert(success && "QueryPerformanceCounter() failed");
	return (count.QuadPart * 1000000) / os_ticks_per_sec.QuadPart;
}

os_file_handle_t
os_file_open(const char *fn, enum os_perm perm)
{
	DWORD access = 0;
	DWORD creation = 0;
	if (perm & OS_PERM_READ)
	{
		access |= GENERIC_READ;
		creation = OPEN_EXISTING;
	}
	if (perm & OS_PERM_WRITE)
	{
		access |= GENERIC_WRITE;
		creation = OPEN_ALWAYS;
	}
	return CreateFileA(fn, access, FILE_SHARE_READ, NULL, creation, FILE_ATTRIBUTE_NORMAL, NULL);
}

void
os_file_close(os_file_handle_t handle)
{
	CloseHandle(handle);
}

bool os_file_getsize(os_file_handle_t handle, off_t *psize)
{
	LARGE_INTEGER size;
	if (!GetFileSizeEx(handle, &size))
		return false;
	*psize = size.QuadPart;
	return true;
}

size_t
os_file_read(os_file_handle_t handle, void *buffer, size_t size)
{
	DWORD nread;
	if (!ReadFile(handle, buffer, size, &nread, NULL))
		return -1;
	return nread;
}

off_t
os_file_seek(os_file_handle_t handle, off_t offset, enum os_seek_anchor anchor)
{
	DWORD method;
	switch (anchor)
	{
		case OS_SEEK_SET: method = FILE_BEGIN; break;
		case OS_SEEK_CUR: method = FILE_CURRENT; break;
		case OS_SEEK_END: method = FILE_END; break;
	}
	LARGE_INTEGER distance;
	distance.QuadPart = offset;
	LARGE_INTEGER new_position;
	if (!SetFilePointerEx(handle, distance, &new_position, method))
		return -1;
	return new_position.QuadPart;
}

os_mmap_handle_t
os_mmap_file(os_file_handle_t file_handle, size_t size, enum os_mmap_perm perms, void **pmap)
{
	DWORD protect = 0;
	DWORD access = 0;
	if (perms & OS_PERM_READ)
	{
		protect = PAGE_READONLY;
		access = FILE_MAP_READ;
	}
	if (perms & OS_PERM_WRITE)
	{
		protect = PAGE_READWRITE;
		access = FILE_MAP_WRITE;
	}

	DWORD sizeHigh, sizeLow;
#ifdef WIN64
	sizeHigh = size >> 32;
#else
	sizeHigh = 0;
#endif // WIN64
	sizeLow = size & 0xffffffff;

	*pmap = NULL;

	os_mmap_handle_t mmap_handle = CreateFileMappingA(file_handle, NULL, protect, sizeHigh, sizeLow, NULL);
	if (mmap_handle == OS_MMAP_HANDLE_INVALID)
		return mmap_handle;

	*pmap = MapViewOfFile(mmap_handle, access, 0, 0, size);
	if (!*pmap)
	{
		DWORD error = GetLastError();
		CloseHandle(mmap_handle);
		SetLastError(error);
		return OS_MMAP_HANDLE_INVALID;
	}

	return mmap_handle;
}

bool
os_munmap_file(os_mmap_handle_t handle, void *ptr, size_t size)
{
	if (ptr && !UnmapViewOfFile(ptr))
	{
		CloseHandle(handle);
		return false;
	}

	return CloseHandle(handle);
}

void
os_choose_file(const char *desc, const char * const exts[], u_int num_exts, bool(*selected_fp)(const char *path))
{
	OPENFILENAMEW config;
	ZeroMemory(&config, sizeof(config));
	config.lStructSize = sizeof(config);
	config.hwndOwner = tk_get_main_win();
	size_t filters_len = strlen(desc) + 1;
	for (u_int ext_index = 0; ext_index < num_exts; ++ext_index)
		filters_len += 2 + strlen(exts[ext_index]) + 1;
	filters_len+= 2;
	char *filters = alloca(filters_len);
	if (!filters)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate GetOpenFileName filter strings");
	filters_len = strlen(desc) + 1;
	CopyMemory(filters, desc, filters_len);
	for (u_int ext_index = 0; ext_index < num_exts; ++ext_index)
		filters_len += os_snprintf(filters + filters_len, sizeof(filters) - filters_len, "%s*.%s", (ext_index > 0) ? ";" : "", exts[ext_index]);
	filters[++filters_len] = '\0';
	WCHAR *wide_filters = alloca((filters_len + 1) * sizeof(*wide_filters));
	if (!wide_filters)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate wide GetOpenFileName filter strings");
	MultiByteToWideChar(CP_UTF8, 0, filters, filters_len + 1, wide_filters, filters_len + 1);
	config.lpstrFilter = wide_filters;
	WCHAR path[1024] = { '\0' };
	config.lpstrFile = path;
	config.nMaxFile = sizeof(path);
	config.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST;
	if (GetOpenFileNameW(&config))
	{
		char utf8_path[ARRAYSIZE(path)];
		int res = WideCharToMultiByte(CP_OEMCP,
			WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK | WC_DEFAULTCHAR,
			path, lstrlenW(path) + 1,
			utf8_path, sizeof(utf8_path),
			NULL, NULL);
		assert(res > 0);
		selected_fp(utf8_path);
	}
	else
	{
		DWORD ext_error = CommDlgExtendedError();
		if (ext_error)
			os_runtime_error(OS_RUNERR_TYPE_WARNING, BIT(OS_RUNERR_RESP_OKAY), "GetOpenFileNameW() failed with error 0x%04x", ext_error);
	}
}

enum os_runerr_resp
os_runtime_error(enum os_runerr_type type, enum os_runerr_resp resp_mask, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	enum os_runerr_resp resp = os_runtime_verror(type, resp_mask, fmt, ap);
	va_end(ap);
	return resp;
}

enum os_runerr_resp
os_runtime_verror(enum os_runerr_type type, enum os_runerr_resp resp_mask, const char *fmt, va_list ap)
{
	DWORD os_err = GetLastError();

	char msg[512];
	vsnprintf(msg, sizeof(msg), fmt, ap);

	TASKDIALOGCONFIG config;
	ZeroMemory(&config, sizeof(config));
	config.cbSize = sizeof(config);

	os_win_handle_t main_win = tk_get_main_win();
	config.hwndParent = (main_win != OS_WIN_HANDLE_INVALID) ? main_win : NULL;

	config.hInstance = NULL;
	config.dwFlags = TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT;
	bool dismiss_allowed = ((resp_mask & (BIT(OS_RUNERR_RESP_OKAY) | BIT(OS_RUNERR_RESP_IGNORE))) == 0);
	if (dismiss_allowed)
		config.dwFlags |= TDF_ALLOW_DIALOG_CANCELLATION;
	config.dwCommonButtons = 0;
	if (resp_mask & BIT(OS_RUNERR_RESP_OKAY))
		config.dwCommonButtons |= TDCBF_OK_BUTTON;

	static WCHAR wide_msg[512];
	size_t msg_len = strlen(msg);
	int wmsg_len = MultiByteToWideChar(CP_UTF8, 0, msg, msg_len, wide_msg, sizeof(wide_msg));
	assert(wmsg_len > 0);
	config.pszMainInstruction = wide_msg;

	switch (type)
	{
		case OS_RUNERR_TYPE_OSERR:
		{
			config.pszMainIcon = TD_ERROR_ICON;
			config.pszWindowTitle = (dismiss_allowed) ? L"Error" : L"Fatal Error";
			static WCHAR wide_error[512];
			DWORD res = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				os_err,
				0,
				wide_error, sizeof(wide_error),
				NULL);
			if (res > 0)
				config.pszContent = wide_error;
			break;
		}

		case OS_RUNERR_TYPE_WARNING:
			config.pszMainIcon = TD_WARNING_ICON;
			config.pszWindowTitle = L"Warning";
			break;

		case OS_RUNERR_TYPE_EMULATION:
			config.pszMainIcon = TD_INFORMATION_ICON;
			config.pszWindowTitle = L"Emulation Error";
			break;
	}

	static TASKDIALOG_BUTTON buttons[OS_RUNERR_NUM_RESP];
	UINT num_buttons = 0;
	for (u_int resp = 0; resp < OS_RUNERR_NUM_RESP; ++resp)
	{
		if ((resp_mask & BIT(resp)) == 0)
			continue;

		buttons[num_buttons].nButtonID = resp;
		switch ((enum os_runerr_resp)resp)
		{
			case OS_RUNERR_RESP_OKAY: buttons[num_buttons].pszButtonText = L"OK"; break;
			case OS_RUNERR_RESP_IGNORE: buttons[num_buttons].pszButtonText = L"Ignore"; break;
			case OS_RUNERR_RESP_ABORT: buttons[num_buttons].pszButtonText = L"Abort"; break;
			case OS_RUNERR_RESP_DEBUG: buttons[num_buttons].pszButtonText = L"Debug"; break;
			case OS_RUNERR_RESP_ALWAYS_IGNORE: buttons[num_buttons].pszButtonText = L"Always Ignore"; break;
			default:
				assert(!"Dialog response not handled");
		}
		++num_buttons;
	}

	config.cButtons = num_buttons;
	config.pButtons = buttons;
	config.nDefaultButton = buttons[0].nButtonID;

	int button;
	HRESULT result = TaskDialogIndirect(&config, &button, NULL, NULL);
	assert(result == S_OK);
	return button;
}

void
os_debug_trap(void)
{
	__debugbreak();
}

int
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	int ac;
	LPWSTR *wide_args = CommandLineToArgvW(GetCommandLineW(), &ac);
	if (!wide_args)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not parse command-line string");

	char **av = calloc(ac + 1, sizeof(*av));
	if (!av)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate space for command-line");

	for (int i = 0; i < ac; ++i)
	{
		int size = WideCharToMultiByte(CP_UTF8,
									   WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK,
									   wide_args[i], -1,
									   NULL, 0,
									   NULL, NULL);
		av[i] = malloc(size);
		if (!av[i])
			main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate space for command-line argument");

		int actual_size = WideCharToMultiByte(CP_UTF8,
											  WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK,
											  wide_args[i], -1,
											  av[i], size,
											  NULL, NULL);
		assert(actual_size == size);
	}
	av[ac] = NULL;

	return main(ac, av);
}
