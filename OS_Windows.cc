#include "Types.hh"
#include "OS_Windows.hh"

#if INTERFACE
#	include <Windows.h>
#	include <sys/types.h>
#	define os_bzero(p, s) ZeroMemory(p, s)
#	define os_bcopy(s, d, l) CopyMemory(d, s, l)
#	if defined(WIN64)
#		define os_bcmp(a, b, s) RtlCompareMemory(a, b, s)
#	else
#		define os_bcmp(a, b, s) memcmp(a, b, s)
#	endif
#	define os_strcasecmp stricmp
#	define os_debug_trap() __debugbreak()

#	define OS_SHORTCUT_LKEY TK_SCANCODE_LCTRL
#	define OS_SHORTCUT_RKEY TK_SCANCODE_RCTRL
#	define OS_SHORTCUT_KEY_NAME "Ctrl"

	typedef HANDLE os_file_handle_t;
#	define OS_FILE_HANDLE_INVALID INVALID_HANDLE_VALUE
	typedef HANDLE os_mmap_handle_t;
#	define OS_MMAP_HANDLE_INVALID INVALID_HANDLE_VALUE
	typedef HWND os_win_handle_t;
#	define OS_WIN_HANDLE_INVALID INVALID_HANDLE_VALUE

	typedef posix_tnode os_tnode_t;
#endif // INTERFACE

#include <CommCtrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cstdio>
#include <cmalloc>
#include <climits>
#include <cassert>

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

void
os_debug_log(const char *msg)
{
	OutputDebugStringA(msg);
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

size_t
os_snprintf(char *s, size_t size, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	size_t result = os_vsnprintf(s, size, fmt, ap);
	va_end(ap);
	return result;
}

static void
os_sprintf_copyfmt(const char **src_beginp, const char *src_end, char **dest_beginp, char *dest_end)
{
	while (*src_beginp != src_end)
	{
		if (*dest_beginp == dest_end)
			main_fatal_error(OS_RUNERR_TYPE_WARNING, "Format string with positional arguments too long");

		*(*dest_beginp)++ = *(*src_beginp)++;
	}
}

size_t
os_vsnprintf(char * const out, size_t out_size, const char * const orig_fmt_buffer, va_list args)
{
	//if (!strchr(orig_fmt, '$'))
		//return _vsprintf_p(out, orig_fmt_size, orig_fmt, args);

	// Windows vsprintf_p() forbids mixing of positional and non-positional arguments and unused positions, so we just
	// make all of them positional and append any skipped ones:
	size_t orig_fmt_len = strlen(orig_fmt_buffer);
	const char *orig_fmt = orig_fmt_buffer, *orig_fmt_end = orig_fmt_buffer + orig_fmt_len;
	size_t out_fmt_len = orig_fmt_len * 4;
	char *out_fmt_buffer = alloca(out_fmt_len + 1), *out_fmt = out_fmt_buffer, *out_fmt_end = out_fmt_buffer + out_fmt_len;
	if (!out_fmt)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate format string");

	u_int max_pos = 0;
	u_int pos_mask = 0;

	while (orig_fmt != orig_fmt_end)
	{
		const char *next_orig_fmt = orig_fmt + 1;
		if (*orig_fmt != '%')
		{
			os_sprintf_copyfmt(&orig_fmt, next_orig_fmt, &out_fmt, out_fmt_end);
			continue;
		}

		if (*next_orig_fmt == '%')
		{
			os_sprintf_copyfmt(&orig_fmt, next_orig_fmt + 1, &out_fmt, out_fmt_end);
			continue;
		}

		char *end_orig_arg;
		long arg_pos = strtol(next_orig_fmt, &end_orig_arg, 10);
		bool have_arg_pos = false;
		if (end_orig_arg != next_orig_fmt && *end_orig_arg == '$')
		{
			have_arg_pos = true;
			next_orig_fmt = end_orig_arg + 1;
		}

		char arg_fmt_buffer[12 + 1], *next_arg_fmt = arg_fmt_buffer, *arg_fmt_end = arg_fmt_buffer + sizeof(arg_fmt_buffer) - 1;
		bool in_fmt_arg = true;
		do
		{
			switch (*next_orig_fmt)
			{
				case '\0':
					main_fatal_error(OS_RUNERR_TYPE_WARNING, "Unterminated format specifier");

				case '*':
				{
					++next_orig_fmt;
					char *end_width_pos;
					unsigned long width_pos = strtoul(next_orig_fmt, &end_width_pos, 10);
					if (end_width_pos != next_orig_fmt && *end_width_pos == '$')
					{
						max_pos = max_uint(width_pos, max_pos);
						next_orig_fmt = end_width_pos + 1;
					}
					else
						width_pos = ++max_pos;

					assert(width_pos <= sizeof(pos_mask) *CHAR_BIT);
					pos_mask |= BIT(width_pos - 1);
					next_arg_fmt+= snprintf(next_arg_fmt, (arg_fmt_end - next_arg_fmt) + 1, "*%u$", width_pos);
					break;
				}

				case 'c': case 'C':
				case 'd': case 'i': case 'o': case 'u': case 'x': case 'X':
				case 'a': case 'A': case 'e': case 'E': case 'f': case 'F': case 'g': case 'G':
				case 'n':
				case 'p':
				case 's': case 'S':
					in_fmt_arg = false;
					// FALLTHRU
				default:
					os_sprintf_copyfmt(&next_orig_fmt, next_orig_fmt + 1, &next_arg_fmt, arg_fmt_end);
			}
		}
		while (in_fmt_arg);
		orig_fmt = next_orig_fmt;

		if (have_arg_pos)
			max_pos = max_uint(arg_pos, max_pos);
		else
			arg_pos = ++max_pos;
		assert(arg_pos <= sizeof(pos_mask) *CHAR_BIT);
		pos_mask |= BIT(arg_pos - 1);

		out_fmt+= snprintf(out_fmt, (out_fmt_end - out_fmt) + 1, "%%%u$", arg_pos);
		char *arg_fmt = arg_fmt_buffer;
		os_sprintf_copyfmt(&arg_fmt, next_arg_fmt, &out_fmt, out_fmt_end);
	}

	for (u_int pos = 1; pos < max_pos; ++pos)
	{
		if (pos_mask & BIT(pos - 1))
			continue;

		out_fmt += snprintf(out_fmt, (out_fmt_end - out_fmt) + 1, "%%%d$0.0s", pos);
	}

	*out_fmt = '\0';
	return _vsprintf_p(out, out_size, out_fmt_buffer, args);
}

os_file_handle_t
os_file_open(const char *fn, os_perm_mask perm)
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

bool
os_file_exists(const char *path)
{
	DWORD attrs = GetFileAttributes(path);
	return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

bool
os_file_getsize(os_file_handle_t handle, off_t *psize)
{
	LARGE_INTEGER size;
	if (!GetFileSizeEx(handle, &size))
		return false;
	*psize = size.QuadPart;
	return true;
}

bool
os_file_iseof(os_file_handle_t handle)
{
	LARGE_INTEGER zero, size, pos;
	zero.QuadPart = 0;
	if (!GetFileSizeEx(handle, &size) || !SetFilePointerEx(handle, zero, &pos, FILE_CURRENT))
	{
		os_runtime_error(OS_RUNERR_TYPE_OSERR, os_runerr_resp_mask::OKAY, "GetFileSizeEx()/SetFilePointerEx() failed");
		return true;
	}
	return pos.QuadPart == size.QuadPart;
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
os_file_seek(os_file_handle_t handle, off_t offset, os_seek_anchor anchor)
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
os_mmap_file(os_file_handle_t file_handle, size_t size, os_perm_mask perms, void **pmap)
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
			os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::OKAY, "GetOpenFileNameW() failed with error 0x%04x", ext_error);
	}
}

os_runerr_resp
os_runtime_verror(os_runerr_type type, os_runerr_resp resp_mask, const char *fmt, va_list ap)
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
	bool dismiss_allowed = ((resp_mask & (os_runerr_resp_mask::OKAY | os_runerr_resp_mask::IGNORE)) != 0);
	if (dismiss_allowed)
		config.dwFlags |= TDF_ALLOW_DIALOG_CANCELLATION;
	config.dwCommonButtons = 0;
	if (resp_mask & os_runerr_resp_mask::OKAY)
		config.dwCommonButtons |= TDCBF_OK_BUTTON;

	static WCHAR wide_msg[512];
	size_t msg_len = strlen(msg);
	int wmsg_len = MultiByteToWideChar(CP_UTF8, 0, msg, msg_len + 1, wide_msg, COUNT_OF(wide_msg));
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
	for (os_runerr_resp resp = static_cast<os_runerr_resp>(0); resp < OS_RUNERR_NUM_RESP; ++resp)
	{
		if ((resp_mask & static_cast<os_runerr_resp_mask>(BIT(resp))) == 0)
			continue;

		buttons[num_buttons].nButtonID = resp;
		switch (resp)
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

int
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	int ac;
	LPWSTR *wide_args = CommandLineToArgvW(GetCommandLineW(), &ac);
	if (!wide_args)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not parse command-line string");

	char **av = new(std::nothrow) char *[ac + 1]();
	if (!av)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate space for command-line");

	for (int i = 0; i < ac; ++i)
	{
		int size = WideCharToMultiByte(CP_UTF8,
									   WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK,
									   wide_args[i], -1,
									   NULL, 0,
									   NULL, NULL);
		av[i] = new char[size];
		if (!av[i])
			main_fatal_error(OS_RUNERR_TYPE_OSERR, "Could not allocate space for command-line argument");

		int actual_size = WideCharToMultiByte(CP_UTF8,
											  WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK,
											  wide_args[i], -1,
											  av[i], size,
											  NULL, NULL);
		assert(actual_size == size);
	}

	return main(ac, av);
}
