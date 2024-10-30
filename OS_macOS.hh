#pragma once

#include "OS_Unix.hh"

#define os_getprogname getprogname

#ifdef __OBJC__
	@class NSWindow;
#else
	typedef struct _NSWindow NSWindow;
#endif

typedef NSWindow *os_win_handle_t;
#define OS_WIN_HANDLE_INVALID NULL

#define OS_SHORTCUT_LKEY TK_SCANCODE_LGUI
#define OS_SHORTCUT_RKEY TK_SCANCODE_RGUI
#define OS_SHORTCUT_KEY_NAME "Cmd"
