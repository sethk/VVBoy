#include "types.h"
#include "os_macos.h"

#if INTERFACE
#	define os_getprogname getprogname

	typedef NSWindow *os_win_handle_t;
#	define OS_WIN_HANDLE_INVALID NULL

#	define OS_SHORTCUT_LKEY TK_SCANCODE_LGUI
#	define OS_SHORTCUT_RKEY TK_SCANCODE_RGUI
#	define OS_SHORTCUT_KEY_NAME "Cmd"

#endif // INTERFACE

#import <AppKit/AppKit.h>

bool
os_init(void)
{
	return true;
}

void
os_fini(void)
{
}

void
os_choose_file(const char *desc, const char * const exts[], u_int num_exts, bool (*selected_fp)(const char *path))
{
	NSAutoreleasePool *pool = [NSAutoreleasePool new];
	NSOpenPanel *openPanel = [NSOpenPanel openPanel];
	[openPanel setTitle:[NSString stringWithUTF8String:desc]];
	[openPanel setCanChooseFiles:YES];
	NSMutableArray *fileTypes = [NSMutableArray arrayWithCapacity:num_exts];
	for (u_int i = 0; i < num_exts; ++i)
		[fileTypes addObject:[NSString stringWithCString:exts[i] encoding:NSASCIIStringEncoding]];
	[openPanel setAllowedFileTypes:fileTypes];
	if ([openPanel runModal] == NSModalResponseOK)
	{
		NSURL *url = [[openPanel URLs] objectAtIndex:0];
		NSCAssert([url isFileURL], @"Selected URL is not a file URL");
		NSString *path = [url path];
		selected_fp([path UTF8String]);
	}

	[pool release];
}

enum os_runerr_resp
os_runtime_verror(enum os_runerr_type type, enum os_runerr_resp resp_mask, const char *fmt, va_list ap)
{
	int os_errno = errno;

	bool dismiss_allowed = ((resp_mask & (BIT(OS_RUNERR_RESP_OKAY) | BIT(OS_RUNERR_RESP_IGNORE))) != 0);

	NSAutoreleasePool *pool = [NSAutoreleasePool new];
	@try
	{
		NSAlert *alert = [NSAlert new];
		NSMutableString *informativeText = [[NSMutableString alloc] initWithFormat:@(fmt) arguments:ap];

		switch (type)
		{
			case OS_RUNERR_TYPE_OSERR:
			{
				//[alert setAlertStyle:NSCriticalAlertStyle];
				[alert setMessageText:(dismiss_allowed) ? @"Error" : @"Fatal error"];
				[informativeText appendFormat:@": %s", strerror(os_errno)];
				break;
			}

			case OS_RUNERR_TYPE_WARNING:
			{
				//[alert setAlertStyle:NSWarningAlertStyle];
				[alert setMessageText:@"Warning"];
				break;
			}

			case OS_RUNERR_TYPE_EMULATION:
			{
				//[alert setAlertStyle:NSInformationalAlertStyle];
				[alert setMessageText:@"Emulation Error"];
				break;
			}
		}

		[alert setInformativeText:informativeText];

		if (resp_mask & BIT(OS_RUNERR_RESP_DEBUG))
			[[alert addButtonWithTitle:@"Debug"] setTag:OS_RUNERR_RESP_DEBUG];
		if (resp_mask & BIT(OS_RUNERR_RESP_ABORT))
			[[alert addButtonWithTitle:@"Abort"] setTag:OS_RUNERR_RESP_ABORT];
		if (resp_mask & BIT(OS_RUNERR_RESP_IGNORE))
			[[alert addButtonWithTitle:@"Ignore"] setTag:OS_RUNERR_RESP_IGNORE];
		if (resp_mask & BIT(OS_RUNERR_RESP_ALWAYS_IGNORE))
			[[alert addButtonWithTitle:@"Always Ignore"] setTag:OS_RUNERR_RESP_ALWAYS_IGNORE];

		__block NSModalResponse response;
		__block BOOL done = NO;
		[alert beginSheetModalForWindow:tk_get_main_win() completionHandler:^(NSModalResponse returnCode)
		{
			response = returnCode;
			done = YES;
		}];

		while (!done)
		{
			tk_pump_input();
			usleep(100 * 1000);
		}

		return response;
	}
	@finally
	{
		[pool release];
	}
}
