#include "os_macos.h"

#import <AppKit/AppKit.h>

void
os_choose_file(const char * const exts[], u_int num_exts, bool (*selected_fp)(const char *path))
{
	NSAutoreleasePool *pool = [NSAutoreleasePool new];
	NSOpenPanel *openPanel = [NSOpenPanel openPanel];
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

enum debug_error_state
os_runtime_error(const char *msg, bool allow_always_ignore)
{
	NSAutoreleasePool *pool = [NSAutoreleasePool new];
	@try
	{
		NSAlert *alert = [NSAlert new];
		[alert setAlertStyle:NSAlertStyleWarning];
		[alert setMessageText:@"Emulation error"];
		[alert setInformativeText:[NSString stringWithUTF8String:msg]];

		[alert addButtonWithTitle:@"Debug"];
		[alert addButtonWithTitle:@"Abort"];
		[alert addButtonWithTitle:@"Ignore"];
		if (allow_always_ignore)
			[alert addButtonWithTitle:@"Always Ignore"];

		__block NSModalResponse response;
		__block BOOL done = NO;
		[alert beginSheetModalForWindow:tk_get_main_win() completionHandler:^(
				NSModalResponse returnCode)
		{
			response = returnCode;
			done = YES;
		}];

		while (!done)
		{
			tk_pump_input();
			usleep(100 * 1000);
		}

		switch (response)
		{
			case NSAlertFirstButtonReturn: return ERROR_DEBUG;
			case NSAlertSecondButtonReturn: return ERROR_ABORT;
			case NSAlertThirdButtonReturn: return ERROR_IGNORE;
			case NSAlertThirdButtonReturn + 1: return ERROR_ALWAYS_IGNORE;
			default: [NSException raise:NSGenericException format:@"Unknown alert response"];
		}
	}
	@finally
	{
		[pool release];
	}
}
