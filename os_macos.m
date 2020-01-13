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
