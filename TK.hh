#pragma once

#ifdef TOOLKIT_GLFW
//#	include "TK_Glfw.hh"
#elif defined(TOOLKIT_SDL)
//#	include "TK_SDL.hh"
#else
#	error No Toolkit defined"
#endif

