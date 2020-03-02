#if INTERFACE
# include <sys/types.h>
# include <stdbool.h>

# include <GLFW/glfw3.h>

	enum tk_scancode
	{
		TK_SCANCODE_F1 = GLFW_KEY_F1,
		TK_SCANCODE_F2 = GLFW_KEY_F2,
		TK_SCANCODE_F3 = GLFW_KEY_F3,
		TK_SCANCODE_F4 = GLFW_KEY_F4,
		TK_SCANCODE_F5 = GLFW_KEY_F5,
		TK_SCANCODE_F6 = GLFW_KEY_F6,
		TK_SCANCODE_F7 = GLFW_KEY_F7,
		TK_SCANCODE_F8 = GLFW_KEY_F8,
		TK_SCANCODE_F9 = GLFW_KEY_F9,
		TK_SCANCODE_GRAVE = GLFW_KEY_GRAVE_ACCENT,
		TK_SCANCODE_LGUI = GLFW_KEY_LEFT_SUPER,
		TK_SCANCODE_RGUI = GLFW_KEY_RIGHT_SUPER,
		TK_SCANCODE_LSHIFT = GLFW_KEY_LEFT_SHIFT,
		TK_SCANCODE_W = GLFW_KEY_W,
		TK_SCANCODE_A = GLFW_KEY_A,
		TK_SCANCODE_S = GLFW_KEY_S,
		TK_SCANCODE_D = GLFW_KEY_D,
		TK_SCANCODE_K = GLFW_KEY_K,
		TK_SCANCODE_APOSTROPHE = GLFW_KEY_APOSTROPHE,
		TK_SCANCODE_RETURN = GLFW_KEY_ENTER,
		TK_SCANCODE_ESCAPE = GLFW_KEY_ESCAPE,
		TK_SCANCODE_R = GLFW_KEY_R,
		TK_SCANCODE_O = GLFW_KEY_O,
		TK_SCANCODE_1 = GLFW_KEY_1,
		TK_SCANCODE_2 = GLFW_KEY_2,
		TK_SCANCODE_RSHIFT = GLFW_KEY_RIGHT_SHIFT,
		TK_SCANCODE_RALT = GLFW_KEY_RIGHT_ALT,
		TK_SCANCODE_UP = GLFW_KEY_UP,
		TK_SCANCODE_LEFT = GLFW_KEY_LEFT,
		TK_SCANCODE_DOWN = GLFW_KEY_DOWN,
		TK_SCANCODE_RIGHT = GLFW_KEY_RIGHT
	};

	enum tk_button
	{
		TK_BUTTON_LSHOULDER = GLFW_GAMEPAD_BUTTON_LEFT_BUMPER,
		TK_BUTTON_DPAD_UP = GLFW_GAMEPAD_BUTTON_DPAD_UP,
		TK_BUTTON_DPAD_LEFT = GLFW_GAMEPAD_BUTTON_DPAD_LEFT,
		TK_BUTTON_DPAD_DOWN = GLFW_GAMEPAD_BUTTON_DPAD_DOWN,
		TK_BUTTON_DPAD_RIGHT = GLFW_GAMEPAD_BUTTON_DPAD_RIGHT,
		TK_BUTTON_BACK = GLFW_GAMEPAD_BUTTON_BACK,
		TK_BUTTON_START = GLFW_GAMEPAD_BUTTON_START,
		TK_BUTTON_RSHOULDER = GLFW_GAMEPAD_BUTTON_RIGHT_BUMPER,
		TK_BUTTON_A = GLFW_GAMEPAD_BUTTON_A,
		TK_BUTTON_B = GLFW_GAMEPAD_BUTTON_B
	};

	enum tk_axis
	{
		TK_AXIS_LEFTX = GLFW_GAMEPAD_AXIS_LEFT_X,
		TK_AXIS_LEFTY = GLFW_GAMEPAD_AXIS_LEFT_Y,
		TK_AXIS_RIGHTX = GLFW_GAMEPAD_AXIS_RIGHT_X,
		TK_AXIS_RIGHTY = GLFW_GAMEPAD_AXIS_RIGHT_Y,
	};

#endif // INTERFACE

#include "tk_glfw.h"
#include <assert.h>
#include <math.h>

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "vendor/cimgui_glfw_opengl3/imgui_impl_glfw_gl3.h"

#define VSYNC (true)

u_int tk_win_width, tk_win_height;
int tk_draw_width, tk_draw_height;
float tk_draw_scale;
GLFWgamepadstate tk_last_gamepad;

static GLFWwindow *glfw_window;

static bool glfw_check_error(const char *operation)
{
	const char *error;
	if (glfwGetError(&error) == GLFW_NO_ERROR)
		return true;

	fprintf(stderr, "GLFW: Failed to %s: %s\n", operation, error);
	return false;
}

static void glfw_error_func(int code, const char *description)
{
	fprintf(stderr, "GLFW Error: %s (code %d)\n", description, code);
}

static void glfw_key_func(GLFWwindow *window, int key, int scancode, int action, int mods)
{
	struct ImGuiIO *imgui_io = igGetIO();

	if (!imgui_io->WantCaptureKeyboard && (action == GLFW_PRESS || action == GLFW_RELEASE))
	{
		if (nvc_input_key(key, (action == GLFW_PRESS)))
			return;
	}

	ImGui_ImplGlfw_KeyCallback(window, key, scancode, action, mods);
}

bool
tk_init(void)
{
	glfwSetErrorCallback(glfw_error_func);

	int result = glfwInit();
	if (result != GLFW_TRUE)
	{
		glfw_check_error("initialize");
		return false;
	}

	glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
	glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);

	tk_win_width = 384 * 3;
	tk_win_height = 224 * 3;

	glfw_window = glfwCreateWindow(tk_win_width, tk_win_height, "VVBoy", NULL, NULL);
	if (!glfw_window)
	{
		glfw_check_error("create window");
		glfwTerminate();
		return false;
	}
	glfwMakeContextCurrent(glfw_window);
	glfwSwapInterval(VSYNC);

	glfwGetFramebufferSize(glfw_window, &tk_draw_width, &tk_draw_height);
	tk_draw_scale = tk_draw_width / tk_win_width;
	assert(fdimf(tk_draw_height / tk_win_height, tk_draw_scale) < 1e-6);

	ImGui_ImplGlfwGL3_Init(glfw_window, false, NULL);

    glfwSetMouseButtonCallback(glfw_window, ImGui_ImplGlfw_MouseButtonCallback);
    glfwSetScrollCallback(glfw_window, ImGui_ImplGlfw_ScrollCallback);
    glfwSetKeyCallback(glfw_window, glfw_key_func);
    glfwSetCharCallback(glfw_window, ImGui_ImplGlfw_CharCallback);

	return true;
}

void
tk_update_caption(const char *caption)
{
	glfwSetWindowTitle(glfw_window, caption);
}

u_int32_t
tk_get_usec(void)
{
	return glfwGetTime() * 1000000;
}

void
tk_frame_begin(void)
{
	ImGui_ImplGlfwGL3_NewFrame(glfw_window);
}

void
tk_frame_end(void)
{
	struct ImDrawData *imgui_data = igGetDrawData();
	if (imgui_data)
		ImGui_ImplGlfwGL3_RenderDrawData(imgui_data);

	glfwSwapBuffers(glfw_window);
}

bool
tk_poll_input()
{
	if (glfwWindowShouldClose(glfw_window))
		return false;

	glfwPollEvents();

	if (glfwJoystickIsGamepad(GLFW_JOYSTICK_1))
	{
		GLFWgamepadstate gamepad;
		if (glfwGetGamepadState(GLFW_JOYSTICK_1, &gamepad))
		{
			for (u_int button = 0; button <= GLFW_GAMEPAD_BUTTON_LAST; ++button)
				if (tk_last_gamepad.buttons[button] != gamepad.buttons[button])
					nvc_input_button(button, gamepad.buttons[button] == GLFW_PRESS);

			for (u_int axis = 0; axis <= GLFW_GAMEPAD_AXIS_LAST; ++axis)
				if (tk_last_gamepad.axes[axis] != gamepad.axes[axis])
					nvc_input_axis(axis, gamepad.axes[axis]);

			tk_last_gamepad = gamepad;
		}
	}

	return true;
}

void
tk_fini(void)
{
	ImGui_ImplGlfwGL3_Shutdown();

	glfwDestroyWindow(glfw_window);

	glfwTerminate();
}

#if INTERFACE
typedef struct _NSWindow NSWindow;
#endif // INTERFACE
#define GLFW_EXPOSE_NATIVE_COCOA
#include <GLFW/glfw3native.h>

NSWindow *
tk_get_main_win()
{
	return glfwGetCocoaWindow(glfw_window);
}
