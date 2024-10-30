#include "Types.hh"
#include "OS.hh"
#include "GL.Gen.hh"

#if INTERFACE
	enum gl_texture
	{
		TEXTURE_LEFT,
		TEXTURE_RIGHT,
		TEXTURE_DEBUG_BGSEG,
		TEXTURE_DEBUG_CHR,
		TEXTURE_DEBUG_FB,
		NUM_TEXTURES
	};
#endif // INTERFACE

#include <GL/gl3w.h>
#include <cassert>

bool gl_draw_left = true;
bool gl_draw_right = true;

static GLuint gl_textures[NUM_TEXTURES];
static GLuint gl_vao, gl_vbo;
static GLuint gl_program;
static GLint gl_color_uniform;
static u_int32_t gl_debug_frame[512 * 512];

// Saved GL state
static GLint last_viewport[4];
static GLint last_program;
static GLint last_vertex_array;
static GLboolean last_blend_enabled;
static GLenum last_blend_src_rgb;
static GLenum last_blend_dst_rgb;
static GLenum last_blend_src_alpha;
static GLenum last_blend_dst_alpha;
static GLenum last_blend_equation_rgb;
static GLenum last_blend_equation_alpha;
static GLint last_texture;

static bool
gl_check_errors(const char *desc)
{
	bool none = true;
	GLenum error;
	while ((error = glGetError()) != GL_NO_ERROR)
	{
		const char *err_desc;
		switch (error)
		{
			default:
			{
				static char unknown_err_desc[10];
				os_snprintf(unknown_err_desc, sizeof(unknown_err_desc), "%08x", error);
				err_desc = unknown_err_desc;
				break;
			}

			case GL_INVALID_ENUM: err_desc = "GL_INVALID_ENUM"; break;
			case GL_INVALID_VALUE: err_desc = "GL_INVALID_VALUE"; break;
			case GL_INVALID_OPERATION: err_desc = "GL_INVALID_OPERATION"; break;
			case GL_OUT_OF_MEMORY: err_desc = "GL_OUT_OF_MEMORY"; break;
		}

		debug_runtime_errorf(NULL, "GL error during %s: %s\n", desc, err_desc);
		none = false;
	}
	return none;
}

static bool
gl_check_program(GLuint program, GLenum pname,
				 const char *desc,
				 PFNGLGETSHADERIVPROC get_func,
				 PFNGLGETSHADERINFOLOGPROC log_func)
{
	GLint status;
	get_func(program, pname, &status);
	if (status != GL_TRUE)
	{
		char log[256];
		log_func(program, sizeof(log), NULL, log);
		debug_runtime_errorf(NULL, "%s failed: %s", desc, log);
		return false;
	}
	return true;
}

bool
gl_init(void)
{
	if (gl3wInit() == -1)
	{
		os_runtime_error(OS_RUNERR_TYPE_WARNING, os_runerr_resp_mask::ABORT, "Could not load OpenGL");
		return false;
	}

	enum
	{
		ATTRIB_POSITION,
		ATTRIB_TEX_COORD
	};

	static const GLchar * vertex_shader_src =
			"#version 150\n"
			"in vec2 i_position;\n"
            "in vec2 i_tex_coord;\n"
			"out vec2 v_tex_coord;\n"
			"void main() {\n"
            "    v_tex_coord = i_tex_coord;\n"
			"    gl_Position = vec4(i_position, 0.0, 1.0);\n"
			"}\n";

	static const GLchar * fragment_shader_src =
			"#version 150\n"
            "in vec2 v_tex_coord;\n"
			"out vec4 o_color;\n"
			"uniform sampler2D tex;\n"
			"uniform vec4 color;\n"
			"void main() {\n"
			"    o_color = texture(tex, v_tex_coord) * color;\n"
			"}\n";

	GLuint vertex_shader, fragment_shader;

	vertex_shader = glCreateShader(GL_VERTEX_SHADER);
	fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
	gl_check_errors("create shaders");

	glShaderSource(vertex_shader, 1, &vertex_shader_src, NULL);
	glCompileShader(vertex_shader);
	gl_check_program(vertex_shader, GL_COMPILE_STATUS, "compile vertex program", glGetShaderiv, glGetShaderInfoLog);

	glShaderSource(fragment_shader, 1, &fragment_shader_src, NULL);
	glCompileShader(fragment_shader);
	gl_check_program(fragment_shader, GL_COMPILE_STATUS, "compile fragment program", glGetShaderiv, glGetShaderInfoLog);

	gl_program = glCreateProgram();
	glAttachShader(gl_program, vertex_shader);
	glAttachShader(gl_program, fragment_shader);
	gl_check_errors("attach shaders");

	glBindAttribLocation(gl_program, ATTRIB_POSITION, "i_position");
	glBindAttribLocation(gl_program, ATTRIB_TEX_COORD, "i_tex_coord");
	glLinkProgram(gl_program);
	if (!gl_check_program(gl_program, GL_LINK_STATUS, "link program", glGetProgramiv, glGetProgramInfoLog))
		return false;

	gl_color_uniform = glGetUniformLocation(gl_program, "color");
	gl_check_errors("get color uniform");

	glUseProgram(gl_program);
	gl_check_errors("use program");

	glDisable(GL_DEPTH_TEST);
	glClearColor(0.0, 0.0, 0.0, 1.0);

	glGenVertexArrays(1, &gl_vao);
	glGenBuffers(1, &gl_vbo);
	glBindVertexArray(gl_vao);
	glBindBuffer(GL_ARRAY_BUFFER, gl_vao);
	if (!gl_check_errors("bind vertex buffers"))
		return false;

	glEnableVertexAttribArray(ATTRIB_POSITION);
	glEnableVertexAttribArray(ATTRIB_TEX_COORD);

	glVertexAttribPointer(ATTRIB_POSITION, 2, GL_FLOAT, GL_FALSE, sizeof(GLfloat) * 4, (void *)(0 * sizeof(GLfloat)));
	glVertexAttribPointer(ATTRIB_TEX_COORD, 2, GL_FLOAT, GL_FALSE, sizeof(GLfloat) * 4, (void *)(2 * sizeof(GLfloat)));
	if (!gl_check_errors("set attribute pointer"))
		return false;

	glGenTextures(NUM_TEXTURES, gl_textures);
	for (u_int i = 0; i < NUM_TEXTURES; ++i)
	{
		glBindTexture(GL_TEXTURE_2D, gl_textures[i]);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	}
	if (!gl_check_errors("set up textures"))
		return false;

	return true;
}

void
gl_fini(void)
{
	glDeleteTextures(2, gl_textures);
	gl_check_errors("delete textures");
}

void
gl_blit(const u_int32_t *fb_argb, bool right)
{
	glBindTexture(GL_TEXTURE_2D, gl_textures[(right) ? TEXTURE_RIGHT : TEXTURE_LEFT]);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 224, 384, 0, GL_RGBA, GL_UNSIGNED_BYTE, fb_argb);
	gl_check_errors("update texture");
}

void
gl_clear(void)
{
	glClear(GL_COLOR_BUFFER_BIT);
}

void
gl_save_state(void)
{
	glGetIntegerv(GL_VIEWPORT, last_viewport);
	glGetIntegerv(GL_CURRENT_PROGRAM, &last_program);
	glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &last_vertex_array);
	last_blend_enabled = glIsEnabled(GL_BLEND);
	glGetIntegerv(GL_BLEND_SRC_RGB, (GLint*)&last_blend_src_rgb);
	glGetIntegerv(GL_BLEND_DST_RGB, (GLint*)&last_blend_dst_rgb);
	glGetIntegerv(GL_BLEND_SRC_ALPHA, (GLint*)&last_blend_src_alpha);
	glGetIntegerv(GL_BLEND_DST_ALPHA, (GLint*)&last_blend_dst_alpha);
	glGetIntegerv(GL_BLEND_EQUATION_RGB, (GLint*)&last_blend_equation_rgb);
	glGetIntegerv(GL_BLEND_EQUATION_ALPHA, (GLint*)&last_blend_equation_alpha);
	glGetIntegerv(GL_TEXTURE_BINDING_2D, &last_texture);
}

void
gl_restore_state(void)
{
	glBindTexture(GL_TEXTURE_2D, last_texture);
	glBlendEquationSeparate(last_blend_equation_rgb, last_blend_equation_alpha);
	glBlendFuncSeparate(last_blend_src_rgb, last_blend_dst_rgb, last_blend_src_alpha, last_blend_dst_alpha);
	if (last_blend_enabled)
		glEnable(GL_BLEND);
	else glDisable(GL_BLEND);
	glBindVertexArray(last_vertex_array);
	glUseProgram(last_program);
	glViewport(last_viewport[0], last_viewport[1], (GLsizei)last_viewport[2], (GLsizei)last_viewport[3]);
}

void
gl_draw(int x, int y, u_int width, u_int height)
{
	GLuint view_x, view_y;
	GLsizei view_width, view_height;

	GLfloat tex_left, tex_right;
	if (x >= 0)
	{
		view_x = x;
		view_width = width;
		tex_left = 0.f;
	}
	else
	{
		view_x = 0;
		int left_inset = -x;
		view_width = width - left_inset;
		tex_left = (GLfloat)left_inset / width;
	}

	int right_x = view_x + view_width;
	if (right_x <= tk_draw_width)
		tex_right = 1.f;
	else
	{
		int right_inset = right_x - tk_draw_width;
		view_width -= right_inset;
		tex_right = 1.f - (GLfloat)right_inset / width;
	}

	GLfloat tex_bottom, tex_top;
	if (y >= 0)
	{
		view_y = y;
		view_height = height;
		tex_bottom = 1.f;
	}
	else
	{
		int bottom_inset = -y;
		tex_bottom = 1.f - ((GLfloat)bottom_inset / height);
		view_height = height - bottom_inset;
		view_y = 0;
	}

	int top_x = view_y + view_height;
	if (top_x <= tk_draw_height)
		tex_top = 0.f;
	else
	{
		int top_inset = top_x - tk_draw_height;
		view_height -= top_inset;
		tex_top = (GLfloat)top_inset / height;
	}

	glViewport(view_x, view_y, view_width, view_height);
	gl_check_errors("set viewport");

	glUseProgram(gl_program);
	glBindVertexArray(gl_vao);
	glBindBuffer(GL_ARRAY_BUFFER, gl_vao);
	gl_check_errors("Bind program and buffers");

	struct gl_vertex
	{
		GLfloat x, y;
		GLfloat u, v;
	} vertices[2][3];

	// u and v flipped because Virtual Boy framebuffer is column-major
	vertices[0][0].x = vertices[1][0].x = vertices[1][2].x = -1.f;
	vertices[0][0].v = vertices[1][0].v = vertices[1][2].v = tex_left;
	vertices[0][1].x = vertices[0][2].x = vertices[1][1].x = 1.f;
	vertices[0][1].v = vertices[0][2].v = vertices[1][1].v = tex_right;

	vertices[0][0].y = vertices[0][1].y = vertices[1][0].y = -1.f;
	vertices[0][0].u = vertices[0][1].u = vertices[1][0].u = tex_bottom;
	vertices[0][2].y = vertices[1][1].y = vertices[1][2].y = 1.f;
	vertices[0][2].u = vertices[1][1].u = vertices[1][2].u = tex_top;

	glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_DYNAMIC_DRAW);
	if (!gl_check_errors("update buffer data"))
		return;

	glEnable(GL_BLEND);
	glBlendFunc(GL_ONE, GL_ONE);
	glBlendEquation(GL_FUNC_ADD);

	if (gl_draw_left)
	{
		glBindTexture(GL_TEXTURE_2D, gl_textures[TEXTURE_LEFT]);
		glUniform4f(gl_color_uniform, 1.0, 0, 0, 1.0);
		glDrawArrays(GL_TRIANGLES, 0, 6);
		gl_check_errors("draw left");
	}

	if (gl_draw_right)
	{
		glBindTexture(GL_TEXTURE_2D, gl_textures[TEXTURE_RIGHT]);
		glUniform4f(gl_color_uniform, 0, 0, 1.0, 1.0);
		glDrawArrays(GL_TRIANGLES, 0, 6);
		gl_check_errors("draw right");
	}
}

void
gl_debug_clear(void)
{
	static const u_int32_t black = 0xff000000;
	memset_pattern4(gl_debug_frame, &black, sizeof(gl_debug_frame));
}
void
gl_debug_draw(u_int x, u_int y, u_int8_t pixel)
{
	assert(x < 512 && y < 512);
	u_int32_t argb = pixel;
	argb|= argb << 2;
	argb|= argb << 4;
	argb|= (argb << 8) | (argb << 16);
	gl_debug_frame[y * 512 + x] = argb;
}

u_int
gl_debug_blit(gl_texture texture)
{
	glBindTexture(GL_TEXTURE_2D, gl_textures[texture]);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 512, 512, 0, GL_RGBA, GL_UNSIGNED_INT_8_8_8_8_REV, gl_debug_frame);
	return gl_textures[texture];
}
