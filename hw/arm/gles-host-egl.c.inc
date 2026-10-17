/*
 * Linux host context backend: EGL, desktop OpenGL (compatibility profile).
 *
 * #included by gles-host.c when it is built with GLES_HOST_EGL (see meson.build,
 * option ltm_host_egl). This is the third context backend next to macOS CGL and
 * iOS EAGL, and it is deliberately the CGL one's twin rather than the ES one's:
 * the renderer in gles-host.c speaks fixed-function desktop GL (glBegin/GL_QUADS,
 * glPushAttrib, glOrtho on doubles, EXT_framebuffer_object, ...), which is what
 * Mesa exposes through EGL_OPENGL_API with no version requested -- a
 * compatibility context, as GLX would hand out. A GLES1 context would instead
 * select the EAGL code path and its renames, and Mesa's GLES1 is optional and
 * often absent.
 *
 * Nothing is ever drawn to a window. The renderer draws into its own FBO and
 * reads the finished frame back with glReadPixels, so the context needs no
 * drawable at all: with EGL_KHR_surfaceless_context it is made current on
 * EGL_NO_SURFACE, and otherwise on a 1x1 pbuffer. That is also what lets this
 * run headless (no X, no Wayland) on the Mesa surfaceless platform.
 *
 * The rest of gles-host.c is written against CGL's names (CGLContextObj,
 * CGLSetCurrentContext, CGLRetainContext, CGLReleaseContext), and so is the
 * ANGLE adapter in gles-host-angle.c.inc. This file maps those four onto EGL
 * the same way, so the share-group and context-lifetime code does not fork.
 *
 * Copyright (c) 2026 the qemu-ios contributors.
 */
#include <EGL/egl.h>
#include <EGL/eglext.h>

#define CGLContextObj GLESEglContextRef
#define CGLSetCurrentContext gles_egl_set_current
#define CGLRetainContext gles_egl_retain
#define CGLReleaseContext gles_egl_release

typedef struct GLESEglContext {
    EGLContext context;
    EGLSurface surface;         /* EGL_NO_SURFACE when the display is surfaceless-capable */
    unsigned refs;
} *CGLContextObj;

static EGLDisplay egl_display = EGL_NO_DISPLAY;
static EGLConfig egl_config;
static bool egl_surfaceless;
static bool egl_init_failed;
/* Only the vCPU thread touches GL, but keep the cache per thread like CGL's
 * current-context slot so a second thread cannot corrupt it. */
static __thread CGLContextObj egl_current;

/* Whole-token match in a space-separated EGL extension string. */
static bool gles_egl_has_ext(const char *list, const char *name)
{
    size_t n = strlen(name);
    const char *p = list;

    while (p && (p = strstr(p, name))) {
        bool start = p == list || p[-1] == ' ';
        bool end = p[n] == ' ' || p[n] == '\0';

        if (start && end) {
            return true;
        }
        p += n;
    }
    return false;
}

/*
 * Bring up the display once. Prefer the Mesa surfaceless platform, which needs
 * no window system at all, and fall back to whatever the default display is
 * (X11 or Wayland through glvnd). IT_GLES_EGL_PLATFORM=default skips the first
 * attempt, which is the knob for a driver that only works through a window
 * system. Failure is sticky: every later context request fails the same way,
 * and gles_host_init turns that into the guest's software-renderer fallback.
 */
static bool gles_egl_display_init(void)
{
    static const EGLint config_attrs[] = {
        EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
        EGL_NONE
    };
    const char *client_exts, *want = getenv("IT_GLES_EGL_PLATFORM");
    EGLint major = 0, minor = 0, count = 0;

    if (egl_display != EGL_NO_DISPLAY) {
        return true;
    }
    if (egl_init_failed) {
        return false;
    }

    client_exts = eglQueryString(EGL_NO_DISPLAY, EGL_EXTENSIONS);
    if (!(want && !strcmp(want, "default")) &&
        gles_egl_has_ext(client_exts, "EGL_MESA_platform_surfaceless")) {
        PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform_display =
            (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");

        if (get_platform_display) {
            egl_display = get_platform_display(EGL_PLATFORM_SURFACELESS_MESA,
                                               EGL_DEFAULT_DISPLAY, NULL);
        }
    }
    if (egl_display == EGL_NO_DISPLAY) {
        egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    }
    if (egl_display == EGL_NO_DISPLAY || !eglInitialize(egl_display, &major, &minor)) {
        fprintf(stderr, "[gles-egl] no usable EGL display (eglGetError 0x%x)\n",
                eglGetError());
        goto fail;
    }
    if (!eglBindAPI(EGL_OPENGL_API)) {
        fprintf(stderr, "[gles-egl] EGL %d.%d has no desktop OpenGL API\n", major, minor);
        goto fail;
    }
    if (!eglChooseConfig(egl_display, config_attrs, &egl_config, 1, &count) || !count) {
        fprintf(stderr, "[gles-egl] no EGL config with a desktop GL pbuffer\n");
        goto fail;
    }
    egl_surfaceless = gles_egl_has_ext(eglQueryString(egl_display, EGL_EXTENSIONS),
                                       "EGL_KHR_surfaceless_context");
    fprintf(stderr, "[gles-egl] EGL %d.%d (%s), %s\n", major, minor,
            eglQueryString(egl_display, EGL_VENDOR),
            egl_surfaceless ? "surfaceless context" : "1x1 pbuffer");
    return true;

fail:
    if (egl_display != EGL_NO_DISPLAY) {
        eglTerminate(egl_display);
    }
    egl_display = EGL_NO_DISPLAY;
    egl_init_failed = true;
    return false;
}

/* Create a context that shares objects with `share` (NULL: a new group). */
static bool gles_egl_create(CGLContextObj share, CGLContextObj *out)
{
    CGLContextObj c;
    static const EGLint pbuffer_attrs[] = { EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE };

    if (!gles_egl_display_init()) {
        return false;
    }
    c = g_new0(struct GLESEglContext, 1);
    c->refs = 1;
    c->surface = EGL_NO_SURFACE;
    /* No version or profile requested: under EGL_OPENGL_API that is the
     * compatibility context, at the highest version the driver offers. */
    c->context = eglCreateContext(egl_display, egl_config,
                                  share ? share->context : EGL_NO_CONTEXT, NULL);
    if (c->context == EGL_NO_CONTEXT) {
        fprintf(stderr, "[gles-egl] eglCreateContext failed (0x%x)\n", eglGetError());
        g_free(c);
        return false;
    }
    if (!egl_surfaceless) {
        c->surface = eglCreatePbufferSurface(egl_display, egl_config, pbuffer_attrs);
        if (c->surface == EGL_NO_SURFACE) {
            fprintf(stderr, "[gles-egl] eglCreatePbufferSurface failed (0x%x)\n",
                    eglGetError());
            eglDestroyContext(egl_display, c->context);
            g_free(c);
            return false;
        }
    }
    *out = c;
    return true;
}

static int CGLSetCurrentContext(CGLContextObj c)
{
    if (egl_current == c) {
        return 0;
    }
    if (!eglMakeCurrent(egl_display, c ? c->surface : EGL_NO_SURFACE,
                        c ? c->surface : EGL_NO_SURFACE,
                        c ? c->context : EGL_NO_CONTEXT)) {
        return -1;
    }
    egl_current = c;
    return 0;
}

static CGLContextObj CGLRetainContext(CGLContextObj c)
{
    c->refs++;
    return c;
}

static void CGLReleaseContext(CGLContextObj c)
{
    if (--c->refs) {
        return;
    }
    if (egl_current == c) {
        CGLSetCurrentContext(NULL);
    }
    eglDestroyContext(egl_display, c->context);
    if (c->surface != EGL_NO_SURFACE) {
        eglDestroySurface(egl_display, c->surface);
    }
    g_free(c);
}
