# QTrace analysis framework #

QTrace aims at providing a generic (i.e., OS-independent) framework to
implement "out-of-the-box" analysis modules ("plugins").

QTrace is still under (heavy) development, so get ready to find lots of bugs :-)

## Compilation ##

To compile a QTrace start configuring it using the `qtrace/configure.sh`
script. As an example, to compile for a 64-bit target, without taint tracking
support use the following commands:

	./qtrace/configure.sh -a x64
	make

By default, `qtrace/configure.sh` enables the `systrace` plugin is compiled
(i.e., the "zero knowledge" system call tracer). You can select a different
plugin using the `-p` option. See `qtrace/configure.sh -h` for a complete list
of available configuration settings.

Please note that, to avoid too many compile-time dependencies, the
`qtrace/configure.sh` script compiles QEMU with VNC support only (i.e., no SDL
support). Thus, after QEMU/QTrace is executed, you need a VNC client to connect
to the guest.

Remember also to add the `qtrace` directory to your library path, as QEMU main
executable must be able to load `libqtrace.so`:

	export LD_LIBRARY_PATH=$(pwd)/qtrace

QTrace verbosity level can be adjusted by changing the `LOG_LEVEL` macro
defined in `qtrace/logging.h`.

## Implementation ##

### Modifications to QEMU source code ###

QTrace is currently based on QEMU 2.1.0 but should be quite easy to port it to
future QEMU versions.

Most of QTrace code is under the `qtrace/` directory. Modifications to the
original QEMU source code are enclosed within `<qtrace>...</qtrace>` tags or
`#ifdef CONFIG_QTRACE_* ... #endif` directives.

### Modules ###

QTrace includes two modules: a dynamic tracer and a taint-tracking engine. Most
of the code for these modules can be found under the `qtrace/trace` and
`qtrace/taint` directories, respectively. In turn, the dynamic tracer includes
the plugin-specific code, and some functionalities common to all the plugins.

To separate module-dependent code from QTrace core functionalities, specific
preprocessor identifiers have been used:

- `CONFIG_QTRACE_TRACER`: Code specific to the dynamic tracer.
- `CONFIG_QTRACE_TAINT`: Code specific to the taint-tracking engine.
- `CONFIG_QTRACE_CORE`: "Core" QTrace code, not specific to any other module.

### libqtrace.so ###

Briefly, most of QTrace code has been compiled into a a C++ shared library
(`libqtrace.so`), while trying to minimize modifications to original QEMU
source code.

The only components left in C are those that act as a bridge between QEMU and
`libqtrace.so`. The rationale was to keep the C bridge as thin as possible, and
to move most of the functionalities to the C++ library.

### Directory structure ###

Besides modifications to the original QEMU source code, most of QTrace code
lives under the `qtrace/` directory. In the following, we briefly describe the
structure of the directory tree:

- `qtrace/pb`: Google Protocol Buffer files
- `qtrace/profiles`: Guest OS profiles (OS-dependent code)
- `qtrace/taint`: Taint-tracking engine
- `qtrace/tests`: Unit tests
- `qtrace/trace`: Dynamic tracing code
- `qtrace/trace/plugin-*`: Plugins code

## TODO ##

- Notify CPL changes
- Support taint tracking for 64-bit systems (WIP)

# Plugins #

A QTrace plugin is the module that implements the analyses performed on the
target system.

Code for the plugin `PLUGIN_NAME` live in `qtrace/trace/plugin-PLUGIN_NAME`. A
specific plugin must be chosen at compilation time.

Currently, only two plugins are provided:

- `systrace`, the "zero knowledge" system call tracer. This plugin is enabled
  by default by `qtrace/configure.sh` if no different options are specified.
- `dummy`, a do-nothing plugin, just for testing purposes.

## "Zero knowledge" system call tracer ##

QTrace is a "zero knowledge" system call tracer, based on
[QEMU](http://www.qemu.org). Its main characteristic is that system call
arguments are dumped without the need to instruct the tracer about their
structure.

As an example, QTrace can be used to easily dump `win32k.sys` graphical system
calls (as well as undocumented ones) despite the intricacies in their arguments
(and the lack of official documentation).

Additionally, QTrace includes a dynamic taint-tracking module, used to
(dynamically) track dependencies between system calls (e.g., one of the output
arguments of system call A is eventually used as an input argument for system
call B).

Traced system calls are serialized to a
[Protocol Buffer](https://developers.google.com/protocol-buffers/) stream and
can then be parsed off-line. QTrace includes some basic Python post-processing
tools.

The whole infrastructure is mainly targeted to Windows systems, but can be
extended to support other OSes as well.

### QEMU options ###

QTrace adds the following command-line options to QEMU:

- `qtrace-trace-disabled` Start emulation with syscall tracing disabled.
- `qtrace-taint-disabled` Start emulation with taint-tracking disabled.
- `qtrace-log FILE` Log QTrace messages to `FILE`.
- `qtrace-profile PROFILE` Select which guest OS profile to use.
- `qtrace-trace FILE` Serialize syscalls to `FILE`.
- `qtrace-syscalls FILTER` Comma-separated list of syscall names to process.
- `qtrace-process NAME` Trace only guest process with name `NAME`.
- `qtrace-foreign` Enable foreign pointers tracking.
- `qtrace-rep-accesses` Track repeated memory accesses.

Additionally, QTrace provides some QEMU monitor commands that can be used to
enable/disable syscall tracing and taint-tracking at run-time.

### Usage example ###

The following command line starts a Windows 7 SP0 32-bit image with syscall
tracing and taint-tracking enabled since the very beginning (slow!).

	./i386-softmmu/qemu-system-i386 -qtrace-profile win7sp0 -snapshot -hda win7.qcow2 -qtrace-trace /tmp/win7.trace -qtrace-log /tmp/qtrace.log

The system call trace will be saved to local file `/tmp/win7.trace`, while log
messages are directed to `/tmp/qtrace.log`.

The trace file can then be processed using `tools/qtrace.py`. As an example, to
generate a HTML trace of recorded system calls, use the following syntax:

	python tools/qtrace.py -o /tmp/win7.html -s src/qtrace/trace/win7sp0_syscalls.h /tmp/win7.trace

The `-s` argument is necessary to provide QTrace with the names of the system
calls for the target OS version.
