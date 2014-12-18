//
// Copyright 2014
//   Roberto Paleari <roberto@greyhats.it>
//   Aristide Fattori <aristidefattori@gmail.com>
//

// Each FOO() macro defines a new profile. It specifies the following:
// - command-line name for this profile
// - name of the object that implements the profile
// - human-readable name for this profile

FOO(winxpsp3, WindowsXPSP3, "Windows XP SP3")
FOO(win7sp0, Windows7SP0, "Windows 7 SP0")

#if TARGET_LONG_BITS != 32
FOO(linux64_3_2_0, Linux64_3_2_0, "Linux 64-bit (3.2.0)")
FOO(linux64_3_14_0, Linux64_3_14_0, "Linux 64-bit (3.14.0)")
FOO(osxmav, OSXMavericks, "MacOSX Mavericks (10.9.4)")
FOO(win81, Windows8_1, "Windows 8.1")
#endif
