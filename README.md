# Magicmida

Magicmida is a Themida auto unpacker for 32-bit and 64-bit applications.

Functions:
* Unpack: Unpacks the binary you select. The unpacked binary will be saved with an `U` suffix.
* Auto create data sections: Restores .rdata/.data sections. Only works on specific targets. This is a must for MSVC applications using Thread Local Storage because they don't work properly otherwise.
* Dump process: Allows you to enter the PID of a running process whose .text section will be dumped (overwritten) into an already unpacked file. This is useful after using Oreans Unvirtualizer in OllyDbg. Only works properly if data sections were created.
* Shrink: Deletes all sections that are no longer needed (if you unvirtualized or if your binary does not use virtualization). Warning: This will break your binary for non-MSVC compilers.

Notes about running unpacked binaries:
* **VM anti-dumps are explicitly not fixed.** If your target has a virtualized entrypoint or any other virtualized code, the resulting dump will be broken and won't run (or it will only run on your system until you reboot, because many anti-dumps use DLL base addresses). Fixing this is possible with special tool assistance, but tedious.
* Unpacked DLLs will miss relocation information, which can make them problematic to use in bigger applications that load a lot of libraries.

Important: Never activate any compatibility mode options for Magicmida or for the target you're unpacking. It would very likely screw up the unpacking process due to shimming.

Windows sometimes decides to auto-apply compatibility patches to an executable if it crashed before. This AppCompat information is stored in the registry and is linked to the exact path of your executable. This can be a problem if you're upgrading to a newer Magicmida version that has fixes for your target. You can try moving your target to a different path or look around in the subkeys of `HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`.

Old targets from 2007-2009 often don't unpack properly on modern Windows versions (this is the case if the process gets stuck on high CPU for more than 2 minutes); these unfortunately require Windows XP to unpack.

## Anti-anti-debugging

Newer versions of Themida detect hardware breakpoints. In order to deal with this, injecting [ScyllaHide](https://github.com/x64dbg/ScyllaHide/releases) is supported. A suitable profile is shipped with Magicmida. You just need to download SycllaHide and put `HookLibraryx86.dll` and `InjectorCLIx86.exe` next to `Magicmida.exe`. Do not overwrite scylla_hide.ini unless you know what you're doing.

## Command line usage

If you'd like to automate unpacking, it's possible to invoke Magicmida as a command line application.
To do so, pass the parameters `/unpack <filename>`.

## Unpacking applications with uiAccess=true

When unpacking an application that has `uiAccess="true"` in its manifest, you'll likely get process creation error code 740 even when running Magicmida as Administrator.
To get around this, you need to perform the following steps:

1. In `Magicmida.exe.manifest`, change `uiAccess` to `true` and recompile.
1. You need to have some version of Windows SDK installed.
1. Run `makecert.exe -r -pe -ss MMTestCert MMTestCert.cer`.
1. Run `certmgr -add MMTestCert.cer -s -r localMachine root`.
1. In my case, I also had to manually copy the cert to the "Trusted Root Certificate" store.
1. Run `signtool.exe sign /s MMTestCert Magicmida.exe`.
1. Copy Magicmida to `C:\Program Files (x86)\Magicmida` and run it from there. This step is important because uiAccess applications need to be in a "trusted location".

## Building

Magicmida can be built with the latest and second-to-latest versions of Delphi Community Edition.

FreePascal/Lazarus is also supported as a build environment, but you'll be dealing with some broken icons in the GUI. x64 builds require a recent-ish FPC git commit.

The BeaEngine object files are built from my [fork](https://github.com/Hendi48/beaengine) of BeaEngine 5.1. There's typically no reason to rebuild them.

## License

Magicmida is licensed under GPLv3.

The [BeaEngine](https://github.com/BeaEngine/beaengine) object and header files are licensed under LGPLv3.
