# Magicmida

Magicmida is a Themida auto-unpacker that works on some 32-bit applications. It works on all versions of Windows (XP and later).

Functions:
* Unpack: Unpacks the binary you select. The unpacked binary will be saved with an `U` suffix.
* Auto create data sections: Restores .rdata/.data sections. Only works on specific targets. This is a must for MSVC applications using Thread Local Storage because they don't work properly otherwise.
* Dump process: Allows you to enter the PID of a running process whose .text section will be dumped (overwritten) into an already unpacked file. This is useful after using Oreans Unvirtualizer in OllyDbg. Only works properly if data sections were created.
* Shrink: Deletes all sections that are no longer needed (if you unvirtualized or if your binary does not use virtualization). Warning: This will break your binary for non-MSVC compilers.

Note: The tool focuses on cleanness of the resulting binaries. Things such as VM anti-dump are explicitly *not* fixed. If your target has a virtualized entrypoint, the resulting dump will be broken and won't run (except for MSVC6, which has special fixup code to restore the OEP).

Important: Never activate any compatibility mode options for Magicmida or for the target you're unpacking. It would very likely screw up the unpacking process due to shimming.

Windows sometimes decides to auto-apply compatibility patches to an executable if it crashed before. This AppCompat information is stored in the registry and is linked to the exact path of your executable. This can be a problem if you're upgrading to a newer Magicmida version that has fixes for your target. You can try moving your target to a different path or look around in the subkeys of `HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`.

## Anti-anti-debugging

Newer versions of Themida detect hardware breakpoints. In order to deal with this, injecting ScyllaHide is supported. A suitable profile is shipped with Magicmida. You just need to download SycllaHide and put `HookLibraryx86.dll` and `InjectorCLIx86.exe` next to `Magicmida.exe`. Do not overwrite scylla_hide.ini unless you know what you're doing.
