# Magicmida

Magicmida is a Themida auto-unpacker that works on some 32-bit applications. It works on all versions of Windows (XP and later).

Functions:
* Unpack: Unpacks the binary you select. The unpacked binary will be saved with an `U` suffix.
* MakeDataSects: Restores .rdata/.data sections. Only works on very specific targets.
* Dump process: Allows you to enter the PID of a running process whose .text section will be dumped (overwritten) into an already unpacked file. This is useful after using Oreans Unvirtualizer in OllyDbg. Only works properly if MakeDataSects was done before.
* Shrink: Deletes all sections that are no longer needed (if you unvirtualized or if your binary does not use virtualization).

Note: The tool focuses on cleanness of the resulting binaries. Things such as VM anti-dump are explicitly *not* fixed.

Important: Never activate any compatibility mode options for Magicmida or for the target you're unpacking. It would very likely screw up the unpacking process due to shimming.
