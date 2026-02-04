unit ThemidaCommon;

interface

uses Windows, SysUtils, Generics.Collections, DebuggerCore, Dumper, Tracer, Utils, BeaEngineDelphi;

type
  TTMCommon = class(TDebuggerCore)
  protected
    FCreateDataSections: Boolean;
    FBaseOfData: UIntPtr;
    FImageBoundary: UIntPtr;
    FPESections: array of TImageSectionHeader;
    FMajorLinkerVersion: Byte;

    TMSect: PByte;
    TMSectR: TMemoryRegion;

    FThemidaV3, FIsVMOEP: Boolean;

    FGuardAddrs: TList<NativeUInt>;

    // These are used by TraceIsAtAPI.
    FTracedAPI: NativeUInt;
    FSleepAPI, FlstrlenAPI: NativeUInt;
    FTraceStartSP: NativeUInt;
    FTraceInVM: Boolean;

    procedure InitPEDetails(NT: PImageNTHeaders);

    procedure CheckVirtualizedOEP(OEP: NativeUInt);

    function DetermineIATAddress(OEP: NativeUInt; Dumper: TDumper): NativeUInt;
    procedure TraceImports(IAT: NativeUInt; Dumper: TDumper);

    function TraceIsAtAPI(Tracer: TTracer; var C: TContext): Boolean; virtual; abstract;
  end;

function DisasmCheck(var Dis: TDisasm): Integer;

implementation

{$POINTERMATH ON}

function DisasmCheck(var Dis: TDisasm): Integer;
begin
  Dis.Archi := SizeOf(Pointer) * 8;
  Result := Disasm(Dis);
  if (Result = UNKNOWN_OPCODE) or (Result = OUT_OF_BLOCK) then
    raise Exception.CreateFmt('Disasm result: %d (EIP = %X)', [Result, Dis.EIP]);
end;

procedure TTMCommon.InitPEDetails(NT: PImageNTHeaders);
var
  Sect: PImageSectionHeader;
  i: Integer;
begin
  Sect := Pointer(PByte(NT) + SizeOf(NT^));

  SetLength(FPESections, NT^.FileHeader.NumberOfSections);
  for i := 0 to High(FPESections) do
    FPESections[i] := Sect[i];

  if NT^.OptionalHeader.AddressOfEntryPoint < FPESections[0].VirtualAddress + FPESections[0].Misc.VirtualSize then
    raise Exception.Create('The selected binary does not seem to be packed (entrypoint is in .text section).');

  FImageBoundary := NT^.OptionalHeader.SizeOfImage + FImageBase;
  Log(ltInfo, Format('Image boundary: %p', [Pointer(FImageBoundary)]));

  FMajorLinkerVersion := NT^.OptionalHeader.MajorLinkerVersion;
  Log(ltInfo, Format('Image linker: %d.%d', [FMajorLinkerVersion, NT^.OptionalHeader.MinorLinkerVersion]));
end;

procedure TTMCommon.CheckVirtualizedOEP(OEP: NativeUInt);
var
  Code: packed record
    Instr: Byte;
    Displ: UInt32;
  end;
begin
  RPM(OEP, @Code, 5);
  if (Code.Instr <> $E9) or (OEP + 5 + Code.Displ < TMSectR.Address) then
    Exit;

  FIsVMOEP := True;
  Log(ltInfo, 'OEP is virtualized (!): jmp ' + IntToHex(OEP + 5 + Code.Displ, 8));
end;

function FindDelphiCall(CodeDump: PByte; CodeSize: Cardinal): Cardinal;
var
  i, Counter: Cardinal;
begin
  // Delphi has type metadata at its .text base rather than code.
  i := 0;
  Counter := 0;
  while i < CodeSize - 6 do
  begin
    if PWord(CodeDump + i)^ = $25FF then
    begin
      Inc(Counter);
      if Counter = 3 then // Skip the first two for good measure
        Exit(i);
    end;
    Inc(i);
  end;

  Result := 0;
end;

function TTMCommon.DetermineIATAddress(OEP: NativeUInt; Dumper: TDumper): NativeUInt;
var
  TextBase, CodeSize, DataSize: NativeUInt;
  DataSectionIndex: Integer;
  CodeDump: PByte;
  NumInstr: Cardinal;

  function FindCallOrJmpPtr(Address: NativeUInt; IgnoreMethodBoundary: Boolean = False): NativeUInt;
  var
    Dis: TDisasm;
    Len: Integer;
    IATPointer, ThePointer: NativeUInt;
  begin
    Result := 0;
    FillChar(Dis, SizeOf(Dis), 0);
    Dis.EIP := NativeUInt(CodeDump) + Address - TextBase;
    Dis.VirtualAddr := Address;
    while (NumInstr < 200) or (IgnoreMethodBoundary and (Address < TextBase + CodeSize)) do
    begin
      Len := DisasmCheck(Dis);

      if (PWord(Dis.EIP)^ = $15FF) or (PWord(Dis.EIP)^ = $25FF) then // call dword ptr/jmp dword ptr
      begin
        Log(ltInfo, 'Found ' + IntToHex(Dis.VirtualAddr, 8) + ' : ' + string(AnsiString(Dis.CompleteInstr)));
        IATPointer := Dis.Operand1.Memory.Displacement;
        {$IFDEF CPUX64}
        Inc(IATPointer, Dis.VirtualAddr + 6);  // RIP-relative
        {$ENDIF}
        // Ensure we didn't stumble upon a pointer into .text.
        if not RPM(IATPointer, @ThePointer, SizeOf(ThePointer)) or (ThePointer > TextBase + CodeSize) then
          Exit(IATPointer);
      end;

      if (PByte(Dis.EIP)^ = $E8) and not IgnoreMethodBoundary then // call
      begin
        if Dis.Instruction.AddrValue > TextBase + CodeSize then
          Exit(0); // 32-bit: Probably direct API call. Handled below via FGuardAddrs.

        Result := FindCallOrJmpPtr(Dis.Instruction.AddrValue);
        if Result <> 0 then
          Exit;
      end;

      if ((PByte(Dis.EIP)^ = $C3) or (PByte(Dis.EIP)^ = $C2)) and not IgnoreMethodBoundary then // ret
        Exit(0);

      Inc(NumInstr);
      if Len > 0 then
      begin
        Inc(Dis.EIP, Len);
        Inc(Dis.VirtualAddr, Len);
      end
      else // better luck next time...
      begin
        Inc(Dis.EIP, 1);
        Inc(Dis.VirtualAddr, 1);
      end;
    end;
  end;

  function ScanData(ToFind: NativeUInt; ScanCode: Boolean = False): NativeUInt;
  var
    StartOffset, ScanSize: NativeUInt;
    DataSect: PByte;
    DataSectWalker, DataSectBound: PNativeUInt;
  begin
    if not ScanCode then
    begin
      StartOffset := TextBase + CodeSize;
      ScanSize := DataSize;
    end
    else
    begin
      StartOffset := TextBase;
      ScanSize := CodeSize;
    end;

    GetMem(DataSect, ScanSize);
    try
      if not RPM(StartOffset, DataSect, ScanSize) then
        raise Exception.Create('DetermineIATAddress.ScanData: RPM failed');

      // We assume the table is machine-word aligned.
      DataSectWalker := PNativeUInt(DataSect);
      DataSectBound := PNativeUInt(DataSect + ScanSize);

      while DataSectWalker < DataSectBound do
      begin
        if DataSectWalker^ = ToFind then
          Exit(NativeUInt(PByte(DataSectWalker) - DataSect) + StartOffset);
        Inc(DataSectWalker);
      end;
    finally
      FreeMem(DataSect);
    end;

    if ScanCode then
      raise Exception.Create('Unable to find API in section')
    else // Retry with first part of section in case of extreme merges (Themida V1).
      Result := ScanData(ToFind, True);
  end;

var
  IATRef, Seeker, Target: NativeUInt;
  IATData: array[0..(MAX_IAT_SIZE div SizeOf(Pointer)) - 1] of NativeUInt;
  Site: array[0..5] of Byte;
  i, Consecutive0: Integer;
begin
  // For MSVC, the IAT often resides at FImageBase + FBaseOfData
  // Other compilers such as Delphi use a dedicated .idata section, but the IAT doesn't start directly at the beginning, so some guesswork is needed

  DataSectionIndex := 0;
  for i := 0 to High(FPESections) do
    if FBaseOfData < FPESections[i].VirtualAddress + FPESections[i].Misc.VirtualSize then
    begin
      DataSectionIndex := i;
      Break;
    end;

  TextBase := FImageBase + FPESections[0].VirtualAddress;
  CodeSize := FBaseOfData - FPESections[0].VirtualAddress;
  DataSize := FPESections[DataSectionIndex].Misc.VirtualSize - (FBaseOfData - FPESections[DataSectionIndex].VirtualAddress);
  Log(ltInfo, Format('Text base: 0x%.8X, code size: 0x%X, data size: 0x%X', [TextBase, CodeSize, DataSize]));
  NumInstr := 0;
  IATRef := 0;
  GetMem(CodeDump, CodeSize);
  try
    if not RPM(TextBase, CodeDump, CodeSize) then
      raise Exception.Create('DetermineIATAddress: RPM failed');

    if not FIsVMOEP then
      IATRef := FindCallOrJmpPtr(OEP)
    else if (PCardinal(@CodeDump[{$IFDEF CPUX86}6{$ELSE}10{$ENDIF}])^ = $6C6F6F42) or (PCardinal(@CodeDump[6])^ = $65747942) then
      IATRef := FindCallOrJmpPtr(TextBase + FindDelphiCall(CodeDump, CodeSize), True)
    else
      IATRef := FindCallOrJmpPtr(TextBase, True);

    if IATRef = 0 then
    begin
      Log(ltInfo, 'No IAT reference found via reference search');
      if FGuardAddrs.Count > 0 then
      begin
        RPM(FGuardAddrs[0], @Site, 6);
        if (Site[0] = $E8) or (Site[0] = $E9) then
          Target := PCardinal(@Site[1])^ + FGuardAddrs[0] + 5
        else if (Site[1] = $E8) or (Site[1] = $E9) then
          Target := PCardinal(@Site[2])^ + FGuardAddrs[0] + 6
        else
          raise Exception.Create('First guard addr is not call/jmp');

        Log(ltInfo, Format('First guard addr %.8X yielded API %.8X', [FGuardAddrs[0], Target]));
        IATRef := ScanData(Target);
      end
      else
        raise Exception.Create('Found no way to obtain IAT reference');
    end;
    Log(ltGood, 'First IAT ref: ' + IntToHex(IATRef, 8));
  finally
    FreeMem(CodeDump);
  end;

  // The IATRef we obtained points somewhere into the IAT area. Now we need to figure out the start of the table.
  Result := 0;
  Seeker := IATRef;
  // Read data such that IATData[High(IATData)] is the pointer at IATRef.
  RPM(IATRef - (SizeOf(IATData) - SizeOf(Pointer)), @IATData, SizeOf(IATData));
  Consecutive0 := 0;
  i := High(IATData);
  while i >= 0 do
  begin
    if IATData[i] = 0 then
    begin
      Inc(Consecutive0);
      if Consecutive0 > 64 then // Yes there are legit executables that have almost 0x100 bytes between their thunks.
        Break;
    end
    else if Dumper.IsAPIAddress(IATData[i]) or (FThemidaV3 and TMSectR.Contains(IATData[i])) then
    begin
      Result := Seeker;
      Consecutive0 := 0;
    end
    else
    begin
      Log(ltInfo, Format('Ending IAT start search at %X because pointer is %X', [Seeker, IATData[i]]));
      Break;
    end;

    Dec(i);
    Dec(Seeker, SizeOf(Pointer));
  end;
  if i = -1 then
    raise Exception.Create('IAT too big');

  if Result = 0 then
    raise Exception.Create('IAT assertion failed');
end;

procedure TTMCommon.TraceImports(IAT: NativeUInt; Dumper: TDumper);
var
  IATData: array[0..(MAX_IAT_SIZE div SizeOf(Pointer)) - 1] of NativeUInt;
  i, OldProtect, TrashCounter: Cardinal;
  NumWritten: NativeUInt;
  DidSetExitProcess: Boolean;
  Ctx: TContext;
begin
  RPM(IAT, @IATData, SizeOf(IATData));

  DidSetExitProcess := False;
  TrashCounter := 0;
  for i := 0 to High(IATData) do
  begin
    if TMSectR.Contains(IATData[i]) then
    begin
      Log(ltInfo, Format('Trace: %.8X [%.8X]', [IATData[i], IAT + i * SizeOf(Pointer)]));

      TrashCounter := 0;

      Ctx.ContextFlags := CONTEXT_CONTROL;
      GetThreadContext(Threads[FCurrentThreadID], Ctx);
      FTraceStartSP := {$IFDEF CPUX86}Ctx.Esp{$ELSE}Ctx.Rsp{$ENDIF};

      FTracedAPI := 0;
      FTraceInVM := False;
      with TTracer.Create(FProcess.dwProcessId, FCurrentThreadID, Threads[FCurrentThreadID], TraceIsAtAPI, Log) do
        try
          // Normally a couple hundred suffice, but newer Themida v3 versions do some export directory walking...
          Trace(IATData[i], 500000);

          if FTraceInVM then
          begin
            if not DidSetExitProcess then
            begin
              DidSetExitProcess := True;
              // ExitProcess seems to be a special case that resolves to a VM func - we assume there is only one such case
              IATData[i] := NativeUInt(GetProcAddress(GetModuleHandle(kernel32), 'ExitProcess'));
              Log(ltInfo, 'Setting API to ExitProcess');
            end
            else
            begin
              Log(ltFatal, 'Unable to determine IAT address for ' + IntToHex(IAT + i * SizeOf(NativeUInt), 8));
            end;
          end
          else if FTracedAPI <> 0 then
          begin
            Log(ltInfo, '-> ' + IntToHex(FTracedAPI, 8));
            if (FTracedAPI < $10000) or ((FTracedAPI >= FImageBase) and (FTracedAPI < FImageBoundary)) then
            begin
              Log(ltInfo, 'Discarding result & aborting IAT tracing');
              Break;
            end;
            IATData[i] := FTracedAPI;
          end
          else
            Log(ltFatal, 'Tracing failed!');
        finally
          Free;
        end;
    end
    else if (IATData[i] = 0) or not Dumper.IsAPIAddress(IATData[i]) then
    begin
      Inc(TrashCounter);
      if TrashCounter > 64 then
        Break;
    end
    else
      TrashCounter := 0;
  end;

  VirtualProtectEx(FProcess.hProcess, Pointer(IAT), SizeOf(IATData), PAGE_READWRITE, @OldProtect);
  if not WriteProcessMemory(FProcess.hProcess, Pointer(IAT), @IATData, SizeOf(IATData), NumWritten) then
    RaiseLastOSError;
end;

end.
