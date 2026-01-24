unit Themida64;

{$IFDEF VER3_2}
  {$ERROR 'FPC 3.2 and older has stack alignment issues in x64 builds.'}
{$ENDIF}

interface

uses Windows, SysUtils, Classes, Utils, Generics.Collections, DebuggerCore, ThemidaCommon, Tracer, Dumper;

type
  TTMDebugger64 = class(TTMCommon)
  private
    CloseHandleAPI, VirtualAllocAPI, FCorExeMain: Pointer;

    FGuardStart, FGuardEnd: NativeUInt;
    FGuardStepping, FTMGuard, FTraceMSVCOEP: Boolean;

    FMSVCInitCookie, FMSVCOEP: NativeUInt;

    FTLSCounter, FTLSTotal: Integer;

    procedure DumpContext(ThreadID: Cardinal);

    function InImageBounds(Address: UIntPtr): Boolean; inline;

    function FindDynamicTM(const APattern: AnsiString; AOff: Cardinal = 0): Cardinal;
    function FindStaticTM(const APattern: AnsiString; AOff: Cardinal = 0): Cardinal;
    procedure SelectThemidaSection(Address: NativeUInt);
    procedure TMInit(var hPE: THandle);

    procedure InstallCodeSectionGuard;
    function IsGuardedAddress(Address: NativeUInt): Boolean;
    function ProcessGuardedAccess(hThread: THandle; const ExcRecord: TExceptionRecord): Cardinal;

    procedure FinishUnpacking(OEP: NativeUInt);

    function TryFindCorrectOEP(HitAddress: NativeUInt): NativeUInt;
    procedure WriteMSVCOEP(CRTStartup: UIntPtr);
  protected
    function TraceIsAtAPI(Tracer: TTracer; var C: TContext): Boolean; override;
  protected
    procedure OnDebugStart(var hPE: THandle; hThread: THandle); override;
    function OnAccessViolation(hThread: THandle; const ExcRec: TExceptionRecord): Cardinal; override;
    procedure OnDLLLoad(const FileName: UnicodeString; BaseAddress: Pointer); override;
    function OnSinglestep(BPA: NativeUInt): Cardinal; override;
    procedure OnHardwareBreakpoint(hThread: THandle; BPA: NativeUInt; var C: TContext); override;
    function OnSoftwareBreakpoint(hThread: THandle; BPA: Pointer): TSoftBPAction; override;
  public
    constructor Create(const AExecutable, AParameters: string; ACreateData: Boolean);
    destructor Destroy; override;
  end;

implementation

uses Math, ShellAPI;

{ TDebugger }

constructor TTMDebugger64.Create(const AExecutable, AParameters: string; ACreateData: Boolean);
begin
  FCreateDataSections := ACreateData; // Currently does nothing.
  FThemidaV3 := True; // Themida V2 is not supported on x64 atm.

  FGuardAddrs := TList<NativeUInt>.Create;

  inherited Create(AExecutable, AParameters, Utils.Log);
end;

destructor TTMDebugger64.Destroy;
begin
  FGuardAddrs.Free;

  inherited;
end;

function TTMDebugger64.InImageBounds(Address: UIntPtr): Boolean;
begin
  Result := (Address >= FImageBase) and (Address < FImageBoundary);
end;

procedure TTMDebugger64.SelectThemidaSection(Address: NativeUInt);
var
  i: Integer;
begin
  for i := 0 to High(FPESections) do
    if (Address >= FPESections[i].VirtualAddress + FImageBase) and (Address < FPESections[i].VirtualAddress + FPESections[i].Misc.VirtualSize + FImageBase) then
    begin
      TMSectR.Address := FPESections[i].VirtualAddress + FImageBase;
      TMSectR.Size := FPESections[i].Misc.VirtualSize;
      GetMem(TMSect, TMSectR.Size);
      if not RPM(TMSectR.Address, TMSect, TMSectR.Size) then
      begin
        FreeMem(TMSect);
        TMSect := nil;
      end;
      Log(ltInfo, Format('TMSect: %X (%d bytes)', [TMSectR.Address, TMSectR.Size]));
      Break;
    end;

  if TMSect = nil then
    raise Exception.CreateFmt('Unable to find section for %X', [Address]);
end;

procedure TTMDebugger64.OnDebugStart(var hPE: THandle; hThread: THandle);
var
  MMPath: string;
begin
  MMPath := ExtractFilePath(ParamStr(0));
  if FileExists(MMPath + 'InjectorCLIx64.exe') then
  begin
    Log(ltGood, 'Applying ScyllaHide');
    ShellExecute(0, 'open', PChar(MMPath + 'InjectorCLIx64.exe'), PChar(Format('pid:%d %s nowait', [FProcess.dwProcessId, MMPath + 'HookLibraryx64.dll'])), nil, SW_HIDE);
  end
  else
    raise Exception.Create('ScyllaHide is mandatory for Themida64 (InjectorCLIx64.exe not found)');

  VirtualAllocAPI := GetProcAddress(GetModuleHandle(kernel32), 'VirtualAlloc');

  FSleepAPI := NativeUInt(GetProcAddress(GetModuleHandle(kernel32), 'Sleep'));
  FlstrlenAPI := NativeUInt(GetProcAddress(GetModuleHandle(kernel32), 'lstrlen'));

  TMInit(hPE);
end;

function TTMDebugger64.OnAccessViolation(hThread: THandle; const ExcRec: TExceptionRecord): Cardinal;
begin
  if IsGuardedAddress(ExcRec.ExceptionInformation[1]) then
    Result := ProcessGuardedAccess(hThread, ExcRec)
  else
    Result := inherited;
end;

procedure TTMDebugger64.OnDLLLoad(const FileName: UnicodeString; BaseAddress: Pointer);
var
  hCorEE: HMODULE;
begin
  if Pos('\mscoree.dll', FileName) > 0 then
  begin
    Log(ltInfo, 'This might be a .NET program - setting _CorExeMain BP');
    hCorEE := LoadLibrary('mscoree.dll'); // Load in this process
    if hCorEE = HMODULE(BaseAddress) then
    begin
      FCorExeMain := GetProcAddress(hCorEE, '_CorExeMain');
      SetSoftBP(FCorExeMain);
    end
    else
      Log(ltFatal, 'DLL was loaded at different base than in target!');
  end;

  inherited;
end;

procedure TTMDebugger64.OnHardwareBreakpoint(hThread: THandle; BPA: NativeUInt; var C: TContext);
var
  EIP: Pointer;
  Buf: UIntPtr;
begin
  EIP := Pointer(C.Rip);

  if EIP = CloseHandleAPI then
  begin
    RPM(C.Rsp, @Buf, 8);

    Log(ltInfo, Format('CloseHandle called from from %p', [Pointer(Buf)]));

    if InImageBounds(Buf) then
    begin
      ResetBreakpoint(EIP);
      SetBreakpoint(FImageBase + $1000, hwWrite);
    end;
  end
  else if EIP = VirtualAllocAPI then
  begin
    RPM(C.Rsp, @Buf, 8);
    Log(ltInfo, Format('AllocMem called from %X', [Buf]));

    if InImageBounds(Buf) then
    begin
      ResetBreakpoint(VirtualAllocAPI);
      InstallCodeSectionGuard;
    end;
  end
  else if BPA = FImageBase + $1000 then
  begin
    Log(ltGood, Format('Wrote to .text base from %X', [UIntPtr(EIP)]));

    if TMSectR.Address = 0 then
      SelectThemidaSection(UIntPtr(EIP));

    ResetBreakpoint(Pointer(FImageBase + $1000));
    SetBreakpoint(UIntPtr(VirtualAllocAPI), hwExecute);
  end
  else
  begin
    Log(ltInfo, Format('Accessed %x from %p', [BPA, EIP]));
  end;
end;

function TTMDebugger64.OnSinglestep(BPA: NativeUInt): Cardinal;
var
  OldProt: DWORD;
begin
  if FGuardStepping then
  begin
    if not VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_NOACCESS, @OldProt) then
      RaiseLastOSError;
    FGuardStepping := False;
    Exit(DBG_CONTINUE);
  end;

  Result := inherited;
end;

function TTMDebugger64.OnSoftwareBreakpoint(hThread: THandle; BPA: Pointer): TSoftBPAction;
begin
  if BPA = FCorExeMain then
  begin
    with TDumperDotnet.Create(FProcess, FImageBase) do
      try
        DumpToFile(ExtractFilePath(FExecutable) + ChangeFileExt(ExtractFileName(FExecutable), 'U' + ExtractFileExt(FExecutable)));
      finally
        Free;
      end;

    Log(ltGood, '.NET process dumped.');

    FHideThreadEnd := True;
    TerminateProcess(FProcess.hProcess, 0);
    Exit(sbpClearContinue); // w/e
  end;

  raise Exception.CreateFmt('Unexpected SoftBP at %p', [BPA]);
end;

procedure TTMDebugger64.DumpContext(ThreadID: Cardinal);
var
  hThread: THandle;
  C: TContext;
begin
  hThread := Threads[ThreadID];
  C.ContextFlags := CONTEXT_CONTROL or CONTEXT_INTEGER;
  if not GetThreadContext(hThread, C) then
  begin
    Log(ltFatal, 'DumpContext: GetThreadContext failed');
    Exit;
  end;

  Log(ltInfo, Format('rax: %X rbx: %X rcx: %X rdx: %X rsi: %X rdi: %X',
    [C.Rax, C.Rbx, C.Rcx, C.Rdx, C.Rsi, C.Rdi]));
  Log(ltInfo, Format('r8: %X r9: %X r10: %X r11: %X r12: %X r13: %X r14: %X r15: %X',
    [C.R8, C.R9, C.R10, C.R11, C.R12, C.R13, C.R14, C.R15]));
  Log(ltInfo, Format('rip: %X rbp: %X rsp: %X eflags: %X',
    [C.Rip, C.Rbp, C.Rsp, C.EFlags]));
end;

{$POINTERMATH ON}

procedure TTMDebugger64.TMInit(var hPE: THandle);
var
  Buf, BufB, Test: PByte;
  x: Cardinal;
  Sect: PImageSectionHeader;
  w: NativeUInt;
  TLSDir: TImageTLSDirectory64;
  TLSDist: IntPtr;
begin
  if (hPE = 0) or (hPE = INVALID_HANDLE_VALUE) then
  begin
    hPE := CreateFile(PChar(FExecutable), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if hPE = INVALID_HANDLE_VALUE then
      raise Exception.CreateFmt('CreateFile code %d', [GetLastError]);
  end;

  SetFilePointer(hPE, 0, nil, FILE_BEGIN);

  GetMem(Buf, $1000);
  if not ReadFile(hPE, Buf^, $1000, x, nil) then
    raise Exception.CreateFmt('ReadFile failed! Code: %d', [GetLastError]);
  BufB := Buf;

  Inc(Buf, PImageDosHeader(Buf)^._lfanew);
  Pointer(Sect) := Buf + SizeOf(TImageNTHeaders);

  SetLength(FPESections, PImageNTHeaders(Buf).FileHeader.NumberOfSections);
  for x := 0 to High(FPESections) do
    FPESections[x] := Sect[x];

  FBaseOfData := Sect[0].VirtualAddress + PImageNTHeaders(Buf).OptionalHeader.SizeOfCode;
  FMajorLinkerVersion := PImageNTHeaders(Buf).OptionalHeader.MajorLinkerVersion;

  // PE Header Antidump
  if Sect[2].Name[1] = Ord('i') then
  begin
    Test := PByte(PByte(@Sect[2].Name[1]) - BufB) + FImageBase;
    VirtualProtectEx(FProcess.hProcess, Test, 1, PAGE_READWRITE, @x);
    x := Ord('p');
    if not WriteProcessMemory(FProcess.hProcess, Test, @x, 1, w) then
      raise Exception.CreateFmt('Fixing PE header antidump failed! Code: %d', [GetLastError]);
  end;

  FImageBoundary := PImageNTHeaders(Buf)^.OptionalHeader.SizeOfImage + FImageBase;
  Log(ltInfo, Format('Image boundary: %p', [Pointer(FImageBoundary)]));

  if string(AnsiString(PAnsiChar(@Sect[0].Name))) = '.text' then
  begin
    // Code not encrypted/compressed
    Log(ltGood, 'Text section not encrypted/compressed, installing page guard');
    InstallCodeSectionGuard;
  end
  else
  begin
    CloseHandleAPI := GetProcAddress(GetModuleHandle(kernel32), 'CloseHandle');
    SetBreakpoint(UIntPtr(CloseHandleAPI), hwExecute);
  end;

  if PImageNTHeaders(Buf).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0 then
  begin
    with PImageNTHeaders(Buf).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] do
      if RPM(FImageBase + VirtualAddress, @TLSDir, Min(Size, SizeOf(TLSDir))) then
      begin
        // NOTE: This is an MSVC-ism, where we assume the TLS callback pointers are located right
        // before the TLS directory. This allows us to determine the amount of callbacks.
        TLSDist := (FImageBase + VirtualAddress) - TLSDir.AddressOfCallBacks;
        if (TLSDist > 0) and (TLSDist <= SizeOf(Pointer) * (4+1)) then // Assume at most 4 TLS entries + zero terminator
        begin
          FTLSTotal := (TLSDist div SizeOf(Pointer)) - 1;
          Log(ltInfo, Format('[MSVC] Expecting %d TLS entries', [FTLSTotal]));
        end;
      end;
  end;

  FreeMem(BufB);
end;

function TTMDebugger64.FindDynamicTM(const APattern: AnsiString; AOff: Cardinal): Cardinal;
begin
  if AOff <> 0 then
    Dec(AOff, TMSectR.Address);

  Result := FindDynamic(APattern, TMSect + AOff, TMSectR.Size - AOff);
  if Result > 0 then
    Inc(Result, TMSectR.Address + AOff);
end;

function TTMDebugger64.FindStaticTM(const APattern: AnsiString; AOff: Cardinal): Cardinal;
begin
  if AOff <> 0 then
    Dec(AOff, TMSectR.Address);

  Result := FindStatic(APattern, TMSect + AOff, TMSectR.Size - AOff);
  if Result > 0 then
    Inc(Result, TMSectR.Address + AOff);
end;

procedure TTMDebugger64.InstallCodeSectionGuard;
var
  OldProt: DWORD;
begin
  FGuardStart := FImageBase + FPESections[0].VirtualAddress;
  FGuardEnd := FImageBase + FBaseOfData;
  VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_NOACCESS, @OldProt);
end;

function TTMDebugger64.IsGuardedAddress(Address: NativeUInt): Boolean;
begin
  if FGuardStart = 0 then
    Exit(False);

  Result := (Address >= FGuardStart) and (Address < FGuardEnd);
end;

function TTMDebugger64.ProcessGuardedAccess(hThread: THandle; const ExcRecord: TExceptionRecord): Cardinal;
var
  OldProt: Cardinal;
  OEP, RetAddr: NativeUInt;
  C: TContext;
begin
  Log(ltInfo, Format('[Guard] %s %X', [AccessViolationFlagToStr(ExcRecord.ExceptionInformation[0]), ExcRecord.ExceptionInformation[1]]));

  VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_EXECUTE_READWRITE, @OldProt);

  if FTMGuard then
  begin
    // We've hit the Themida section after executing a TLS entypoint.
    FTMGuard := False;
    InstallCodeSectionGuard;
  end
  else if not InImageBounds(UIntPtr(ExcRecord.ExceptionAddress)) then
  begin
    // Random library code reading our text base...
    FGuardStepping := True;
  end
  else if UIntPtr(ExcRecord.ExceptionAddress) > FGuardEnd then
  begin
    // Themida access
    if TMSectR.Address = 0 then
      SelectThemidaSection(UIntPtr(ExcRecord.ExceptionAddress));

    FGuardAddrs.Add(ExcRecord.ExceptionInformation[1]);
    FGuardStepping := True;
  end
  else if (ExcRecord.ExceptionInformation[0] = 8) and (FTLSTotal > 0) and (FTLSCounter < FTLSTotal) then
  begin
    Inc(FTLSCounter);
    Log(ltGood, Format('TLS %d: %.8X', [FTLSCounter, UIntPtr(ExcRecord.ExceptionAddress), 8]));
    FGuardStart := TMSectR.Address;
    FGuardEnd := FImageBoundary;
    FTMGuard := True;
    VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_NOACCESS, @OldProt);
  end
  else if FTraceMSVCOEP then
  begin
    // We're at mainCrtStartup.
    WriteMSVCOEP(UIntPtr(ExcRecord.ExceptionAddress));
    FinishUnpacking(FMSVCOEP);
  end
  else
  begin
    OEP := UIntPtr(ExcRecord.ExceptionAddress);

    // Check if virtualized (but goes to .text first for jmp).
    CheckVirtualizedOEP(OEP);

    // Check if virtualized and stolen (goes straight into VM without using jmp in .text).
    C.ContextFlags := CONTEXT_CONTROL;
    if GetThreadContext(hThread, C) then
    begin
      RPM(C.Rsp, @RetAddr, 8);
      if TMSectR.Contains(RetAddr) {and not IsTMExceptionHandler(RetAddr)} then
      begin
        Log(ltInfo, Format('Return address points into Themida section: %.9X', [RetAddr]));
        OEP := TryFindCorrectOEP(OEP);

        if FTraceMSVCOEP then
        begin
          FMSVCOEP := OEP;

          // Skip and wait for next .text hit.
          C.Rip := RetAddr;
          Inc(C.Rsp, 8);
          if not SetThreadContext(hThread, C) then
            RaiseLastOSError;

          InstallCodeSectionGuard;
          Exit(DBG_CONTINUE);
        end;
      end
      else
        Log(ltGood, 'OEP: ' + IntToHex(OEP, 8));
    end
    else
      Log(ltFatal, 'GetThreadContext failed for further OEP check');

    FinishUnpacking(OEP);
  end;

  if FGuardStepping then
  begin
    // Single-step, then re-protect in OnSinglestep.
    C.ContextFlags := CONTEXT_CONTROL;
    if not GetThreadContext(hThread, C) then
      RaiseLastOSError;
    C.EFlags := C.EFlags or $100;
    SetThreadContext(hThread, C);
  end;

  Result := DBG_CONTINUE;
end;

function TTMDebugger64.TryFindCorrectOEP(HitAddress: NativeUInt): NativeUInt;
var
  TextBuf: PByte;
  TextLen: Integer;
  i: Cardinal;
  ScanFor: Cardinal;
  OEP: NativeUInt;
begin
  Result := HitAddress;
  if not (FMajorLinkerVersion in [9, 10, 11, 12, 14]) then
  begin
    Log(ltFatal, 'Don''t know what to do about OEP for this compiler. Your target likely won''t run.');
    Exit;
  end;

  // MSVC: Assume HitAddress is at __security_init_cookie.
  // Scan for call __security_init_cookie; jmp __scrt_common_main_seh
  TextLen := FBaseOfData - FPESections[0].VirtualAddress;
  GetMem(TextBuf, TextLen);
  try
    RPM(FImageBase + FPESections[0].VirtualAddress, TextBuf, TextLen);

    ScanFor := HitAddress - FImageBase - FPESections[0].VirtualAddress;
    for i := 0 to TextLen - 10 do
      if (TextBuf[i] = $E8) and (TextBuf[i + 5] = $E9) and (PCardinal(@TextBuf[i + 1])^ + i + 5 = ScanFor) then
      begin
        OEP := FImageBase + FPESections[0].VirtualAddress + i;
        Log(ltGood, Format('Found suitable real OEP %.9X', [OEP]));
        Exit(OEP);
      end;

    // Got two suspicious reads as last accesses, checking out the VM jmp at OEP?
    if (FGuardAddrs.Count >= 2) and (FGuardAddrs.Last = FGuardAddrs[FGuardAddrs.Count - 2] + 1) then
    begin
      FMSVCInitCookie := HitAddress;
      FTraceMSVCOEP := True;
      Exit(FGuardAddrs[FGuardAddrs.Count - 2]);
    end;

    Log(ltFatal, 'Real OEP not found. Your target likely won''t run.');
  finally
    FreeMem(TextBuf);
  end;
end;

procedure TTMDebugger64.WriteMSVCOEP(CRTStartup: UIntPtr);
var
  x: NativeUInt;
  Instrs: packed record
    SubRsp: UInt32;
    Call: Byte;
    CallRel: Integer;
    AddRsp: UInt32;
    Jmp: Byte;
    JmpRel: Integer;
  end;
begin
  VirtualProtectEx(FProcess.hProcess, Pointer(FMSVCOEP), SizeOf(Instrs), PAGE_EXECUTE_READWRITE, @x);

  Instrs.SubRsp := $28EC8348;
  Instrs.Call := $E8;
  Instrs.CallRel := FMSVCInitCookie - (FMSVCOEP + 4) - 5;
  Instrs.AddRsp := $28C48348;
  Instrs.Jmp := $E9;
  Instrs.JmpRel := CRTStartup - (FMSVCOEP + 4+5+4) - 5;

  WriteProcessMemory(FProcess.hProcess, Pointer(FMSVCOEP), @Instrs, SizeOf(Instrs), x);

  Log(ltGood, Format('Virtualized MSVC9+ OEP restored: %X', [FMSVCOEP]));
end;

procedure TTMDebugger64.FinishUnpacking(OEP: NativeUInt);
var
  IAT: NativeUInt;
  FN: string;
  Dumper: TDumper;
begin
  Dumper := TDumper.Create(FProcess, FImageBase, OEP);

  // Look for IAT by analyzing code near OEP.
  IAT := DetermineIATAddress(OEP, Dumper);
  Log(ltGood, 'IAT: ' + IntToHex(IAT, 8));

  TraceImports(IAT, Dumper);

  // Process the IAT into an import directory and dump the binary to disk.
  FN := ExtractFilePath(FExecutable) + ChangeFileExt(ExtractFileName(FExecutable), 'U' + ExtractFileExt(FExecutable));
  Dumper.IAT := IAT;
  Dumper.DumpToFile(FN, Dumper.Process());
  Dumper.Free;

  FHideThreadEnd := True;
  TerminateProcess(FProcess.hProcess, 0);

  Log(ltGood, 'Operation completed successfully.');
end;

function TTMDebugger64.TraceIsAtAPI(Tracer: TTracer; var C: TContext): Boolean;
var
  InsnData: Cardinal;
  ReturnAddr: NativeUInt;
begin
  if (Tracer.Counter > 100) and (Tracer.Counter < 5000) then
  begin
    RPM(C.Rip, @InsnData, 4);
    if InsnData = $0CB10FF0 then // First 4 bytes of "lock cmpxchg [rbx+rbp], ecx"
    begin
      FTraceInVM := True;
      Log(ltInfo, 'Trace ran into Themida VM, stopping');
      Exit(True); // Stop
    end;
  end;

  // cat & mouse game with fake calls
  if (C.Rsp < FTraceStartSP) and ((C.Rip = FSleepAPI) or (C.Rip = FlstrlenAPI)) then
  begin
    // It'd be better to just execute them, but the tracer currently faults at far jumps for wow64 syscalls.
    Log(ltInfo, Format('Skipping anti-trace API at %p', [Pointer(C.Rip)]));
    RPM(C.Rsp, @ReturnAddr, SizeOf(ReturnAddr));
    Inc(C.Rsp, SizeOf(ReturnAddr));
    C.Rip := ReturnAddr;
  end;

  Result := not TMSectR.Contains(C.Rip);
  if Result and (C.Rsp < FTraceStartSP) then
  begin
    Log(ltInfo, Format('Warning: Might have encountered new fake API at %.8x', [C.Rip]));
    Result := False;
  end;

  if Result then
    FTracedAPI := C.Rip;
end;

end.

