unit Themida64;

interface

uses Windows, SysUtils, Classes, Utils, TlHelp32, Generics.Collections, DebuggerCore, Dumper;

type
  TTMDebugger64 = class(TDebuggerCore)
  private
    FBaseOfData: UIntPtr;
    FImageBoundary: UIntPtr;
    FPESections: array of TImageSectionHeader;
    FMajorLinkerVersion: Byte;
    FCreateDataSections: Boolean;

    // Themida
    TMSect: PByte;
    TMSectR: TMemoryRegion;
    Base1, RepEIP: UIntPtr;
    CloseHandleAPI, AllocMemAPI, FFirstRealAPI: Pointer;
    BaseAccessed: Boolean;

    FGuardStart, FGuardEnd: NativeUInt;
    FGuardStepping, FTMGuard, FTraceMSVCOEP: Boolean;
    FGuardAddrs: TList<NativeUInt>;

    FMSVCInitCookie, FMSVCOEP: NativeUInt;

    FTLSCounter, FTLSTotal: Integer;

    procedure DumpContext(ThreadID: Cardinal);

    function InImageBounds(Address: UIntPtr): Boolean; inline;

    function FindDynamicTM(const APattern: AnsiString; AOff: Cardinal = 0): Cardinal;
    function FindStaticTM(const APattern: AnsiString; AOff: Cardinal = 0): Cardinal;
    procedure SelectThemidaSection(Address: NativeUInt);
    procedure TMInit(var hPE: THandle);
    function TMFinderCheck(C: PContext): Boolean;

    procedure InstallCodeSectionGuard;
    function IsGuardedAddress(Address: NativeUInt): Boolean;
    function ProcessGuardedAccess(hThread: THandle; const ExcRecord: TExceptionRecord): Cardinal;

    function DetermineIATAddress(OEP: NativeUInt; Dumper: TDumper): NativeUInt;
    procedure FinishUnpacking(OEP: NativeUInt);

    function TryFindCorrectOEP(HitAddress: NativeUInt): NativeUInt;
    procedure WriteMSVCOEP(CRTStartup: UIntPtr);
  protected
    procedure OnDebugStart(var hPE: THandle; hThread: THandle); override;
    function OnAccessViolation(hThread: THandle; const ExcRec: TExceptionRecord): Cardinal; override;
    function OnSinglestep(BPA: NativeUInt): Cardinal; override;
    procedure OnHardwareBreakpoint(hThread: THandle; BPA: NativeUInt; var C: TContext); override;
    function OnSoftwareBreakpoint(hThread: THandle; BPA: Pointer): TSoftBPAction; override;
  public
    constructor Create(const AExecutable, AParameters: string; ACreateData: Boolean);
    destructor Destroy; override;
  end;

implementation

uses BeaEngineDelphi, Math, ShellAPI;

function DisasmCheck(var Dis: TDisasm): Integer;
begin
  Result := Disasm(Dis);
  if (Result = UNKNOWN_OPCODE) or (Result = OUT_OF_BLOCK) then
    raise Exception.CreateFmt('Disasm result: %d (EIP = %X)', [Result, Dis.EIP]);
end;

{ TDebugger }

constructor TTMDebugger64.Create(const AExecutable, AParameters: string; ACreateData: Boolean);
begin
  FCreateDataSections := ACreateData; // Currently does nothing.

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
begin
  if FileExists('InjectorCLIx64.exe') then
  begin
    Log(ltGood, 'Applying ScyllaHide');
    ShellExecute(0, 'open', 'InjectorCLIx64.exe', PChar(Format('pid:%d %s nowait', [FProcess.dwProcessId, ExtractFilePath(ParamStr(0)) + 'HookLibraryx64.dll'])), nil, SW_HIDE);
  end
  else
    raise Exception.Create('ScyllaHide is mandatory for Themida64 (InjectorCLIx64.exe not found)');

  TMInit(hPE);
end;

function TTMDebugger64.OnAccessViolation(hThread: THandle; const ExcRec: TExceptionRecord): Cardinal;
begin
  if IsGuardedAddress(ExcRec.ExceptionInformation[1]) then
    Result := ProcessGuardedAccess(hThread, ExcRec)
  else
    Result := inherited;
end;

procedure TTMDebugger64.OnHardwareBreakpoint(hThread: THandle; BPA: NativeUInt; var C: TContext);
var
  EIP: Pointer;
  Buf, Buf2: UIntPtr;
begin
  EIP := Pointer(C.Rip);

  if EIP = CloseHandleAPI then
  begin
    RPM(C.Rsp, @Buf, 8);

    Log(ltInfo, Format('CloseHandle called from from %p', [Pointer(Buf)]));

    if InImageBounds(Buf) then
    begin
      ResetBreakpoint(EIP);
      SetBreakpoint(FImageBase + $1000, hwAccess);
    end;
  end
  else if EIP = AllocMemAPI then
  begin
    RPM(C.Rsp, @Buf, 8);
    Log(ltInfo, Format('AllocMem called from %X', [Buf]));

    if InImageBounds(Buf) then
    begin
      ResetBreakpoint(AllocMemAPI);
      InstallCodeSectionGuard;
    end;
  end
  else if EIP = FFirstRealAPI then
  begin
    if RPM(C.Rsp, @Buf, 8) then
    begin
      Log(ltGood, 'API called from ' + IntToHex(Buf, 8));
      if InImageBounds(Buf) then
      begin
        if not RPM(C.Rbp + 8, @Buf2, 8) then
        begin
          Log(ltFatal, 'Call stack analysis failed');
          Exit;
        end;
        FinishUnpacking(Buf2 - 5 - 4);
      end;
    end
    else
      WaitForSingleObject(GetCurrentThread, INFINITE);
  end
  else if BPA = FImageBase + $1000 then
  begin
    if not BaseAccessed then
    begin
      Log(ltGood, Format('Accessed .text base from %X', [UIntPtr(EIP)]));
      // Next, look for a write
      ResetBreakpoint(Pointer(FImageBase + $1000));
      SetBreakpoint(FImageBase + $1000, hwWrite);
      BaseAccessed := True;
    end
    else
    begin
      // Write occurred
      Log(ltGood, Format('Wrote to .text base from %X', [UIntPtr(EIP)]));
      if TMFinderCheck(@C) then
      begin
        ResetBreakpoint(Pointer(FImageBase + $1000));
        SetBreakpoint(UIntPtr(AllocMemAPI), hwExecute);   // if IAT is protected
        SetBreakpoint(UIntPtr(FFirstRealAPI), hwExecute); // if IAT is not protected
        RepEIP := C.Rip;
      end;
    end;
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
    if not VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_NOACCESS, OldProt) then
      RaiseLastOSError;
    FGuardStepping := False;
    Exit(DBG_CONTINUE);
  end;

  Result := inherited;
end;

function TTMDebugger64.OnSoftwareBreakpoint(hThread: THandle; BPA: Pointer): TSoftBPAction;
begin
  raise Exception.Create('SoftBPs are not used by TTMDebugger64');
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

function TTMDebugger64.TMFinderCheck(C: PContext): Boolean;
var
  Rep: Word;
  Tmp: NativeUInt;
begin
  RPM(C.Rip, @Rep, 2);
  if Rep = $A4F3 then
    Exit(True);

  Log(ltInfo, '[TODO] FinderCheck: ' + IntToHex(Rep, 4));
  Tmp := FImageBase + $1000 + Base1 - 4;
  Result := (C.Rax = Tmp) or (C.Rbx = Tmp) or (C.Rcx = Tmp) or (C.Rdx = Tmp) or (C.Rsi = Tmp) or (C.Rdi = Tmp);
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
  Base1 := Sect[0].Misc.VirtualSize;

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
  Log(ltInfo, Format('Image boundary: %.8X', [FImageBoundary]));

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

  //AllocMemAPI := GetProcAddress(GetModuleHandle('ntdll.dll'), 'ZwAllocateVirtualMemory');
  AllocMemAPI := GetProcAddress(GetModuleHandle('kernel32.dll'), 'VirtualAlloc');

  FFirstRealAPI := GetProcAddress(GetModuleHandle('kernel32.dll'), 'GetSystemTimeAsFileTime');
  //FFirstRealAPI := GetProcAddress(GetModuleHandle('kernel32.dll'), 'GetVersion');
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
  VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_NOACCESS, OldProt);
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

  VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_EXECUTE_READWRITE, OldProt);

  if TMSectR.Address = 0 then
    SelectThemidaSection(UIntPtr(ExcRecord.ExceptionAddress));

  if FTMGuard then
  begin
    // We've hit the Themida section after executing a TLS entypoint.
    FTMGuard := False;
    InstallCodeSectionGuard;
  end
  else if NativeUInt(ExcRecord.ExceptionAddress) > FGuardEnd then
  begin
    FGuardAddrs.Add(ExcRecord.ExceptionInformation[1]);
    // Single-step, then re-protect in OnSinglestep.
    FGuardStepping := True;
    C.ContextFlags := CONTEXT_CONTROL;
    if not GetThreadContext(hThread, C) then
      RaiseLastOSError;
    C.EFlags := C.EFlags or $100;
    SetThreadContext(hThread, C);
  end
  else if (ExcRecord.ExceptionInformation[0] = 8) and (FTLSTotal > 0) and (FTLSCounter < FTLSTotal) then
  begin
    Inc(FTLSCounter);
    Log(ltGood, Format('TLS %d: %.8X', [FTLSCounter, UIntPtr(ExcRecord.ExceptionAddress), 8]));
    FGuardStart := TMSectR.Address;
    FGuardEnd := FImageBoundary;
    FTMGuard := True;
    VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_NOACCESS, OldProt);
  end
  else if FTraceMSVCOEP then
  begin
    // We're at mainCrtStartup.
    WriteMSVCOEP(UIntPtr(ExcRecord.ExceptionAddress));
    FinishUnpacking(FMSVCOEP);
  end
  else
  begin
    OEP := NativeUInt(ExcRecord.ExceptionAddress);

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

  // Process the IAT into an import directory and dump the binary to disk.
  FN := ExtractFilePath(FExecutable) + ChangeFileExt(ExtractFileName(FExecutable), 'U' + ExtractFileExt(FExecutable));
  Dumper.IAT := IAT;
  Dumper.DumpToFile(FN, Dumper.Process());
  Dumper.Free;

  FHideThreadEnd := True;
  TerminateProcess(FProcess.hProcess, 0);

  Log(ltGood, 'Operation completed successfully.');
end;

function TTMDebugger64.DetermineIATAddress(OEP: NativeUInt; Dumper: TDumper): NativeUInt;
var
  TextBase, CodeSize: NativeUInt;
  CodeDump: PByte;
  NumInstr: Cardinal;

  function FindCallOrJmpPtr(Address: NativeUInt; IgnoreMethodBoundary: Boolean = False): NativeUInt;
  var
    Dis: TDisasm;
    Len: Integer;
  begin
    Result := 0;
    FillChar(Dis, SizeOf(Dis), 0);
    Dis.EIP := NativeUInt(CodeDump) + Address - TextBase;
    Dis.VirtualAddr := Address;
    while NumInstr < 5000 do
    begin
      Len := DisasmCheck(Dis);

      if (PWord(Dis.EIP)^ = $15FF) or (PWord(Dis.EIP)^ = $25FF) then // call dword ptr/jmp dword ptr
      begin
        Log(ltInfo, 'Found ' + IntToHex(Dis.VirtualAddr, 8) + ' : ' + string(AnsiString(Dis.CompleteInstr)));
        Exit(Dis.VirtualAddr + NativeUInt(Dis.Operand1.Memory.Displacement) + 6);
      end;

      if (PByte(Dis.EIP)^ = $E8) and not IgnoreMethodBoundary then // call
      begin
        if Dis.Instruction.AddrValue > TextBase + CodeSize then
          Exit(0);

        Result := FindCallOrJmpPtr(Dis.Instruction.AddrValue);
        if Result <> 0 then
          Exit;
      end;

      if ((PByte(Dis.EIP)^ = $C3) or (PByte(Dis.EIP)^ = $C2)) and not IgnoreMethodBoundary then // ret
        Exit(0);

      Inc(NumInstr);
      Inc(Dis.EIP, Len);
      Inc(Dis.VirtualAddr, Len);
    end;
  end;

var
  IATRef, Seeker, CurAddress, x: NativeUInt;
  IATData: array[0..(MAX_IAT_SIZE div SizeOf(Pointer))-1] of NativeUInt;
  i: Cardinal;
  WroteExitProcess: Boolean;
begin
  // For MSVC, the IAT often resides at FImageBase + FBaseOfData
  // Other compilers such as Delphi use a dedicated .idata section, but the IAT doesn't start directly at the beginning, so some guesswork is needed

  TextBase := FImageBase + FPESections[0].VirtualAddress;
  CodeSize := FBaseOfData - FPESections[0].VirtualAddress;
  Log(ltInfo, Format('Text base: %.8X, code size: %X', [TextBase, CodeSize]));
  NumInstr := 0;
  GetMem(CodeDump, CodeSize);
  try
    if not RPM(TextBase, CodeDump, CodeSize) then
      raise Exception.Create('DetermineIATAddress: RPM failed');

    // TODO if not FIsVMOEP then
    //  IATRef := FindCallOrJmpPtr(OEP)
    //else
      IATRef := FindCallOrJmpPtr(TextBase, True);

    if IATRef = 0 then
      raise Exception.Create('Unable to obtain IAT reference');

    Log(ltInfo, 'First IAT ref: ' + IntToHex(IATRef, 8));
  finally
    FreeMem(CodeDump);
  end;

  // The IATRef we obtained points somewhere into the IAT area. Now we need to figure out the start of the table.
  Seeker := IATRef - $1000;
  RPM(Seeker, @IATData, SizeOf(IATData));
  for i := 0 to High(IATData) do
  begin
    if not Dumper.IsAPIAddress(IATData[i]) then
      Inc(Seeker, SizeOf(NativeUInt))
    else
      Break; // Let's hope we didn't randomly stumble upon a valid API address somewhere before the IAT.
  end;

  // ExitProcess is often redirected to Themida VM in new versions.
  WroteExitProcess := False;
  RPM(Seeker, @IATData, SizeOf(IATData));
  for i := 0 to (Dumper.DetermineIATSize(@IATData[0]) div SizeOf(Pointer)) - 1 do
  begin
    if TMSectR.Contains(IATData[i]) then
    begin
      CurAddress := Seeker + i * SizeOf(UIntPtr);
      if WroteExitProcess then
      begin
        Log(ltFatal, Format('Encountered another Themida IAT pointer at %X', [CurAddress]));
        Continue;
      end;
      Log(ltInfo, Format('Replacing redirect [IAT]%X->[VM]%X with ExitProcess', [CurAddress, IATData[i]]));
      IATData[i] := UIntPtr(GetProcAddress(GetModuleHandle(kernel32), 'ExitProcess'));
      VirtualProtectEx(FProcess.hProcess, Pointer(CurAddress), SizeOf(UIntPtr), PAGE_READWRITE, @x);
      WriteProcessMemory(FProcess.hProcess, Pointer(CurAddress), @IATData[i], SizeOf(UIntPtr), x);
      WroteExitProcess := True;
    end;
  end;

  Result := Seeker;
end;

end.

