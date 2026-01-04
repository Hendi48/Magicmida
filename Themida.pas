unit Themida;

interface

uses Windows, SysUtils, Classes, Utils, TlHelp32, Generics.Collections, DebuggerCore, Dumper, Patcher, Tracer;

type
  TEFLRecord = record
    Address: NativeUInt;
    Original: TBytes;
  end;

  TTMDebugger = class(TDebuggerCore)
  private
    FCreateDataSections: Boolean;
    FBaseOfData: NativeUInt;
    FPESections: array of TImageSectionHeader;
    FMajorLinkerVersion: Byte;
    FWow64: LongBool;

    // Themida
    FImageBoundary: NativeUInt;
    FBaseAccessCount: Integer;
    FCompressed: Boolean;
    TMSect: PByte;
    TMSectR: TMemoryRegion;
    Base1, RepEIP, NtQIP: NativeUInt;
    CloseHandleAPI, AllocMemAPI, AllocHeapAPI, KiFastSystemCall, NtSIT, NtQIP64, VirtualProtectAPI: Pointer;
    CmpImgBase, MagicJump, MagicJumpV1: Pointer;
    BaseAccessed, NewVer, AncientVer: Boolean;
    AllocMemCounter: Integer;
    IJumper, MJ_1, MJ_2, MJ_3, MJ_4: NativeUInt;
    EFLs: array[0..2] of TEFLRecord;
    FThemidaV3, FThemidaV2BySections, FIsVMOEP: Boolean;
    FTracedAPI: NativeUInt;
    FSleepAPI, FlstrlenAPI: NativeUInt;
    FTraceStartSP: NativeUInt;
    FTraceInVM: Boolean;

    FGuardStart, FGuardEnd: NativeUInt;
    FGuardProtection: Integer;
    FGuardStepping: Boolean;
    FGuardAddrs: TList<NativeUInt>;

    FTLSAddressesOfCallbacks: Cardinal;
    FTLSCounter, FTLSTotal: Cardinal;

    function FindDynamicTM(const APattern: AnsiString; AOff: Cardinal = 0): Cardinal;
    function FindStaticTM(const APattern: AnsiString; AOff: Cardinal = 0): Cardinal;
    procedure SelectThemidaSection(EIP: NativeUInt);
    procedure TMInit(var hPE: THandle);
    function TMFinderCheck(C: PContext): Boolean;
    procedure TMIATFix(EIP: NativeUInt);
    procedure TMIATFix2;
    procedure TMIATFix3(EIP: NativeUInt);
    procedure TMIATFix4;
    procedure TMIATFix5(Eax: NativeUInt);
    procedure TMIATFixThemidaV1(BaseCompare1: NativeUInt);
    function GetIATBPAddressNew(var Res: NativeUInt): Boolean;
    function InstallEFLPatch(EIP: Pointer; var C: TContext; var Rec: TEFLRecord): Boolean;

    procedure InstallCodeSectionGuard(Protection: Cardinal);
    function IsGuardedAddress(Address: NativeUInt): Boolean;
    function ProcessGuardedAccess(hThread: THandle; const ExcRecord: TExceptionRecord): Cardinal;

    procedure RestoreStolenOEPForMSVC6(hThread: THandle; var OEP: NativeUInt);
    procedure CheckVirtualizedOEP(OEP: NativeUInt);
    function TryFindCorrectOEP(OEP: NativeUInt): NativeUInt;
    function IsTMExceptionHandler(Address: NativeUInt): Boolean;
    procedure FixupAPICallSites(IAT: NativeUInt);
    function DetermineIATAddress(OEP: NativeUInt; Dumper: TDumper): NativeUInt;
    procedure TraceImports(IAT: NativeUInt);
    function TraceIsAtAPI(Tracer: TTracer; var C: TContext): Boolean;
    procedure FinishUnpacking(OEP: NativeUInt);
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

uses BeaEngineDelphi, ShellAPI, AntiDumpFix, Math;

{ TDebugger }

constructor TTMDebugger.Create(const AExecutable, AParameters: string; ACreateData: Boolean);
begin
  FCreateDataSections := ACreateData;

  FGuardAddrs := TList<NativeUInt>.Create;

  inherited Create(AExecutable, AParameters, Utils.Log);
end;

destructor TTMDebugger.Destroy;
begin
  FGuardAddrs.Free;

  inherited;
end;

function TTMDebugger.OnAccessViolation(hThread: THandle; const ExcRec: TExceptionRecord): Cardinal;
begin
  if IsGuardedAddress(ExcRec.ExceptionInformation[1]) then
    Result := ProcessGuardedAccess(hThread, ExcRec)
  else
    Result := inherited;
end;

procedure TTMDebugger.OnDebugStart(var hPE: THandle; hThread: THandle);
begin
  CloseHandleAPI := GetProcAddress(GetModuleHandle(kernel32), 'CloseHandle');
  SetBreakpoint(Cardinal(CloseHandleAPI), hwExecute, False);

  if FileExists('InjectorCLIx86.exe') then
  begin
    Log(ltGood, 'Applying ScyllaHide');
    ShellExecute(0, 'open', 'InjectorCLIx86.exe', PChar(Format('pid:%d %s nowait', [FProcess.dwProcessId, ExtractFilePath(ParamStr(0)) + 'HookLibraryx86.dll'])), nil, SW_HIDE);
  end
  else
  begin
    NtSIT := GetProcAddress(GetModuleHandle('ntdll.dll'), 'ZwSetInformationThread');
    SetBreakpoint(Cardinal(NtSIT), hwExecute, False);
    KiFastSystemCall := GetProcAddress(GetModuleHandle('ntdll.dll'), 'KiFastSystemCall');

    if not (IsWow64Process(FProcess.hProcess, FWow64) and FWow64) then
    begin
      SetSoftBP(KiFastSystemCall);
      NtQIP := PCardinal(Cardinal(GetProcAddress(GetModuleHandle('ntdll.dll'), 'ZwQueryInformationProcess')) + 1)^;
    end
    else
    begin
      NtQIP64 := GetProcAddress(GetModuleHandle('ntdll.dll'), 'ZwQueryInformationProcess');
      SetBreakpoint(Cardinal(NtQIP64), hwExecute, False);
    end;
  end;

  VirtualProtectAPI := GetProcAddress(GetModuleHandle(kernel32), 'VirtualProtect');

  FSleepAPI := NativeUInt(GetProcAddress(GetModuleHandle(kernel32), 'Sleep'));
  FlstrlenAPI := NativeUInt(GetProcAddress(GetModuleHandle(kernel32), 'lstrlen'));

  UpdateDR(hThread);

  //FetchMemoryRegions;
  TMInit(hPE);
end;

const
  STATUS_PORT_NOT_SET = $C0000353;

procedure TTMDebugger.OnHardwareBreakpoint(hThread: THandle; BPA: NativeUInt; var C: TContext);
var
  EIP: Pointer;
  Buf, Buf2, WriteBuf, InfoClass: Cardinal;
  x: NativeUInt;
begin
  EIP := Pointer(C.Eip);

  if EIP = CloseHandleAPI then
  begin
    RPM(C.Esp, @Buf, 4);

    if Buf < FImageBoundary then
    begin
      ResetBreakpoint(EIP);
      if FCompressed then
        SetBreakpoint(FImageBase + $1000, hwAccess)
      else
        SetBreakpoint(Cardinal(AllocMemAPI));
    end;
  end
  else if EIP = AllocMemAPI then
  begin
    // NT-Layer ZwAllocateVirtualMemory <- kernelbase.VirtualAllocEx <- kernelbase.VirtualAlloc
    //                                       ^^^ not for NT 6.3
    RPM(C.Ebp, @Buf, 4);
    if Abs(Buf - C.Ebp) < $40 then
      RPM(Buf + 4, @Buf, 4)
    else
      RPM(C.Ebp + 4, @Buf, 4);
    Log(ltInfo, Format('AllocMem called from %.8X', [Buf]));

    if Buf shr 31 <> 0 then // Kernel address, can't be right
      WaitForSingleObject(Self.Handle, INFINITE);

    if Buf < FImageBoundary then
    begin
      Inc(AllocMemCounter);
      if AllocMemCounter = IfThen(FCompressed, 4, 5) then
      begin
        ResetBreakpoint(AllocMemAPI);
        if not FThemidaV3 then
        begin
          Log(ltGood, 'IAT fixing started.');
          TMIATFix(Buf);
        end
        else
          InstallCodeSectionGuard(PAGE_NOACCESS);
      end;
    end;
  end
  else if EIP = CmpImgBase then
  begin
    ResetBreakpoint(CmpImgBase);
    TMIATFix3(NativeUInt(EIP));
  end
  else if EIP = MagicJump then
  begin
    ResetBreakpoint(MagicJump);
    TMIATFix4;
  end
  else if EIP = Pointer(MJ_1) then
  begin
    ResetBreakpoint(Pointer(MJ_1));
    TMIATFix5(C.Eax);
  end
  else if EIP = MagicJumpV1 then
  begin
    ResetBreakpoint(MagicJumpV1);
    TMIATFixThemidaV1(UIntPtr(MagicJumpV1));
  end
  else if EIP = AllocHeapAPI then
  begin
    Log(ltFatal, 'Special IAT fix failed, perhaps not needed for this binary');
    ResetBreakpoint(AllocHeapAPI);
    SoftBPClear;
    InstallCodeSectionGuard(PAGE_NOACCESS);
  end
  else if EIP = VirtualProtectAPI then
  begin
    {RPM(C.Esp + 4, @Buf, 4);
    RPM(C.Esp + 8, @Buf2, 4);
    Log(ltInfo, Format('[%d] Protect: %X %X', [FCurrentThreadId, Buf, Buf2]));}
    // Ensure we break on execution in case it's still on PAGE_READONLY.
    InstallCodeSectionGuard(PAGE_NOACCESS);
  end
  else if EIP = NtSIT then
  begin
    if RPM(C.Esp, @Buf, 4) and (Buf < FImageBoundary) and RPM(C.Esp + 8, @InfoClass, 4) and (InfoClass = 17) then
    begin
      Log(ltGood, 'Ignoring NtSetInformationThread(ThreadHideFromDebugger)');
      Inc(C.Esp, 5 * 4); // 4 paramaters + ret
      C.Eip := Buf;
      C.Eax := STATUS_SUCCESS;
      C.ContextFlags := CONTEXT_CONTROL or CONTEXT_INTEGER;
      if not SetThreadContext(hThread, C) then
        Log(ltFatal, '[NtSetInformationThread] SetContextThread');
    end;
  end
  else if FWow64 and (EIP = NtQIP64) then
  begin
    if RPM(C.Esp, @Buf, 4) and RPM(C.Esp + 8, @InfoClass, 4) and ((InfoClass = 7) or (InfoClass = 30)) then
    begin
      if InfoClass = 7 then
        Log(ltGood, 'Faking ProcessDebugPort')
      else
        Log(ltGood, 'Faking ProcessDebugObjectHandle');
      RPM(C.Esp + 12, @Buf2, 4);
      WriteBuf := 0; // Debug Port/Debug Object Handle
      WriteProcessMemory(FProcess.hProcess, Pointer(Buf2), @WriteBuf, 4, x);
      Inc(C.Esp, 6 * 4); // 5 parameters + ret
      C.Eip := Buf;
      if InfoClass = 7 then
        C.Eax := STATUS_SUCCESS
      else
        C.Eax := STATUS_PORT_NOT_SET;
      C.ContextFlags := CONTEXT_CONTROL or CONTEXT_INTEGER;
      if not SetThreadContext(hThread, C) then
        Log(ltFatal, '[KiFastSystemCall] SetContextThread');
    end;
  end
  else if BPA = FImageBase + $1000 then
  begin
    Inc(FBaseAccessCount);
    Log(ltGood, Format('Accessed text base from %p', [EIP]));
    if not BaseAccessed then
    begin
      ResetBreakpoint(Pointer(FImageBase + $1000));
      SetBreakpoint(FImageBase + $1000, hwWrite);
      BaseAccessed := True;
    end
    else
    begin
      if TMFinderCheck(@C) then
      begin
        ResetBreakpoint(Pointer(FImageBase + $1000));
        SetBreakpoint(Cardinal(AllocMemAPI), hwExecute);
        RepEIP := C.Eip;
      end
      else if (FBaseAccessCount = 3) and not FThemidaV2BySections then // hackish, but seems ok so far
      begin
        FThemidaV3 := True;
        Log(ltInfo, 'Assuming Themida v3');
        SelectThemidaSection(C.Eip);
        ResetBreakpoint(Pointer(FImageBase + $1000));
        SetBreakpoint(Cardinal(AllocMemAPI), hwExecute);
      end;
    end;
  end
  else
  begin
    Log(ltInfo, Format('Accessed %x from %p', [BPA, EIP]));
  end;
end;

function TTMDebugger.OnSinglestep(BPA: NativeUInt): Cardinal;
var
  OldProt: NativeUInt;
begin
  if FGuardStepping then
  begin
    VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, FGuardProtection, OldProt);
    FGuardStepping := False;
    Exit(DBG_CONTINUE);
  end;

  Result := inherited;
end;

function TTMDebugger.OnSoftwareBreakpoint(hThread: THandle; BPA: Pointer): TSoftBPAction;
var
  x, Jumper, Res: NativeUInt;
  C: TContext;
  mK32, mU32, mA32: HMODULE;
  bs: array[0..40] of Byte;
  Buf: PByte;
  i: Integer;
  WriteBuf, InfoClass: Cardinal;
begin
  C.ContextFlags := CONTEXT_FULL;
  GetThreadContext(hThread, C);

  if not FWow64 and (BPA = KiFastSystemCall) then
  begin
    if (C.Eax = NtQIP) and RPM(C.Esp, @Res, 4) and RPM(C.Esp + 12, @InfoClass, 4) and ((InfoClass = 7) or (InfoClass = 30)) then
    begin
      if InfoClass = 7 then
        Log(ltGood, 'Faking ProcessDebugPort')
      else
        Log(ltGood, 'Faking ProcessDebugObjectHandle');
      RPM(C.Esp + 16, @x, 4);
      WriteBuf := 0; // Debug Port
      WriteProcessMemory(FProcess.hProcess, Pointer(x), @WriteBuf, 4, x);
      Inc(C.Esp, 4); // 5 paramaters + ret
      C.Eip := Res;
      if InfoClass = 7 then
        C.Eax := STATUS_SUCCESS
      else
        C.Eax := STATUS_PORT_NOT_SET;
    end
    else
    begin
      C.Edx := C.Esp;
      C.Eip := NativeUInt(KiFastSystemCall) + 2;
    end;

    if not SetThreadContext(hThread, C) then
      Log(ltFatal, '[KiFastSystemCall] SetContextThread');
    Exit(sbpKeepContinueNoStep);
  end;

  Log(ltInfo, Format('Software breakpoint at %p', [BPA]));

  // Should only be called during IAT patching
  // eax should hold a module base now

  if not NewVer then
  begin
    mK32 := GetModuleHandle(kernel32);
    mU32 := GetModuleHandle(user32);
    mA32 := GetModuleHandle(advapi32);
    if (C.Eax <> mK32) and (C.Eax <> mU32) and (C.Eax <> mA32) then
    begin
      // Rare path in certain weird binaries.
      Log(ltInfo, Format('eax: %.8X', [C.Eax]));
      if not IsHWBreakpoint(AllocHeapAPI) then
        SetBreakpoint(Cardinal(AllocHeapAPI), hwExecute);
      // Restore original byte and single step.
      Exit(sbpKeepContinue);
    end;

    Result := sbpClearContinue;
    SoftBPClear;

    Jumper := 5 + C.Eip + PCardinal(TMSect + C.Eip + 1 - TMSectR.Address)^;

    Res := Cardinal(VirtualAllocEx(FProcess.hProcess, nil, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Log(ltInfo, 'IAT patch location: ' + IntTOHex(Res, 8));

    Buf := @bs;
    PWord(Buf)^ := $F881; // cmp eax
    PCardinal(Buf + 2)^ := mK32;
    PCardinal(Buf + 6)^ := $F8811574;
    PCardinal(Buf + 10)^ := mA32;
    PCardinal(Buf + 14)^ := $F8810D74;
    PCardinal(Buf + 18)^ := mU32;
    PWord(Buf + 22)^ := $0574;
    PByte(Buf + 24)^ := $E9;
    PCardinal(Buf + 25)^ := Jumper - (Res + 24) - 5;
    PUInt64(Buf + 29)^ := $E9000002872404C7;
    PCardinal(Buf + 37)^ := Jumper - (Res + 36) - 5;
    WriteProcessMemory(FProcess.hProcess, Pointer(Res), Buf, 41, x);
    FlushInstructionCache(FProcess.hProcess, Pointer(Res), 41);

    Buf^ := $E9;
    PCardinal(Buf + 1)^ := Res - C.Eip - 5;
    WriteProcessMemory(FProcess.hProcess, Pointer(C.Eip), Buf, 5, x);
    FlushInstructionCache(FProcess.hProcess, Pointer(C.Eip), 5);

    Log(ltGood, 'Special IAT patch was successfully written!');
  end
  else // Teflon time!
  begin
    Result := sbpClearContinue;

    for i := 0 to High(EFLs) do
    begin
      if EFLs[i].Address = 0 then
      begin
        EFLs[i].Address := Cardinal(BPA);
        if InstallEFLPatch(BPA, C, EFLs[i]) then
          Exit
        else
          Break;
      end;
    end;

    SoftBPClear;
    Log(ltInfo, 'Found no base in registers!');
    Log(ltGood, 'Special >> NEW << IAT Patch was written!');
  end;

  if not AncientVer then
    InstallCodeSectionGuard(PAGE_READONLY) // Not using PAGE_NOACCESS here is a performance optimization for some targets (esp. MC1.14).
  else
    InstallCodeSectionGuard(PAGE_NOACCESS);
  Log(ltInfo, 'Please wait, call site tracing might take a while...');
end;

function DisasmCheck(var Dis: TDisasm): Integer;
begin
  Dis.Archi := 32;
  Result := Disasm(Dis);
  if (Result = UNKNOWN_OPCODE) or (Result = OUT_OF_BLOCK) then
    raise Exception.CreateFmt('Disasm result: %d (EIP = %X)', [Result, Dis.EIP]);
end;

function TTMDebugger.InstallEFLPatch(EIP: Pointer; var C: TContext; var Rec: TEFLRecord): Boolean;
var
  Bases: array[0..2] of HMODULE;
  HookDest: Pointer;
  bs: array[0..127] of Byte;
  Buf, OrigOps: PByte;
  Dis: TDisasm;
  M, FoundBase: HMODULE;
  RegComp: Word;
  TotalSize, x: NativeUInt;
begin
  Bases[0] := GetModuleHandle(kernel32);
  Bases[1] := GetModuleHandle(user32);
  Bases[2] := GetModuleHandle(advapi32);

  FillChar(Dis, SizeOf(Dis), 0);
  Dis.EIP := Cardinal(TMSect) + Cardinal(EIP) - TMSectR.Address;
  if DisasmCheck(Dis) = 5 then
    if (TMSect + (Cardinal(EIP) - TMSectR.Address))^ = $E9 then
      raise Exception.Create('efl oldstyle');

  FoundBase := 0;
  RegComp := 0;
  for M in Bases do
  begin
    if C.Eax = M then
      RegComp := $F881
    else if C.Ecx = M then
      RegComp := $F981
    else if C.Edx = M then
      RegComp := $FA81
    else if C.Ebx = M then
      RegComp := $FB81
    else if C.Ebp = M then
      RegComp := $FD81
    else if C.Esi = M then
      RegComp := $FE81
    else if C.Edi = M then
      RegComp := $FF81
    else
      Continue;

    FoundBase := M;
    Break;
  end;

  if FoundBase = 0 then
    Exit(False);

  HookDest := VirtualAllocEx(FProcess.hProcess, nil, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  Buf := @bs;
  PWord(Buf)^ := RegComp;
  PCardinal(Buf + 2)^ := Bases[0];
  PWord(Buf + 6)^ := $2874;
  PWord(Buf + 8)^ := RegComp;
  PCardinal(Buf + 10)^ := Bases[1];
  PWord(Buf + 14)^ := $2074;
  PWord(Buf + 16)^ := RegComp;
  PCardinal(Buf + 18)^ := Bases[2];
  PWord(Buf + 22)^ := $1874;
  PWord(Buf + 24)^ := $1DEB; // jmp to OrigOps
  PUInt64(Buf + $30)^ := $90000002462404C7; // mov [esp], 0x246 (EFL Patch)
  OrigOps := Buf + $37;

  TotalSize := 0;
  Dis.EIP := Cardinal(TMSect) + Cardinal(EIP) - TMSectR.Address;
  while TotalSize < 5 do
  begin
    x := DisasmCheck(Dis);
    Inc(TotalSize, x);
    Inc(Dis.EIP, x);
  end;
  // Copy original opcodes
  Move((TMSect + (Cardinal(EIP) - TMSectR.Address))^, OrigOps^, TotalSize);
  SetLength(Rec.Original, TotalSize);
  Move(OrigOps^, Rec.Original[0], TotalSize);
  // Calculate jump back
  Inc(OrigOps, TotalSize);
  OrigOps^ := $E9;
  PCardinal(OrigOps+1)^ := (Cardinal(EIP) + TotalSize) - (Cardinal(OrigOps) - Cardinal(Buf) + Cardinal(HookDest)) - 5;

  //Log(ltInfo, 'OrigOps size: ' + IntToStr(TotalSize));

  // Copy to target
  WriteProcessMemory(FProcess.hProcess, HookDest, Buf, 128, x);
  FlushInstructionCache(FProcess.hProcess, HookDest, 128);

  // Install hook
  Buf^ := $E9;
  PCardinal(Buf+1)^ := Cardinal(HookDest) - Cardinal(EIP) - 5;
  WriteProcessMemory(FProcess.hProcess, EIP, Buf, 5, x);
  FlushInstructionCache(FProcess.hProcess, EIP, 5);

  // Check if there's a jz/jnz that became invalid due to the hook and fix it
  RPM(Cardinal(EIP) - 3 - 6, @bs[0], 6);
  if (bs[0] = $0F) and ((bs[1] = $84) or (bs[1] = $85)) and (PCardinal(@bs[2])^ in [4..7]) then
  begin
    PCardinal(@bs[2])^ := (Cardinal(HookDest) + $37 + (PCardinal(@bs[2])^ - 3)) - (Cardinal(EIP) - 3 - 6) - 6;
    WriteProcessMemory(FProcess.hProcess, Pointer(Cardinal(EIP) - 3 - 4), @bs[2], 4, x);
  end;

  // SPECIAL_IAT_PATCH_OK = 1
  Log(ltGood, 'EFL Patch at ' + IntToHex(Cardinal(EIP), 8));

  Result := True;
end;

function TTMDebugger.TMFinderCheck(C: PContext): Boolean;
var
  Rep: Word;
  Tmp: NativeUInt;
begin
  RPM(C.Eip, @Rep, 2);
  if Rep = $A4F3 then
    Exit(True);

  Tmp := FImageBase + $1000 + Base1 - 4;
  Result := (C.Eax = Tmp) or (C.Ebx = Tmp) or (C.Ecx = Tmp) or (C.Edx = Tmp) or (C.Esi = Tmp) or (C.Edi = Tmp);
end;

{$POINTERMATH ON}

procedure TTMDebugger.TMInit(var hPE: THandle);
var
  Buf, BufB, Test: PByte;
  x: Cardinal;
  Sect: PImageSectionHeader;
  w: NativeUInt;
  TLSDir: TImageTLSDirectory32;
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

  if (FPESections[High(FPESections)].Misc.VirtualSize = $1000) and (FPESections[High(FPESections)].SizeOfRawData = $1000)
     and (FPESections[High(FPESections) - 1].Misc.VirtualSize = $1000) then
    FThemidaV2BySections := True;

  FBaseOfData := PImageNTHeaders(Buf).OptionalHeader.BaseOfData;
  FMajorLinkerVersion := PImageNTHeaders(Buf).OptionalHeader.MajorLinkerVersion;

  FCompressed := FPESections[0].Misc.VirtualSize <> FPESections[0].SizeOfRawData;

  Base1 := Sect[0].Misc.VirtualSize;

  // PE Header Antidump
  Test := PByte(PByte(@Sect[2].Name[1]) - BufB) + FImageBase;
  VirtualProtectEx(FProcess.hProcess, Test, 1, PAGE_READWRITE, @x);
  x := Ord('p');
  if not WriteProcessMemory(FProcess.hProcess, Test, @x, 1, w) then
    raise Exception.CreateFmt('Fixing PE header antidump failed! Code: %d', [GetLastError]);

  FImageBoundary := PImageNTHeaders(Buf)^.OptionalHeader.SizeOfImage + FImageBase;
  Log(ltInfo, Format('Image boundary: %.8X', [FImageBoundary]));

  if PImageNTHeaders(Buf).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0 then
  begin
    with PImageNTHeaders(Buf).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] do
      if RPM(FImageBase + VirtualAddress, @TLSDir, Min(Size, SizeOf(TLSDir))) then
      begin
        // NOTE: This might be an MSVC-ism, where we assume the TLS callback pointers are located right
        // after the indexes. This allows us to determine the amount of callbacks.
        TLSDist := TLSDir.AddressOfCallBacks - TLSDir.AddressOfIndex;
        if (TLSDist > 0) and (TLSDist <= 4 * 4) then // Assume at most 4 TLS entries
        begin
          FTLSTotal := TLSDist div 4;
          FTLSAddressesOfCallbacks := TLSDir.AddressOfCallBacks;
          Log(ltInfo, Format('Expecting up to %d TLS entries', [FTLSTotal]));
        end;
      end;
  end;

  FreeMem(BufB);

  AllocMemAPI := GetProcAddress(GetModuleHandle('ntdll.dll'), 'ZwAllocateVirtualMemory');
  AllocHeapAPI := GetProcAddress(GetModuleHandle('ntdll.dll'), 'RtlAllocateHeap');
end;

procedure TTMDebugger.SelectThemidaSection(EIP: NativeUInt);
const
  ANCIENT_NAME: PAnsiChar = 'Themida '; // default section name in late 2000s
var
  i: Integer;
begin
  for i := 0 to High(FPESections) do
    if (EIP >= FPESections[i].VirtualAddress + FImageBase) and (EIP < FPESections[i].VirtualAddress + FPESections[i].Misc.VirtualSize + FImageBase) then
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
      if CompareMem(@FPESections[i].Name, ANCIENT_NAME, 8) then
      begin
        AncientVer := True;
        Log(ltInfo, 'Ancient Themida detected.');
      end;
      Break;
    end;

  if TMSect = nil then
    raise Exception.Create('FATAL NO DATA');
end;

procedure TTMDebugger.TMIATFix(EIP: NativeUInt);
begin
  SelectThemidaSection(EIP);

  TMIATFix2;
end;

procedure TTMDebugger.TMIATFix2;
var
  CompareJumpsNew, CmpEax10000: Cardinal;
begin
  CompareJumpsNew := FindDynamicTM('74??8B8D????????8B093B8D????????7410');
  if CompareJumpsNew = 0 then
  begin
    // Old Themida 1.x versions
    CmpEax10000 := FindStaticTM('3D000001000F83');
    if CmpEax10000 = 0 then
    begin
      Log(ltFatal, '"cmp eax, 10000" not found');
      Exit;
    end;

    Log(ltGood, 'cmp eax, 10000 at ' + IntToHex(CmpEax10000, 8));

    MagicJumpV1 := Pointer(FindDynamicTM('3B8D????????0F84????0000', CmpEax10000));
    if MagicJumpV1 = nil then
    begin
      Log(ltFatal, 'First ImageBase compare jump not found');
      Exit;
    end;

    SetBreakpoint(UIntPtr(MagicJumpV1), hwExecute);
  end
  else
  begin
    Log(ltGood, 'ImageBase compare jumps found at: ' + IntToHex(CompareJumpsNew, 8));
    CmpImgBase := Pointer(CompareJumpsNew);
    SetBreakpoint(CompareJumpsNew, hwExecute);
  end;
end;

procedure TTMDebugger.TMIATFix3(EIP: NativeUInt);
var
  x: Cardinal;
begin
  if EIP = 0 then
    raise Exception.Create('Cannot call TMIATFix3 with EIP=0');

  x := EIP - TMSectR.Address;
  x := EIP + FindDynamic('4B0F84????0000', TMSect + x, TMSectR.Size - x);
  if x = EIP then
  begin
    Log(ltFatal, 'Magic jumps not found');
  end
  else
  begin
    Log(ltGood, 'Magic jumps detected at: ' + IntToHex(x, 8));
    MagicJump := Pointer(x);
    SetBreakpoint(x, hwExecute);
  end;
end;

function TTMDebugger.GetIATBPAddressNew(var Res: NativeUInt): Boolean;
var
  B: Byte;
  Dis: TDisasm;
begin
  repeat
    Res := FindDynamicTM('39??9C', Res);

    if Res = 0 then
      Exit(False);

    RPM(Res-1, @B, 1);
    Inc(Res);
  until B <> $66;
  Dec(Res);

  FillChar(Dis, SizeOf(Dis), 0);
  Dis.EIP := Cardinal(TMSect + (Res - TMSectR.Address));
  if DisasmCheck(Dis) <> 2 then
    Exit(False); // instruction doesn't have a size of 2

  if Res > MJ_1 then
    Exit(False); // added for 213.2

  Inc(Res, 3);
  //Log(ltInfo, IntToHex(Res, 8));
  Result := True;
end;

procedure TTMDebugger.TMIATFix4;
var
  Res, Off: NativeUInt;
  Zech, Jumper, Jumper_x2: NativeUInt;
  B1, B2, B3, B4: Byte;
  Valid: Boolean;
begin
  Res := FindStaticTM('83F8500F82');
  if Res = 0 then
    raise Exception.Create('"cmp eax, 50" not found');

  Log(ltGood, 'cmp eax, 50 detected at: ' + IntToHex(Res, 8));
  Log(ltGood, '[LCF-AT] Fixing IAT with the Fast IAT Patch Method.');

  Res := FindDynamicTM('3985????????0F84');
  if Res = 0 then
    raise Exception.Create('Not found');

  Zech := Res + 6;
  IJumper := Zech;

  Off := Res;
  Res := FindStaticTM('2BD90F84', Off);
  if Res = 0 then
    Res := FindStaticTM('29CB0F84', Off);
  if Res = 0 then
    raise Exception.Create('Both patterns not found');

  MJ_2 := Res;
  Jumper := 6 + MJ_2 + 2 + PCardinal(TMSect + MJ_2 + 4 - TMSectR.Address)^;

  Off := Res + 1;
  Res := FindStaticTM('2BD90F84', Off);
  if Res = 0 then
    Res := FindStaticTM('29CB0F84', Off);
  if Res = 0 then
    raise Exception.Create('Both patterns not found (2)');

  MJ_3 := Res;
  Jumper_x2 := 6 + MJ_3 + 2 + PCardinal(TMSect + MJ_3 + 4 - TMSectR.Address)^;
  if Jumper <> Jumper_x2 then
    raise Exception.Create('Old magic jump');

  Off := Res + 1;
  Res := FindStaticTM('2BD90F84', Off);
  if Res = 0 then
    Res := FindStaticTM('29CB0F84', Off);
  if Res = 0 then
    raise Exception.Create('Both patterns not found (3)');

  MJ_4 := Res;
  Off := MJ_2;

  while (PWord(TMSect + Off - TMSectR.Address)^ <> $840F) or (6 + Off + PCardinal(TMSect + Off + 2 - TMSectR.Address)^ <> Jumper) do
    Dec(Off);

  MJ_1 := Off;
  Log(ltInfo, 'MJ1 ' + IntToHex(MJ_1, 8));
  Log(ltInfo, 'MJ2 ' + IntToHex(MJ_2, 8));
  Log(ltInfo, 'MJ3 ' + IntToHex(MJ_3, 8));
  Log(ltInfo, 'MJ4 ' + IntToHex(MJ_4, 8));

  RPM(MJ_1 - 1, @B1, 1);
  RPM(MJ_2, @B2, 1);
  RPM(MJ_3, @B3, 1);
  RPM(MJ_4, @B4, 1);
  if ((B1 <> $4B) or (B2 <> $2B) or (B3 <> $2B) or (B4 <> $2B)) and (B2 <> $29) then
    NewVer := False
  else
    NewVer := True;

  if (FindDynamicTM('68????????E9??????FF68????????E9??????FF68????????E9??????FF') <> 0) then
    NewVer := False;
  if (FindDynamicTM('68????????68????????E9??????FF68????????68????????E9??????FF') <> 0) then
    NewVer := True;

  if not NewVer then
    Log(ltInfo, 'Older Themida version found.')
  else
    Log(ltInfo, 'Newer Themida version found.');

  // NEW_RISC = 1, WL_IS_NEW = 1

  Res := FindStaticTM('3BC89CE9');
  if Res = 0 then
  begin
    Res := TMSectR.Address;
    Valid := GetIATBPAddressNew(Res);
    while Res <> 0 do
    begin
      if Valid then
      begin
        Log(ltInfo, 'SetSoft: ' + IntToHex(Res, 8));
        SetSoftBP(Pointer(Res));
      end;

      Inc(Res, 2);
      Valid := GetIATBPAddressNew(Res);
    end;

    // SP_WAS_SET = 1, SP_NEW_USE = 1
  end
  else
  begin
    repeat
      Inc(Res, 3);
      Log(ltInfo, 'SetSoft : ' + IntToHex(Res, 8));
      SetSoftBP(Pointer(Res));
      Res := FindStaticTM('3BC89CE9', Res);
    until Res = 0;
  end;

  // Monitor code section for write accesses (tampering with API call sites, old Themida versions only)
  // The collected addresses are processed in FinishUnpacking/FixupAPICallSites
  InstallCodeSectionGuard(PAGE_READONLY); // Not using PAGE_NOACCESS here is a performance optimization for some targets (esp. MC1.14).

  SetBreakpoint(MJ_1, hwExecute);
end;

procedure TTMDebugger.TMIATFix5(Eax: NativeUInt);
var
  Buf: UInt64;
  x: NativeUInt;
begin
  Log(ltInfo, 'First API in eax: ' + IntToHex(Eax, 8));

  Buf := $E990;
  WriteProcessMemory(FProcess.hProcess, Pointer(IJumper), @Buf, 2, x);
  Buf := $909090909090;
  WriteProcessMemory(FProcess.hProcess, Pointer(MJ_1), @Buf, 6, x);
  WriteProcessMemory(FProcess.hProcess, Pointer(MJ_2+2), @Buf, 6, x);
  WriteProcessMemory(FProcess.hProcess, Pointer(MJ_3+2), @Buf, 6, x);
  WriteProcessMemory(FProcess.hProcess, Pointer(MJ_4+2), @Buf, 6, x);
  FlushInstructionCache(FProcess.hProcess, Pointer(MJ_1), 6);
  Log(ltGood, 'IAT Jumper was found & fixed at ' + IntToHex(IJumper, 8));
end;

procedure TTMDebugger.TMIATFixThemidaV1(BaseCompare1: NativeUInt);
var
  Buf: UInt64;
  BaseCompare2, BaseCompare3, x: NativeUInt;
  OldProt: Cardinal;
begin
  BaseCompare2 := FindDynamicTM('3B8D????????0F84????0000', BaseCompare1 + 12);
  if BaseCompare2 = 0 then
    raise Exception.Create('[Themida 1.x] BaseCompare2 not found');

  BaseCompare3 := FindDynamicTM('3B8D????????0F84????0000', BaseCompare2 + 12);
  if BaseCompare3 = 0 then
    raise Exception.Create('[Themida 1.x] BaseCompare3 not found');

  IJumper := FindDynamicTM('3985????????0F84');
  if IJumper = 0 then
    raise Exception.Create('[Themida 1.x] IAT jumper not found');

  Log(ltInfo, 'BC1 ' + IntToHex(BaseCompare1, 8));
  Log(ltInfo, 'BC2 ' + IntToHex(BaseCompare2, 8));
  Log(ltInfo, 'BC3 ' + IntToHex(BaseCompare3, 8));

  // This is required so Themida doesn't end the process when BaseCompare patches are in place.
  Buf := $E990;
  WriteProcessMemory(FProcess.hProcess, Pointer(IJumper+6), @Buf, 2, x);
  // These prevent IAT wrapping, which only happens for the three modules kernel32, user32 and advapi32.
  Buf := $909090909090;
  WriteProcessMemory(FProcess.hProcess, Pointer(BaseCompare1+6), @Buf, 6, x);
  WriteProcessMemory(FProcess.hProcess, Pointer(BaseCompare2+6), @Buf, 6, x);
  WriteProcessMemory(FProcess.hProcess, Pointer(BaseCompare3+6), @Buf, 6, x);

  Log(ltGood, 'IAT Jumper was found & fixed at ' + IntToHex(IJumper, 8));

  FGuardStart := FImageBase + FPESections[0].VirtualAddress;
  FGuardEnd := FImageBase + $100000;
  FGuardProtection := PAGE_NOACCESS;
  VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, FGuardProtection, OldProt);
end;

function TTMDebugger.FindDynamicTM(const APattern: AnsiString; AOff: Cardinal): Cardinal;
begin
  if AOff <> 0 then
    Dec(AOff, TMSectR.Address);

  Result := FindDynamic(APattern, TMSect + AOff, TMSectR.Size - AOff);
  if Result > 0 then
    Inc(Result, TMSectR.Address + AOff);
end;

function TTMDebugger.FindStaticTM(const APattern: AnsiString; AOff: Cardinal): Cardinal;
begin
  if AOff <> 0 then
    Dec(AOff, TMSectR.Address);

  Result := FindStatic(APattern, TMSect + AOff, TMSectR.Size - AOff);
  if Result > 0 then
    Inc(Result, TMSectR.Address + AOff);
end;

function TTMDebugger.IsTMExceptionHandler(Address: NativeUInt): Boolean;
var
  Data: array[0..63] of Byte;
  i: Integer;
begin
  // Sometimes the "return" address at OEP is just some exception handler and not a VM continuation.
  RPM(Address, @Data, 64);

  for i := 0 to High(Data) - 4 do
    if PCardinal(@Data[i])^ = $00B8838B then // mov eax, [ebx+CONTEXT._Eip]
      Exit(True);

  Result := False;
end;

procedure TTMDebugger.InstallCodeSectionGuard(Protection: Cardinal);
var
  OldProt: DWORD;
begin
  FGuardStart := FImageBase + FPESections[0].VirtualAddress;
  FGuardEnd := FImageBase + FBaseOfData;
  FGuardProtection := Protection;
  VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, FGuardProtection, OldProt);

  if not FThemidaV3 and not IsHWBreakpoint(VirtualProtectAPI) then
    SetBreakpoint(NativeUInt(VirtualProtectAPI));
end;

function TTMDebugger.IsGuardedAddress(Address: NativeUInt): Boolean;
begin
  if FGuardStart = 0 then
    Exit(False);

  Result := (Address >= FGuardStart) and (Address < FGuardEnd);
end;

function TTMDebugger.ProcessGuardedAccess(hThread: THandle; const ExcRecord: TExceptionRecord): Cardinal;
var
  OldProt, RetAddr: Cardinal;
  Args: array[0..2] of Cardinal;
  C: TContext;
  OEP: NativeUInt;
label
  OEPReached;
begin
  //Log(ltInfo, Format('[Guard] %X (%d)', [ExcRecord.ExceptionInformation[1], ExcRecord.ExceptionInformation[0]]));

  VirtualProtectEx(FProcess.hProcess, Pointer(FGuardStart), FGuardEnd - FGuardStart, PAGE_EXECUTE_READWRITE, OldProt);

  if NativeUInt(ExcRecord.ExceptionAddress) > FGuardEnd then
  begin
    FGuardAddrs.Add(ExcRecord.ExceptionInformation[1]);
    // Single-step, then re-protect in OnHardwareBreakpoint
    FGuardStepping := True;
    C.ContextFlags := CONTEXT_CONTROL;
    if not GetThreadContext(hThread, C) then
      RaiseLastOSError;
    C.EFlags := C.EFlags or $100;
    SetThreadContext(hThread, C);
  end
  else if {(ExcRecord.ExceptionInformation[0] = 8) and} (FTLSTotal > 0) and (FTLSCounter < FTLSTotal) then
  begin
    C.ContextFlags := CONTEXT_CONTROL;
    if GetThreadContext(hThread, C) then
    begin
      RPM(C.Esp, @RetAddr, 4);
      RPM(C.Esp + 4, @Args, 12);
      if TMSectR.Contains(RetAddr) and not IsTMExceptionHandler(RetAddr) and ((Args[0] and $FFF) = 0) and (Args[1] <= 3) then
      begin
        Inc(FTLSCounter);
        Log(ltGood, Format('TLS %d: %.8X (%X, %X, %X)', [FTLSCounter, UIntPtr(ExcRecord.ExceptionAddress), Args[0], Args[1], Args[2]]));
        // Skip execution, we want nothing initialized in the unpacked binary.
        C.Eip := RetAddr;
        Inc(C.Esp, 4 + 3*4);
        SetThreadContext(hThread, C);
        InstallCodeSectionGuard(FGuardProtection);
      end
      else
      begin
        Log(ltInfo, Format('This doesn''t look like TLS (ret %X; args %X, %X, %X), assuming OEP.', [RetAddr, Args[0], Args[1], Args[2]]));
        goto OEPReached;
      end;
    end
    else
    begin
      Log(ltFatal, 'GetThreadContext failed for TLS check');
      goto OEPReached;
    end;
  end
  else
  begin
OEPReached:
    OEP := NativeUInt(ExcRecord.ExceptionAddress);
    Log(ltGood, 'OEP: ' + IntToHex(OEP, 8));

    RestoreStolenOEPForMSVC6(hThread, OEP);
    CheckVirtualizedOEP(OEP);

    if not AncientVer then
    begin
      // Check if virtualized and stolen (goes straight into VM without using jmp in .text).
      C.ContextFlags := CONTEXT_CONTROL;
      if GetThreadContext(hThread, C) then
      begin
        RPM(C.Esp, @RetAddr, 4);
        if TMSectR.Contains(RetAddr) and not IsTMExceptionHandler(RetAddr) then
        begin
          Log(ltInfo, Format('OEP return address points into Themida section: %.8X', [RetAddr]));
          OEP := TryFindCorrectOEP(OEP);
        end;
      end
      else
        Log(ltFatal, 'GetThreadContext failed for further OEP check');
    end;

    FinishUnpacking(OEP);
  end;

  Result := DBG_CONTINUE;
end;

procedure TTMDebugger.FinishUnpacking(OEP: NativeUInt);
var
  IAT: NativeUInt;
  i: Integer;
  x: NativeUInt;
  FN: string;
  Dumper: TDumper;
begin
  // Remove EFL jumps from VM code
  for i := 0 to High(EFLs) do
  begin
    if EFLs[i].Address <> 0 then
    begin
      WriteProcessMemory(FProcess.hProcess, Pointer(EFLs[i].Address), @EFLs[i].Original[0], Length(EFLs[i].Original), x);
    end
    else
      Break;
  end;

  Dumper := TDumper.Create(FProcess, FImageBase, OEP);

  // Look for IAT by analyzing code near OEP
  IAT := DetermineIATAddress(OEP, Dumper);
  Log(ltGood, 'IAT: ' + IntToHex(IAT, 8));

  // Themida v3: Weak traceable import protection
  if FThemidaV3 then
  begin
    // Import addresses are protected with a simple xor+subtraction scheme. The values are different
    // for each address slot - they're held in a big table somewhere in the TM section. The entire
    // code that does these computations and stores the address is virtualized. There is no runtime
    // decision not to do this like there was before (with kernel32/advapi32/user32 bases), so we
    // can't patch it out.
    TraceImports(IAT);
  end;

  // Old Themida versions like turning API calls into relative calls/jumps - restore them to absolute references to the IAT
  // Note: In newer v2 versions, Themida still tends to write to all call sites, but the data is the same that is already there (so a no-op, but we still need to track it just in case, wasting some time during the unpacking process)
  if FGuardAddrs.Count > 0 then
    FixupAPICallSites(IAT);

  if FIsVMOEP and FThemidaV3 then
  begin
    with TAntiDumpFixer.Create(FProcess.hProcess, FImageBase) do
    begin
      RedirectOEP(OEP, IAT);
      Free;
    end;
  end;

  // Process the IAT into an import directory and dump the binary to disk
  FN := ExtractFilePath(FExecutable) + ChangeFileExt(ExtractFileName(FExecutable), 'U' + ExtractFileExt(FExecutable));
  Dumper.IAT := IAT;
  Dumper.DumpToFile(FN, Dumper.Process());
  Dumper.Free;

  FHideThreadEnd := True;
  TerminateProcess(FProcess.hProcess, 0);

  if FCreateDataSections then
    with TPatcher.Create(FN) do
      try
        ProcessMkData;
      finally
        Free;
      end;

  Log(ltGood, 'Operation completed successfully.');
end;

function TTMDebugger.DetermineIATAddress(OEP: NativeUInt; Dumper: TDumper): NativeUInt;
var
  TextBase, CodeSize, DataSize: NativeUInt;
  DataSectionIndex: Integer;
  CodeDump: PByte;
  NumInstr: Cardinal;

  function FindCallOrJmpPtr(Address: NativeUInt; IgnoreMethodBoundary: Boolean = False): NativeUInt;
  var
    Dis: TDisasm;
    Len: Integer;
    ThePointer: NativeUInt;
  begin
    Result := 0;
    FillChar(Dis, SizeOf(Dis), 0);
    Dis.EIP := NativeUInt(CodeDump) + Address - TextBase;
    Dis.VirtualAddr := Address;
    while (NumInstr < 200) or (IgnoreMethodBoundary and (Address < TextBase + CodeSize)) do
    begin
      Len := DisasmCheck(Dis);
      //Log(ltInfo, IntToHex(Dis.VirtualAddr) + ' : ' + string(AnsiString(Dis.CompleteInstr)));

      if (PWord(Dis.EIP)^ = $15FF) or (PWord(Dis.EIP)^ = $25FF) then // call dword ptr/jmp dword ptr
      begin
        // Ensure we didn't stumble upon a pointer into .text.
        if not RPM(Dis.Operand1.Memory.Displacement, @ThePointer, SizeOf(ThePointer)) or (ThePointer > TextBase + CodeSize) then
          Exit(Dis.Operand1.Memory.Displacement);
      end;

      if (PByte(Dis.EIP)^ = $E8) and not IgnoreMethodBoundary then // call
      begin
        if Dis.Instruction.AddrValue > TextBase + CodeSize then
          Exit(0); // Probably direct API call. Handled below via FGuardAddrs.

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
  IATData: array[0..2047] of NativeUInt;
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
  Log(ltInfo, Format('Text base: %.8X, code size: %X, data size: %X', [TextBase, CodeSize, DataSize]));
  NumInstr := 0;
  IATRef := 0;
  GetMem(CodeDump, CodeSize);
  try
    if not RPM(TextBase, CodeDump, CodeSize) then
      raise Exception.Create('DetermineIATAddress: RPM failed');

    if not FIsVMOEP then
      IATRef := FindCallOrJmpPtr(OEP)
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
  // Read data such that IATData[High(IATData)] is the dword at IATRef.
  RPM(IATRef - (SizeOf(IATData) - 4), @IATData, SizeOf(IATData));
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
      Log(ltInfo, Format('Ending IAT start search at %X because word is %X', [Seeker, IATData[i]]));
      Break;
    end;

    Dec(i);
    Dec(Seeker, 4);
  end;
  if i = -1 then
    raise Exception.Create('IAT too big');

  if Result = 0 then
    raise Exception.Create('IAT assertion failed');
end;

procedure TTMDebugger.FixupAPICallSites(IAT: NativeUInt);
var
  i: Integer;
  SiteAddr, Target, NumWritten: NativeUInt;
  SiteSet: TList<NativeUInt>;
  Site: array[0..5] of Byte;
  IsJmp: Boolean;
  IATData: array[0..2047] of NativeUInt;
  IATMap: TDictionary<NativeUInt, NativeUInt>;
begin
  SiteSet := TList<NativeUInt>.Create;
  IATMap := TDictionary<NativeUInt, NativeUInt>.Create;

  FGuardAddrs.Sort;
  SiteSet.Add(FGuardAddrs[0]);
  for i := 1 to FGuardAddrs.Count - 1 do
    if FGuardAddrs[i] >= SiteSet.Last + 6 then
      SiteSet.Add(FGuardAddrs[i]);

  Log(ltInfo, Format('Deduced %d call sites from %d accesses', [SiteSet.Count, FGuardAddrs.Count]));

  RPM(IAT, @IATData, SizeOf(IATData));
  for i := 0 to High(IATData) do
    IATMap.AddOrSetValue(IATData[i], IAT + Cardinal(i) * 4);

  IsJmp := False;
  Target := 0;

  for SiteAddr in SiteSet do
  begin
    RPM(SiteAddr, @Site, 6);
    if (Site[0] = $E8) or (Site[0] = $E9) then
    begin
      Target := PCardinal(@Site[1])^ + SiteAddr + 5;
      IsJmp := Site[0] = $E9;
    end
    else if (Site[1] = $E8) or (Site[1] = $E9) then
    begin
      Target := PCardinal(@Site[2])^ + SiteAddr + 6;
      IsJmp := Site[1] = $E9;
    end
    else
    begin
      if (Site[0] <> $FF) or not (Site[1] in [$15, $25]) then
        Log(ltFatal, Format('Unknown call site at %X: %02X %02X %02X %02X %02X %02X', [SiteAddr, Site[0], Site[1], Site[2], Site[3], Site[4], Site[5]]));
      Continue;
    end;

    if not IATMap.ContainsKey(Target) then
    begin
      Log(ltFatal, Format('Not in IAT: %X (from %X)', [Target, SiteAddr]));
      Continue;
    end;

    // Turn the relative call/jmp into call/jmp dword ptr [iat]
    Site[0] := $FF;
    Site[1] := $15 + Ord(IsJmp) * $10;
    PCardinal(@Site[2])^ := IATMap[Target];
    WriteProcessMemory(FProcess.hProcess, Pointer(SiteAddr), @Site, 6, NumWritten)
  end;

  IATMap.Free;
  SiteSet.Free;
end;

procedure TTMDebugger.RestoreStolenOEPForMSVC6(hThread: THandle; var OEP: NativeUInt);
const
  RESTORE_DATA: array[0..45] of Byte = (
    $55, $8B, $EC, $6A, $FF,
    $68, 0, 0, 0, 0, // stru
    $68, 0, 0, 0, 0, // except handler
    $64, $A1, $00, $00, $00, $00, $50, $64, $89, $25, $00, $00, $00, $00,
    $83, $EC, $58,
    $53, $56, $57,
    $89, $65, $E8,
    $FF, $15, 0, 0, 0, 0, // call ds:GetVersion
    $33, $D2
  );
var
  C: TContext;
  CheckBuf: array[0..2] of Byte;
  IAT: NativeUInt;
  IATData: array[0..511] of NativeUInt;
  RestoreBuf: array[0..High(RESTORE_DATA)] of Byte;
  StackData: array[0..1] of NativeUInt;
  NumWritten: NativeUInt;
  i: Cardinal;
  GetVerAddr: NativeUInt;
begin
  RPM(OEP, @CheckBuf, 2);

  // mov dl, ah
  if (CheckBuf[0] <> $8A) or (CheckBuf[1] <> $D4) then
    Exit; // not MSVC6 or not stolen

  Log(ltInfo, 'Stolen MSVC6 OEP detected.');

  RPM(OEP - Cardinal(Length(RESTORE_DATA)) - 3, @CheckBuf, 3);
  if (CheckBuf[0] <> $C2) and (CheckBuf[2] <> $C3) then
  begin
    Log(ltFatal, 'Stolen OEP gap mismatch.');
    Exit;
  end;

  Move(RESTORE_DATA, RestoreBuf, Length(RestoreBuf));
  Dec(OEP, Length(RestoreBuf));

  GetVerAddr := NativeUInt(GetProcAddress(GetModuleHandle(kernel32), 'GetVersion'));

  IAT := FImageBase + FBaseOfData;

  RPM(IAT, @IATData, SizeOf(IATData));
  for i := 0 to High(IATData) do
    if IATData[i] = GetVerAddr then
    begin
      PCardinal(@RestoreBuf[Length(RestoreBuf) - 6])^ := IAT + i * 4;
      Break;
    end;

  if PCardinal(@RestoreBuf[Length(RestoreBuf) - 6])^ = 0 then
  begin
    Log(ltFatal, 'Unable to find GetVersion in IAT.');
    Exit;
  end;

  C.ContextFlags := CONTEXT_INTEGER or CONTEXT_CONTROL;
  if not GetThreadContext(hThread, C) then
    RaiseLastOSError;

  if C.Esp <> C.Ebp - $74 then
  begin
    Log(ltFatal, Format('Stack frame mismatch: esp=%x, ebp=%x', [C.Esp, C.Ebp]));
    Exit;
  end;

  RPM(C.Ebp - 3 * SizeOf(NativeUInt), @StackData, SizeOf(StackData));

  PCardinal(@RestoreBuf[6])^ := StackData[1];
  PCardinal(@RestoreBuf[11])^ := StackData[0];

  WriteProcessMemory(FProcess.hProcess, Pointer(OEP), @RestoreBuf, Length(RestoreBuf), NumWritten);

  Log(ltGood, 'Correct OEP: ' + IntToHex(OEP, 8));
end;

procedure TTMDebugger.CheckVirtualizedOEP(OEP: NativeUInt);
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

function TTMDebugger.TryFindCorrectOEP(OEP: NativeUInt): NativeUInt;
var
  TextBuf: PByte;
  TextLen: Integer;
  i: Cardinal;
  ScanFor: Cardinal;
begin
  Result := OEP;
  if not (FMajorLinkerVersion in [9, 10, 11, 12, 14]) then
  begin
    Log(ltFatal, 'Don''t know what to do about OEP for this compiler. Your target likely won''t run.');
    Exit;
  end;

  // MSVC: Assume current (wrong) OEP is at __security_init_cookie.
  // Scan for call __security_init_cookie; jmp __scrt_common_main_seh
  TextLen := FBaseOfData - FPESections[0].VirtualAddress;
  GetMem(TextBuf, TextLen);
  try
    RPM(FImageBase + FPESections[0].VirtualAddress, TextBuf, TextLen);

    ScanFor := OEP - FImageBase - FPESections[0].VirtualAddress;
    for i := 0 to TextLen - 10 do
      if (TextBuf[i] = $E8) and (TextBuf[i + 5] = $E9) and (PCardinal(@TextBuf[i + 1])^ + i + 5 = ScanFor) then
      begin
        OEP := FImageBase + FPESections[0].VirtualAddress + i;
        Log(ltGood, Format('Found likely real OEP %.8X', [OEP]));
        Exit(OEP);
      end;

    Log(ltFatal, 'Real OEP not found. Your target likely won''t run.');
  finally
    FreeMem(TextBuf);
  end;
end;

procedure TTMDebugger.TraceImports(IAT: NativeUInt);
var
  IATData: array[0..(MAX_IAT_SIZE div 4) - 1] of NativeUInt;
  i, OldProtect: Cardinal;
  NumWritten: NativeUInt;
  DidSetExitProcess: Boolean;
  Ctx: TContext;
begin
  RPM(IAT, @IATData, SizeOf(IATData));

  DidSetExitProcess := False;
  for i := 0 to High(IATData) do
  begin
    if TMSectR.Contains(IATData[i]) then
    begin
      Log(ltInfo, Format('Trace: %.8X [%.8X]', [IATData[i], IAT + i * SizeOf(Pointer)]));

      Ctx.ContextFlags := CONTEXT_CONTROL;
      GetThreadContext(Threads[FCurrentThreadID], Ctx);
      FTraceStartSP := Ctx.Esp;

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
    end;
  end;

  VirtualProtectEx(FProcess.hProcess, Pointer(IAT), SizeOf(IATData), PAGE_READWRITE, OldProtect);
  if not WriteProcessMemory(FProcess.hProcess, Pointer(IAT), @IATData, SizeOf(IATData), NumWritten) then
    RaiseLastOSError;
end;

function TTMDebugger.TraceIsAtAPI(Tracer: TTracer; var C: TContext): Boolean;
var
  ReturnAddr, InsnData: Cardinal;
begin
  if (Tracer.Counter > 100) and (Tracer.Counter < 5000) then
  begin
    RPM(C.Eip, @InsnData, 4);
    if InsnData = $4CB10FF0 then // First 4 bytes of "lock cmpxchg [ebp+ebx+0], ecx"
    begin
      FTraceInVM := True;
      Log(ltInfo, 'Trace ran into Themida VM, stopping');
      Exit(True); // Stop
    end;
  end;

  // cat & mouse game with fake calls
  if (C.Esp < FTraceStartSP) and ((C.Eip = FSleepAPI) or (C.Eip = FlstrlenAPI)) then
  begin
    // It'd be better to just execute them, but the tracer currently faults at far jumps for wow64 syscalls.
    Log(ltInfo, Format('Skipping anti-trace API at %.8x', [C.Eip]));
    RPM(C.Esp, @ReturnAddr, 4);
    Inc(C.Esp, 8);
    C.Eip := ReturnAddr;
  end;

  Result := not TMSectR.Contains(C.Eip);
  if Result and (C.Esp < FTraceStartSP) then
  begin
    Log(ltInfo, Format('Warning: Might have encountered new fake API at %.8x', [C.Eip]));
    Result := False;
  end;

  if Result then
    FTracedAPI := C.Eip;
end;

end.

