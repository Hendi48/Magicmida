unit DebuggerCore;

interface

uses
  Windows, Classes, SysUtils, Generics.Collections, Utils;

type
  THWBPType = (hwExecute, hwWrite, hwReserved, hwAccess);

  TBreakpoint = record
    Address: NativeUInt;
    BType: THWBPType;
    Disabled: Boolean;

    procedure Change(AAddress: NativeUInt; AType: THWBPType);
    function IsSet: Boolean;
  end;

  TSoftBPAction = (sbpKeepContinue, sbpClearContinue, sbpKeepContinueNoStep);

  TDebuggerCore = class abstract(TThread)
  private
    FAttachPID: Cardinal;
    FHW1, FHW2, FHW3, FHW4: TBreakpoint;
    FThreads: TDictionary<Cardinal, THandle>;
    FSoftBPs: TDictionary<Pointer, Byte>;
    FSoftBPReenable: NativeUInt;

    function PEExecute: Boolean;

    function GetThread(ThreadID: Cardinal): THandle;

    function OnCreateThreadDebugEvent(var DebugEv: TDebugEvent): DWORD;
    function OnCreateProcessDebugEvent(var DebugEv: TDebugEvent): DWORD;
    function OnExitThreadDebugEvent(var DebugEv: TDebugEvent): DWORD;
    function OnLoadDllDebugEvent(var DebugEv: TDebugEvent): DWORD;
    function OnExitProcessDebugEvent(var DebugEv: TDebugEvent): DWORD;
    function OnUnloadDllDebugEvent(var DebugEv: TDebugEvent): DWORD;
    function OnOutputDebugStringEvent(var DebugEv: TDebugEvent): DWORD;
    function OnRipEvent(var DebugEv: TDebugEvent): DWORD;
    function OnHardwareBreakpoint(var DebugEv: TDebugEvent): DWORD; overload;
    function OnSoftwareBreakpoint(var DebugEv: TDebugEvent): DWORD; overload;

    function WriteByte(Address: Pointer; Value: Byte): Boolean;
  protected
    procedure Execute; override;
  protected
    Log: TLogProc;
    FExecutable, FParameters: string;
    FProcess: TProcessInformation;
    FCurrentThreadID: Cardinal;
    FImageBase: NativeUInt;
    FMemRegions: array of TMemoryRegion;
    FHideThreadEnd: Boolean;

    procedure FetchMemoryRegions;
    function RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;

    procedure SetBreakpoint(Address: NativeUInt; BType: THWBPType = hwExecute; RefreshContexts: Boolean = True);
    function DisableBreakpoint(Address: Pointer): Boolean;
    procedure EnableBreakpoints;
    procedure ResetBreakpoint(Address: Pointer);
    function IsHWBreakpoint(Address: Pointer): Boolean;
    procedure ApplyDebugRegisters(var C: TContext);
    procedure UpdateDR(hThread: THandle);

    procedure SetSoftBP(Address: Pointer);
    procedure SoftBPClear;
  protected
    procedure OnDebugStart(var hPE: THandle; hThread: THandle); virtual; abstract;
    function OnAccessViolation(hThread: THandle; const ExcRec: TExceptionRecord): Cardinal; virtual;
    procedure OnHardwareBreakpoint(hThread: THandle; BPA: NativeUInt; var C: TContext); overload; virtual; abstract;
    function OnSoftwareBreakpoint(hThread: THandle; BPA: Pointer): TSoftBPAction; overload; virtual; abstract;
    procedure OnUnsolicitedSoftwareBreakpoint(hThread: THandle; BPA: Pointer); virtual;
    function OnSinglestep(BPA: NativeUInt): Cardinal; virtual;
  public
    constructor Create(const AExecutable, AParameters: string; ALog: TLogProc); overload;
    constructor Create(APID: Cardinal; ALog: TLogProc); overload;
    destructor Destroy; override;

    procedure Detach;

    property Threads[ThreadID: Cardinal]: THandle read GetThread;
  end;

implementation

{ TDebugger }

constructor TDebuggerCore.Create(const AExecutable, AParameters: string; ALog: TLogProc);
begin
  FExecutable := AExecutable;
  FParameters := AParameters;
  Log := ALog;

  FThreads := TDictionary<Cardinal, THandle>.Create(32);
  FSoftBPs := TDictionary<Pointer, Byte>.Create;

  inherited Create(False);
end;

constructor TDebuggerCore.Create(APID: Cardinal; ALog: TLogProc);
begin
  FAttachPID := APID;
  Log := ALog;

  FThreads := TDictionary<Cardinal, THandle>.Create(32);
  FSoftBPs := TDictionary<Pointer, Byte>.Create;

  inherited Create(False);
end;

destructor TDebuggerCore.Destroy;
begin
  FThreads.Free;
  FSoftBPs.Free;

  inherited;
end;

procedure TDebuggerCore.Detach;
var
  hThread: THandle;
begin
  for hThread in FThreads.Values do
    SuspendThread(hThread);

  if DebugActiveProcessStop(FProcess.dwProcessId) then
    Log(ltInfo, 'Detached.')
  else
    Log(ltFatal, 'Detaching failed.');
end;

function TDebuggerCore.GetThread(ThreadID: Cardinal): THandle;
begin
  if not FThreads.TryGetValue(ThreadID, Result) then
    raise Exception.CreateFmt('Thread %d not found', [ThreadID]);
end;

procedure TDebuggerCore.Execute;
var
  Ev: TDebugEvent;
  Status: Cardinal;
begin
  if not PEExecute then
  begin
    try
      RaiseLastOSError;
    except
      Log(ltFatal, 'Creating the process failed: ' + ExceptObject.ToString);
    end;
    Exit;
  end;

  try
    Status := DBG_CONTINUE;
    while True do
    begin
      if not WaitForDebugEvent(Ev, INFINITE) then
      begin
        try
          RaiseLastOSError;
        except
          Log(ltFatal, 'OS Error: ' + ExceptObject.ToString);
        end;
        Exit;
      end;
      //Writeln(Ev.dwDebugEventCode);

      FCurrentThreadID := Ev.dwThreadId;

      case Ev.dwDebugEventCode of
        EXCEPTION_DEBUG_EVENT:
        begin
          Status := DBG_EXCEPTION_NOT_HANDLED;
          case Ev.Exception.ExceptionRecord.ExceptionCode of
             EXCEPTION_ACCESS_VIOLATION: Status := OnAccessViolation(FThreads[Ev.dwThreadId], Ev.Exception.ExceptionRecord);

             EXCEPTION_BREAKPOINT:
             begin
               if FSoftBPs.ContainsKey(Ev.Exception.ExceptionRecord.ExceptionAddress) then
                 Status := OnSoftwareBreakpoint(Ev)
               else
                 OnUnsolicitedSoftwareBreakpoint(FThreads[Ev.dwThreadId], Ev.Exception.ExceptionRecord.ExceptionAddress);
             end;

             EXCEPTION_DATATYPE_MISALIGNMENT: ;
               // First chance: Pass this on to the system.
               // Last chance: Display an appropriate error.

             EXCEPTION_SINGLE_STEP:
               Status := OnHardwareBreakpoint(Ev);

             DBG_CONTROL_C: ;
               // First chance: Pass this on to the system.
               // Last chance: Display an appropriate error.

             else // Handle other exceptions.
             begin
               if Ev.Exception.dwFirstChance = 0 then
               begin
                 Log(ltFatal, 'dwFirstChance = 0');
                 Exit;
               end;
               Log(ltInfo, Format('Code 0x%.8X at 0x%p', [Ev.Exception.ExceptionRecord.ExceptionCode, Ev.Exception.ExceptionRecord.ExceptionAddress]));
               Status := DBG_EXCEPTION_NOT_HANDLED;
             end;
          end;
        end;

        CREATE_THREAD_DEBUG_EVENT:
         // As needed, examine or change the thread's registers
         // with the GetThreadContext and SetThreadContext functions;
         // and suspend and resume thread execution with the
         // SuspendThread and ResumeThread functions.
          Status := OnCreateThreadDebugEvent(Ev);

        CREATE_PROCESS_DEBUG_EVENT:
         // As needed, examine or change the registers of the
         // process's initial thread with the GetThreadContext and
         // SetThreadContext functions; read from and write to the
         // process's virtual memory with the ReadProcessMemory and
         // WriteProcessMemory functions; and suspend and resume
         // thread execution with the SuspendThread and ResumeThread
         // functions. Be sure to close the handle to the process image
         // file with CloseHandle.
          Status := OnCreateProcessDebugEvent(Ev);

        EXIT_THREAD_DEBUG_EVENT:
         // Display the thread's exit code.
          Status := OnExitThreadDebugEvent(Ev);

        EXIT_PROCESS_DEBUG_EVENT:
        begin
          Status := OnExitProcessDebugEvent(Ev);
          ContinueDebugEvent(Ev.dwProcessId, Ev.dwThreadId, Status);
          Break;
        end;

        LOAD_DLL_DEBUG_EVENT:
         // Read the debugging information included in the newly
         // loaded DLL. Be sure to close the handle to the loaded DLL
         // with CloseHandle.
          Status := OnLoadDllDebugEvent(Ev);

        UNLOAD_DLL_DEBUG_EVENT:
         // Display a message that the DLL has been unloaded.
          Status := OnUnloadDllDebugEvent(Ev);

        OUTPUT_DEBUG_STRING_EVENT:
         // Display the output debugging string.
          Status := OnOutputDebugStringEvent(Ev);

        RIP_EVENT:
          Status := OnRipEvent(Ev);
      end;

      // Resume executing the thread that reported the debugging event.
      ContinueDebugEvent(Ev.dwProcessId, Ev.dwThreadId, Status);
    end;
    //Log(ltInfo, 'Debug session concluded.');
  except
    Log(ltFatal, 'Critical error in debug loop: ' + ExceptObject.ToString);
  end;
end;

function TDebuggerCore.OnCreateThreadDebugEvent(var DebugEv: TDebugEvent): DWORD;
begin
  Log(ltInfo, Format('[%.4d] Thread started (%p).', [DebugEv.dwThreadId, {$IFDEF FPC}{$IFNDEF VER3_2}@{$ENDIF}{$ENDIF}DebugEv.CreateThread.lpStartAddress]));

  FThreads.Add(DebugEv.dwThreadId, DebugEv.CreateThread.hThread);
  UpdateDR(DebugEv.CreateThread.hThread);

  Result := DBG_CONTINUE;
end;

function TDebuggerCore.OnAccessViolation(hThread: THandle; const ExcRec: TExceptionRecord): Cardinal;
begin
  Log(ltInfo, Format('[%d] Access violation at 0x%p: %s of 0x%p', [FCurrentThreadID, ExcRec.ExceptionAddress, AccessViolationFlagToStr(ExcRec.ExceptionInformation[0]), Pointer(ExcRec.ExceptionInformation[1])]));
  Result := DBG_EXCEPTION_NOT_HANDLED;
end;

function TDebuggerCore.OnCreateProcessDebugEvent(var DebugEv: TDebugEvent): DWORD;
const
  OFFSET_IMAGEBASE = {$IFDEF CPUX86} 8 {$ELSE} 16 {$ENDIF};
  OFFSET_SHIMDATA = {$IFDEF CPUX86} $1E8 {$ELSE} $2D8 {$ENDIF};
var
  pbi: TProcessBasicInformation;
  Buf: Cardinal;
  x: NativeUInt;
begin
  Log(ltInfo, Format('Launch Debug Session (PID: %d, TID: %d)', [DebugEv.dwProcessId, DebugEv.dwThreadId]));

  FProcess.hProcess := DebugEv.CreateProcessInfo.hProcess;

  NtQueryInformationProcess(FProcess.hProcess, 0, @pbi, SizeOf(pbi), nil);
  Log(ltInfo, Format('PEB: %.8X', [UIntPtr(pbi.PebBaseAddress)]));

  Buf := 0;
  if ReadProcessMemory(FProcess.hProcess, PByte(pbi.PebBaseAddress) + 2, @Buf, 1, x) then
  begin
    if Buf = 1 then
    begin
      Log(ltGood, 'Patching PEB.BeingDebugged');
      Buf := 0;
      WriteProcessMemory(FProcess.hProcess, PByte(pbi.PebBaseAddress) + 2, @Buf, 1, x);
    end;
  end
  else
    Log(ltFatal, 'Reading PEB failed');

  if ReadProcessMemory(FProcess.hProcess, PByte(pbi.PebBaseAddress) + OFFSET_IMAGEBASE, @FImageBase, SizeOf(FImageBase), x) then
  begin
    Log(ltInfo, 'Process Image Base: ' + IntToHex(FImageBase, 8));
  end;

  if ReadProcessMemory(FProcess.hProcess, PByte(pbi.PebBaseAddress) + OFFSET_SHIMDATA, @Buf, 4, x) and (Buf <> 0) then
  begin
    Buf := 0;
    if WriteProcessMemory(FProcess.hProcess, PByte(pbi.PebBaseAddress) + OFFSET_SHIMDATA, @Buf, 4, x) then
      Log(ltInfo, 'Cleared PEB.pShimData to prevent apphelp hooks');
  end;

  FThreads.Add(DebugEv.dwThreadId, DebugEv.CreateProcessInfo.hThread);

  //FetchMemoryRegions;

  OnDebugStart(DebugEv.CreateProcessInfo.hFile, DebugEv.CreateProcessInfo.hThread);

  Result := DBG_CONTINUE;

  CloseHandle(DebugEv.CreateProcessInfo.hFile);
  //CloseHandle(DebugEv.CreateProcessInfo.hProcess);
  //CloseHandle(DebugEv.CreateProcessInfo.hThread);
end;

function TDebuggerCore.OnExitThreadDebugEvent(var DebugEv: TDebugEvent): DWORD;
begin
  if not FHideThreadEnd then
    Log(ltInfo, Format('[%.4d] Thread ended (code %d).', [DebugEv.dwThreadId, DebugEv.ExitThread.dwExitCode]));
  FThreads.Remove(DebugEv.dwThreadId);
  Result := DBG_CONTINUE;
end;

function TDebuggerCore.OnHardwareBreakpoint(var DebugEv: TDebugEvent): DWORD;
var
  EIP: Pointer;
  hThread: THandle;
  C: TContext;
  BP: TBreakpoint;
  CC: Byte;
  x: NativeUInt;
begin
  EIP := DebugEv.Exception.ExceptionRecord.ExceptionAddress;

  hThread := FThreads[DebugEv.dwThreadId];
  C.ContextFlags := CONTEXT_CONTROL or CONTEXT_INTEGER or CONTEXT_DEBUG_REGISTERS;
  if not GetThreadContext(hThread, C) then
    Log(ltFatal, 'GetThreadContext failed');

  if (((C.Dr6 shr 14) and 1) = 0) and (FHW1.IsSet or FHW2.IsSet or FHW3.IsSet or FHW4.IsSet) then // Bit 14: Single-step execution mode
  begin
    case C.Dr6 and $F of
      1: BP := FHW1;
      2: BP := FHW2;
      4: BP := FHW3;
      8: BP := FHW4;
      else
      begin
        Log(ltFatal, Format('Unknown hwbp at %p (Dr6: %.8X)', [EIP, C.Dr6]));
        Exit(DBG_EXCEPTION_NOT_HANDLED);
      end;
    end;

    OnHardwareBreakpoint(hThread, BP.Address, C);

    // Disable and step over.
    if (BP.BType = hwExecute) and DisableBreakpoint(EIP) then
    begin
      UpdateDR(hThread);
      C.ContextFlags := CONTEXT_CONTROL;
      C.EFlags := C.EFlags or $100;
      if not SetThreadContext(hThread, C) then
        Log(ltFatal, 'SetThreadContext failed');
    end;

    Result := DBG_CONTINUE;
  end
  else if FSoftBPReenable <> 0 then
  begin
    // Re-enable soft bp after stepping over it.
    CC := $CC;
    WriteProcessMemory(FProcess.hProcess, Pointer(FSoftBPReenable), @CC, 1, x);
    FSoftBPReenable := 0;
    Result := DBG_CONTINUE;
  end
  else
    Result := OnSinglestep(NativeUInt(EIP));
end;

function TDebuggerCore.OnSinglestep(BPA: NativeUInt): Cardinal;
begin
  // we stepped over a HWBP and may enable it again
  EnableBreakpoints;
  Result := DBG_CONTINUE;
end;

function TDebuggerCore.OnLoadDllDebugEvent(var DebugEv: TDebugEvent): DWORD;
var
  lpImageName: Pointer;
  szBuffer: array[0..MAX_PATH] of WideChar;
  x: NativeUInt;
  DLL: UnicodeString;
begin
  if (not ReadProcessMemory(FProcess.hProcess, DebugEv.LoadDll.lpImageName, @lpImageName, Sizeof(Pointer), x) or
      not ReadProcessMemory(FProcess.hProcess, lpImageName, @szBuffer, sizeof(szBuffer), x)) then
    DLL := '?'
  else
    DLL := UnicodeString(szBuffer);
  Log(ltInfo, Format('[%.8X] Loaded %s', [UIntPtr(DebugEv.LoadDll.lpBaseOfDll), DLL]));
  if Pos('aclayers.dll', LowerCase(DLL)) > 0 then
    raise Exception.Create('[FATAL] Compatibility mode screws up the unpacking process.');
  Result := DBG_CONTINUE;
  CloseHandle(DebugEv.LoadDll.hFile);
end;

function TDebuggerCore.OnExitProcessDebugEvent(var DebugEv: TDebugEvent): DWORD;
begin
  Log(ltInfo, Format('Process ended (code %d).', [DebugEv.ExitProcess.dwExitCode]));
  Result := DBG_CONTINUE;
end;

function TDebuggerCore.OnUnloadDllDebugEvent(var DebugEv: TDebugEvent): DWORD;
begin
  Result := DBG_CONTINUE;
end;

procedure TDebuggerCore.OnUnsolicitedSoftwareBreakpoint(hThread: THandle; BPA: Pointer);
begin
  Log(ltInfo, 'Unsolicited int3');
end;

function TDebuggerCore.OnOutputDebugStringEvent(var DebugEv: TDebugEvent): DWORD;
var
  Buf: array[0..255] of Char;
begin
  //if DebugEv.DebugString.nDebugStringLength > 0 then
  //Log(ltInfo, Format('fUnicode: %d, nLength: %d', [DebugEv.DebugString.fUnicode, DebugEv.DebugString.nDebugStringLength]));
  if (DebugEv.DebugString.nDebugStringLength > 0) and (DebugEv.DebugString.nDebugStringLength < 256) then
  begin
    if RPM(Cardinal(DebugEv.DebugString.lpDebugStringData), @Buf, DebugEv.DebugString.nDebugStringLength) then
    begin
      Buf[DebugEv.DebugString.nDebugStringLength] := #0;
      Log(ltInfo, '[Debug Str] ' + Buf);
    end;
  end;
  Result := DBG_CONTINUE;
end;

function TDebuggerCore.OnRipEvent(var DebugEv: TDebugEvent): DWORD;
begin
  Log(ltFatal, 'SYSTEM ERROR');
  Result := DBG_CONTINUE;
end;

function TDebuggerCore.PEExecute: Boolean;
var
  SI: TStartupInfo;
  PI: TProcessInformation;
  Flags: DWORD;
  CmdLine, CurrentDir: string;
begin
  if FAttachPID <> 0 then
  begin
    Exit(DebugActiveProcess(FAttachPID));
  end;

  CurrentDir := ExtractFilePath(FExecutable);
  if AnsiLastChar(CurrentDir) = '\' then
    Delete(CurrentDir, Length(CurrentDir), 1);

  FillChar(SI, SizeOf(SI), 0);
  with SI do
  begin
    cb := SizeOf(SI);
    dwFlags := STARTF_USESHOWWINDOW;
    wShowWindow := SW_SHOW;
  end;

  FillChar(PI, SizeOf(PI), 0);
  CmdLine := Format('"%s" %s', [FExecutable, TrimRight(FParameters)]);

  Flags := CREATE_DEFAULT_ERROR_MODE or CREATE_NEW_CONSOLE or NORMAL_PRIORITY_CLASS or 1 or 2;

  Result := CreateProcess(nil, PChar(CmdLine), nil, nil, False, Flags, nil, PChar(CurrentDir), SI, PI);
  FProcess := PI;
end;

procedure TDebuggerCore.FetchMemoryRegions;
var
  Address: NativeUInt;
  mbi: TMemoryBasicInformation;
begin
  Address := 0;
  mbi.RegionSize := $1000;

  while (VirtualQueryEx(FProcess.hProcess, Pointer(Address), mbi, SizeOf(mbi)) <> 0) and (Address + mbi.RegionSize > Address) do
  begin
    SetLength(FMemRegions, Length(FMemRegions) + 1);
    FMemRegions[High(FMemRegions)].Address := NativeUInt(mbi.BaseAddress);
    FMemRegions[High(FMemRegions)].Size := mbi.RegionSize;

    Inc(Address, mbi.RegionSize);
  end;
end;

function TDebuggerCore.IsHWBreakpoint(Address: Pointer): Boolean;
begin
  Result := (Pointer(FHW1.Address) = Address) or (Pointer(FHW2.Address) = Address) or
            (Pointer(FHW3.Address) = Address) or (Pointer(FHW4.Address) = Address);
end;

procedure TDebuggerCore.SetBreakpoint(Address: NativeUInt; BType: THWBPType; RefreshContexts: Boolean);
var
  T: THandle;
begin
  if FHW1.Address = 0 then
    FHW1.Change(Address, BType)
  else if FHW2.Address = 0 then
    FHW2.Change(Address, BType)
  else if FHW3.Address = 0 then
    FHW3.Change(Address, BType)
  else if FHW4.Address = 0 then
    FHW4.Change(Address, BType)
  else
    raise Exception.Create('All breakpoints in use');

  if RefreshContexts then
    for T in FThreads.Values do
      UpdateDR(T);
end;

function TDebuggerCore.DisableBreakpoint(Address: Pointer): Boolean;
begin
  Result := True;

  if Pointer(FHW1.Address) = Address then
    FHW1.Disabled := True
  else if Pointer(FHW2.Address) = Address then
    FHW2.Disabled := True
  else if Pointer(FHW3.Address) = Address then
    FHW3.Disabled := True
  else if Pointer(FHW4.Address) = Address then
    FHW4.Disabled := True
  else
    Result := False;
end;

procedure TDebuggerCore.EnableBreakpoints;
var
  T: THandle;
begin
  if FHW1.Disabled or FHW2.Disabled or FHW3.Disabled or FHW4.Disabled then
  begin
    FHW1.Disabled := False;
    FHW2.Disabled := False;
    FHW3.Disabled := False;
    FHW4.Disabled := False;

    for T in FThreads.Values do
      UpdateDR(T);
  end;
end;

procedure TDebuggerCore.ResetBreakpoint(Address: Pointer);
var
  T: THandle;
begin
  if Pointer(FHW1.Address) = Address then
    FHW1.Address := 0
  else if Pointer(FHW2.Address) = Address then
    FHW2.Address := 0
  else if Pointer(FHW3.Address) = Address then
    FHW3.Address := 0
  else if Pointer(FHW4.Address) = Address then
    FHW4.Address := 0;

  for T in FThreads.Values do
    UpdateDR(T);
end;

function TDebuggerCore.RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
begin
  Result := ReadProcessMemory(FProcess.hProcess, Pointer(Address), Buf, BufSize, BufSize);
end;

procedure TDebuggerCore.ApplyDebugRegisters(var C: TContext);
var
  Mask: Cardinal;
begin
  Mask := 0;

  C.Dr0 := FHW1.Address;
  if FHW1.IsSet then
  begin
    Mask := 1;
  end;

  C.Dr1 := FHW2.Address;
  if FHW2.IsSet then
  begin
    Mask := Mask or (1 shl 2);
  end;

  C.Dr2 := FHW3.Address;
  if FHW3.IsSet then
  begin
    Mask := Mask or (1 shl 4);
  end;

  C.Dr3 := FHW4.Address;
  if FHW4.IsSet then
  begin
    Mask := Mask or (1 shl 6);
  end;

  C.Dr6 := C.Dr6 and $FFFFBFFF;
  C.Dr7 := Mask or (UInt8(FHW1.BType) shl 16) or (UInt8(FHW2.BType) shl 20) or (UInt8(FHW3.BType) shl 24) or (UInt8(FHW4.BType) shl 28);
end;

procedure TDebuggerCore.UpdateDR(hThread: THandle);
var
  C: TContext;
begin
  C.ContextFlags := CONTEXT_DEBUG_REGISTERS;
  if GetThreadContext(hThread, C) then
  begin
    ApplyDebugRegisters(C);
    SetThreadContext(hThread, C);
  end
  else
    Log(ltFatal, 'GetThreadContext failed');
end;

function TDebuggerCore.WriteByte(Address: Pointer; Value: Byte): Boolean;
var
  OldProt: DWORD;
  x: NativeUInt;
begin
  Result := VirtualProtectEx(FProcess.hProcess, Address, 1, PAGE_EXECUTE_READWRITE, @OldProt) and
            WriteProcessMemory(FProcess.hProcess, Address, @Value, 1, x) and
            VirtualProtectEx(FProcess.hProcess, Address, 1, OldProt, @OldProt);
  FlushInstructionCache(FProcess.hProcess, Address, 1);
end;

function TDebuggerCore.OnSoftwareBreakpoint(var DebugEv: TDebugEvent): DWORD;
var
  EIP: Pointer;
  hThread: THandle;
  Action: TSoftBPAction;
  C: TContext;
  B: Byte;
begin
  EIP := DebugEv.Exception.ExceptionRecord.ExceptionAddress;
  hThread := FThreads[DebugEv.dwThreadId];

  C.ContextFlags := CONTEXT_CONTROL;
  GetThreadContext(hThread, C);
  Dec({$IFDEF CPUX86}C.Eip{$ELSE}C.Rip{$ENDIF});
  SetThreadContext(hThread, C);

  B := FSoftBPs[EIP];
  // Before OnSoftwareBreakpoint (child implementations may write to EIP!).
  if not WriteByte(EIP, B) then
    Log(ltFatal, 'Restoring original byte failed');

  Action := OnSoftwareBreakpoint(hThread, EIP);

  if Action = sbpClearContinue then
  begin
    FSoftBPs.Remove(EIP);
  end
  else if Action = sbpKeepContinue then // Keep, single step
  begin
    FSoftBPReenable := {$IFDEF CPUX86}C.Eip{$ELSE}C.Rip{$ENDIF};
    C.EFlags := C.EFlags or $100;
    SetThreadContext(hThread, C);
  end
  else if Action = sbpKeepContinueNoStep then
  begin
    if not WriteByte(EIP, $CC) then
      Log(ltFatal, 'KeepContinueNoStep failed');
  end;

  Result := DBG_CONTINUE;
end;

procedure TDebuggerCore.SetSoftBP(Address: Pointer);
var
  B: Byte;
  x: NativeUInt;
begin
  if not ReadProcessMemory(FProcess.hProcess, Address, @B, 1, x) then
    raise Exception.CreateFmt('Read for soft bp at %p failed', [Address]);

  if FSoftBPs.ContainsKey(Address) then
  begin
    if B <> $CC then
      Log(ltFatal, Format('Soft bp inconsistency at %p!', [Address]));
    Exit;
  end;

  FSoftBPs.Add(Address, B);

  if not WriteByte(Address, $CC) then
    raise Exception.CreateFmt('Write for soft bp at %p failed', [Address]);

  FlushInstructionCache(FProcess.hProcess, Address, 1);
end;

procedure TDebuggerCore.SoftBPClear;
var
  BP: TPair<Pointer, Byte>;
begin
  for BP in FSoftBPs do
  begin
    WriteByte(BP.Key, BP.Value);
  end;
  FSoftBPs.Clear;
end;

{ TBreakpoint }

procedure TBreakpoint.Change(AAddress: NativeUInt; AType: THWBPType);
begin
  Address := AAddress;
  BType := AType;
end;

function TBreakpoint.IsSet: Boolean;
begin
  Result := not Disabled and (Address > 0);
end;

end.

