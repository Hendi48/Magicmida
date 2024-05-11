unit Tracer;

interface

uses Windows, SysUtils, Utils;

type
  TTracer = class;

  TTracePredicate = function(Tracer: TTracer; var C: TContext): Boolean of object;

  TTracer = class
  private
    FProcessID, FThreadID: Cardinal;
    FThreadHandle: THandle;
    FPredicate: TTracePredicate;
    FCounter, FLimit: Cardinal;
    FLimitReached: Boolean;
    Log: TLogProc;

    FStartAddress: NativeUInt;

    function OnSingleStep(const Ev: TDebugEvent): Cardinal;
  public
    constructor Create(AProcessID, AThreadID: Cardinal; AThreadHandle: THandle;
      APredicate: TTracePredicate; ALog: TLogProc);

    procedure Trace(AAddress: NativeUInt; ALimit: Cardinal);

    property StartAddress: NativeUInt read FStartAddress;
    property Counter: Cardinal read FCounter;
    property LimitReached: Boolean read FLimitReached;
  end;

implementation

{ TTracer }

constructor TTracer.Create(AProcessID, AThreadID: Cardinal; AThreadHandle: THandle;
  APredicate: TTracePredicate; ALog: TLogProc);
begin
  FProcessID := AProcessID;
  FThreadID := AThreadID;
  FThreadHandle := AThreadHandle;
  FPredicate := APredicate;
  Log := ALog;
end;

procedure TTracer.Trace(AAddress: NativeUInt; ALimit: Cardinal);
var
  C: TContext;
  Ev: TDebugEvent;
  Status: Cardinal;
  hThread: THandle;
begin
  FCounter := 0;
  FLimit := ALimit;
  FLimitReached := False;
  FStartAddress := AAddress;

  C.ContextFlags := CONTEXT_CONTROL;
  if not GetThreadContext(FThreadHandle, C) then
    RaiseLastOSError;

  C.Eip := AAddress;
  C.EFlags := C.EFlags or $100; // Trap
  if not SetThreadContext(FThreadHandle, C) then
    RaiseLastOSError;

  if not ContinueDebugEvent(FProcessID, FThreadID, DBG_CONTINUE) then
    Exit;

  Status := DBG_EXCEPTION_NOT_HANDLED;
  while WaitForDebugEvent(Ev, INFINITE) do
  begin
    if Ev.dwThreadId <> FThreadID then
    begin
      Log(ltInfo, Format('Suspending spurious thread %d', [Ev.dwThreadId]));
      hThread := OpenThread(2, False, Ev.dwThreadId); // THREAD_SUSPEND_RESUME
      if hThread <> INVALID_HANDLE_VALUE then
      begin
        SuspendThread(hThread);
        CloseHandle(hThread);
      end;
      ContinueDebugEvent(Ev.dwProcessId, Ev.dwThreadId, DBG_CONTINUE);
      Continue;
    end;

    case Ev.dwDebugEventCode of
      EXCEPTION_DEBUG_EVENT:
      begin
        if Ev.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_SINGLE_STEP then
        begin
          Status := OnSingleStep(Ev);
          if Status = DBG_CONTROL_BREAK then
            Break;
        end
        else
        begin
          Log(ltFatal, Format('Unexpected exception during tracing: %.8X at %p in thread %d', [Ev.Exception.ExceptionRecord.ExceptionCode, Ev.Exception.ExceptionRecord.ExceptionAddress, Ev.dwThreadId]));
          Exit;
        end;
      end;

      else
        Status := DBG_CONTINUE;
    end;

    ContinueDebugEvent(Ev.dwProcessId, Ev.dwThreadId, Status);
  end;
end;

function TTracer.OnSingleStep(const Ev: TDebugEvent): Cardinal;
var
  C: TContext;
begin
  Inc(FCounter);
  if (FLimit <> 0) and (FCounter > FLimit) then
  begin
    FLimitReached := True;
    Log(ltInfo, 'Giving up trace due to instruction limit');
    Exit(DBG_CONTROL_BREAK);
  end;

  C.ContextFlags := CONTEXT_CONTROL;
  if not GetThreadContext(FThreadHandle, C) then
    RaiseLastOSError;

  if FPredicate(Self, C) then
    Result := DBG_CONTROL_BREAK
  else
    Result := DBG_CONTINUE;

  C.EFlags := C.EFlags or $100;
  if not SetThreadContext(FThreadHandle, C) then
    RaiseLastOSError;
end;

end.
