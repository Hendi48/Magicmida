unit Tracer;

interface

uses Windows, SysUtils, Utils;

type
  TTracePredicate = function(const C: TContext): Boolean of object;

  TTracer = class
  private
    FProcessID, FThreadID: Cardinal;
    FThreadHandle: THandle;
    FPredicate: TTracePredicate;
    FCounter, FLimit: Cardinal;
    FLimitReached: Boolean;
    Log: TLogProc;

    function OnSingleStep(const Ev: TDebugEvent): Cardinal;
  public
    constructor Create(AProcessID, AThreadID: Cardinal; AThreadHandle: THandle;
      APredicate: TTracePredicate; ALog: TLogProc);

    procedure Trace(AAddress: NativeUInt; ALimit: Cardinal);

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
begin
  FCounter := 0;
  FLimit := ALimit;
  FLimitReached := False;

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
          Log(ltFatal, 'Unexpected exception during tracing: ' + IntToHex(Ev.Exception.ExceptionRecord.ExceptionCode, 8));
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

  C.EFlags := C.EFlags or $100;
  if not SetThreadContext(FThreadHandle, C) then
    RaiseLastOSError;

  if FPredicate(C) then
    Result := DBG_CONTROL_BREAK
  else
    Result := DBG_CONTINUE;
end;

end.
