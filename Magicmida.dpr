program Magicmida;

{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

uses
  Windows,
  TypInfo,
  Vcl.Forms,
  Unit2 in 'Unit2.pas' {ThemidaUnpackerWnd},
  Debugger in 'Debugger.pas',
  Utils in 'Utils.pas',
  Dumper in 'Dumper.pas',
  PEInfo in 'PEInfo.pas',
  Patcher in 'Patcher.pas',
  BeaEngineDelphi32 in 'BeaEngineDelphi32.pas',
  Tracer in 'Tracer.pas',
  AntiDumpFix in 'AntiDumpFix.pas',
  DebuggerCore in 'DebuggerCore.pas';

{$R *.res}

procedure ConsoleLog(MsgType: TLogMsgType; const Msg: string);
begin
  Writeln('[', Copy(TypInfo.GetEnumName(TypeInfo(TLogMsgType), Ord(MsgType)), 3, 10), '] ', Msg);
end;

procedure CheckCommandlineInvocation;
begin
  if (ParamCount >= 1) and (ParamStr(1) = '/unpack') then
  begin
    if not AttachConsole(ATTACH_PARENT_PROCESS) then
    begin
      AssignFile(Output, 'NUL');
      Rewrite(Output);
    end;
    Log := ConsoleLog;

    if ParamCount < 2 then
    begin
      Writeln('Usage: ', ParamStr(0), ' /unpack <filename>');
      Halt(1);
    end;

    try
      with TDebugger.Create(ParamStr(2), '', True) do
        try
          WaitFor;
        finally
          Free;
        end;
    finally
      Halt(0);
    end;
  end;
end;


begin
  CheckCommandlineInvocation;

  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TThemidaUnpackerWnd, ThemidaUnpackerWnd);
  Application.Run;
end.
