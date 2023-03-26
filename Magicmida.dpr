program Magicmida;

{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

uses
  Vcl.Forms,
  Unit2 in 'Unit2.pas' {ThemidaUnpackerWnd},
  Debugger in 'Debugger.pas',
  Utils in 'Utils.pas',
  Dumper in 'Dumper.pas',
  PEInfo in 'PEInfo.pas',
  Patcher in 'Patcher.pas',
  BeaEngineDelphi32 in 'BeaEngineDelphi32.pas',
  Tracer in 'Tracer.pas',
  AntiDumpFix in 'AntiDumpFix.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TThemidaUnpackerWnd, ThemidaUnpackerWnd);
  Application.Run;
end.
