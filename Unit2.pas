unit Unit2;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics,
  Controls, Forms, Dialogs, StdCtrls, Themida, ComCtrls, ImgList, Utils, System.ImageList,
  Vcl.Menus;

type
  TThemidaUnpackerWnd = class(TForm)
    btnUnpack: TButton;
    OD: TOpenDialog;
    LV: TListView;
    ImageList1: TImageList;
    btnShrink: TButton;
    btnDumpProcess: TButton;
    cbDataSections: TCheckBox;
    pmSections: TPopupMenu;
    miCreateSectionsNow: TMenuItem;
    procedure btnDumpProcessClick(Sender: TObject);
    procedure btnUnpackClick(Sender: TObject);
    procedure btnShrinkClick(Sender: TObject);
    procedure miCreateSectionsNowClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    procedure Log(MsgType: TLogMsgType; const Msg: string);
  end;

var
  ThemidaUnpackerWnd: TThemidaUnpackerWnd;

implementation

uses Patcher;

{$R *.dfm}

procedure GUILog(MsgType: TLogMsgType; const Msg: string);
begin
  ThemidaUnpackerWnd.Log(MsgType, Msg);
end;

procedure TThemidaUnpackerWnd.FormCreate(Sender: TObject);
begin
  Utils.Log := GUILog;
end;

procedure TThemidaUnpackerWnd.btnUnpackClick(Sender: TObject);
begin
  if OD.Execute then
  begin
    TDebugger.Create(OD.FileName, '', cbDataSections.Checked).FreeOnTerminate := True;
  end;
end;

procedure TThemidaUnpackerWnd.btnShrinkClick(Sender: TObject);
begin
  if OD.Execute then
    with TPatcher.Create(OD.FileName) do
    begin
      ProcessShrink();
      Free;
    end;
end;

procedure TThemidaUnpackerWnd.miCreateSectionsNowClick(Sender: TObject);
begin
  if OD.Execute then
    with TPatcher.Create(OD.FileName) do
    begin
      try
        ProcessMkData;
      finally
        Free;
      end;
    end;
end;

procedure TThemidaUnpackerWnd.btnDumpProcessClick(Sender: TObject);
var
  PIDInput: string;
  PID: NativeInt;
  hProcess: THandle;
begin
  PIDInput := InputBox('Dump Olly Process', 'PID:', '');
  if PIDInput = '' then
    Exit;

  PID := StrToInt(PIDInput);

  hProcess := OpenProcess(PROCESS_ALL_ACCESS, False, PID);
  if hProcess = 0 then
    RaiseLastOSError;

  if OD.Execute then
    with TPatcher.Create(OD.FileName) do
    begin
      try
        DumpProcessCode(hProcess);
      finally
        Free;
      end;
    end;
end;

procedure TThemidaUnpackerWnd.Log(MsgType: TLogMsgType; const Msg: string);
begin
  with LV.Items.Add do
  begin
    Caption := Msg;
    ImageIndex := Integer(MsgType);
    MakeVisible(False);
  end;
end;

end.
