unit Utils;

interface

uses Windows, SysUtils, Classes;

type
  TLogMsgType = (ltInfo, ltGood, ltFatal);
  TLogProc = procedure(MsgType: TLogMsgType; const Msg: string);

var
  /// <summary>Global log proc, must be set before doing anything!</summary>
  Log: TLogProc;

function NtQueryInformationProcess(ProcessHandle: THandle; ProcessInformationClass: DWORD;
  ProcessInformation: Pointer; ProcessInformationLength: DWORD; ReturnLength: PCardinal): Integer; stdcall; external 'ntdll.dll';
function NtQueryInformationThread(ThreadHandle: THandle; ThreadInformationClass: DWORD;
  ThreadInformation: Pointer; ThreadInformationLength: DWORD; ReturnLength: PCardinal): Integer; stdcall; external 'ntdll.dll';
{$IFDEF FPC}
function DebugActiveProcessStop(PID: Cardinal): BOOL; stdcall; external kernel32;
{$ENDIF}
function OpenThread(dwDesiredAccess: Cardinal; bInheritHandle: BOOL; dwThreadId: Cardinal): THandle; stdcall; external kernel32;

function RtlGetVersion(var Info: OSVERSIONINFOW): LONG; stdcall; external 'ntdll.dll';

const
  STATUS_SUCCESS = Integer(0);

type
  // Windows structs
  TProcessBasicInformation = record
    ExitStatus: Cardinal;
    PebBaseAddress: Pointer;
    AffinityMask: UIntPtr;
    BasePriority: DWORD;
    UniqueProcessId: UIntPtr;
    InheritedFromUniqueProcessId: UIntPtr;
  end;

  TThreadBasicInformation = record
    ExitStatus: Cardinal;
    TebBaseAddress: Pointer;
    UniqueProcess: THandle;
    UniqueThread: THandle;
    AffinityMask: UIntPtr;
    Priority: DWORD;
    BasePriority: DWORD;
  end;

  {$IFDEF FPC}
  PImageExportDirectory = PIMAGE_EXPORT_DIRECTORY;
  PImageImportDescriptor = PIMAGE_IMPORT_DESCRIPTOR;
  TImageImportDescriptor = IMAGE_IMPORT_DESCRIPTOR;
  TImageTLSDirectory32 = IMAGE_TLS_DIRECTORY32;
  TImageTLSDirectory64 = IMAGE_TLS_DIRECTORY64;
  {$ENDIF}

  // Custom structs
  TMemoryRegion = record
    Address: NativeUInt;
    Size: Cardinal;

    constructor Create(AAddress: NativeUInt; ASize: Cardinal);
    function Contains(AAddress: NativeUInt): Boolean;
  end;

function AccessViolationFlagToStr(Flag: Byte): string;
function FindDynamic(const APattern: AnsiString; ABuf: PByte; ASize: Cardinal): Cardinal;
function FindStatic(const APattern: AnsiString; ABuf: PByte; ASize: Cardinal): Cardinal;

function GetWindowsBuildNumber: Cardinal;
function GetPETimestamp(const Filename: string): Cardinal;

implementation

{ TMemoryRegion }

constructor TMemoryRegion.Create(AAddress: NativeUInt; ASize: Cardinal);
begin
  Address := AAddress;
  Size := ASize;
end;

function TMemoryRegion.Contains(AAddress: NativeUInt): Boolean;
begin
  Result := (AAddress >= Address) and (AAddress < Address + Size);
end;

function AccessViolationFlagToStr(Flag: Byte): string;
begin
  case Flag of
    0: Result := 'Read';
    1: Result := 'Write';
    8: Result := 'Execute';
    else Result := IntToStr(Flag);
  end;
end;

function FindDynamic(const APattern: AnsiString; ABuf: PByte; ASize: Cardinal): Cardinal;
var
  bWC: Cardinal;
  B: TArray<Byte>;
  i, j: Cardinal;
  Max: PByte;
begin
  bWC := 0;

  SetLength(B, Length(APattern) div 2);
  for i := 1 to Length(APattern) div 2 do
    if APattern[i * 2 - 1] <> AnsiChar('?') then
      Val('$' + string(APattern[i * 2 - 1] + APattern[i * 2]), B[i - 1], j)
    else
      bWC := bWC or (1 shl (i - 1));

  i := Cardinal(ABuf);
  Max := ABuf + ASize - Length(B);
  while ABuf < Max do
  begin
    for j := 0 to High(B) do
    begin
      if ((bWC shr j) and 1 = 0) and (PByte(ABuf + j)^ <> B[j]) then
        Break;

      if j = UInt32(High(B)) then
        Exit(Cardinal(ABuf) - i);
    end;

    Inc(ABuf);
  end;

  Result := 0;
end;

function FindStatic(const APattern: AnsiString; ABuf: PByte; ASize: Cardinal): Cardinal;
var
  B: TArray<Byte>;
  i, j: Cardinal;
  Max: PByte;
begin
  SetLength(B, Length(APattern) div 2);
  for i := 1 to Length(APattern) div 2 do
    Val('$' + string(APattern[i * 2 - 1] + APattern[i * 2]), B[i - 1], j);

  i := Cardinal(ABuf);
  Max := ABuf + ASize - Length(B);
  while ABuf < Max do
  begin
    if CompareMem(ABuf, @B[0], Length(B)) then
      Exit(Cardinal(ABuf) - i);

    Inc(ABuf);
  end;

  Result := 0;
end;

function GetWindowsBuildNumber: Cardinal;
var
  Info: OSVERSIONINFOW;
begin
  Info.dwOSVersionInfoSize := SizeOf(Info);
  RtlGetVersion(Info);
  Result := Info.dwBuildNumber;
end;

function GetPETimestamp(const Filename: string): Cardinal;
var
  Header: array[0..$FFF] of Byte;
begin
  with TFileStream.Create(Filename, fmOpenRead or fmShareDenyWrite) do
  begin
    Read(Header, SizeOf(Header));
    Free;
  end;

  if Cardinal(PImageDosHeader(@Header[0])^._lfanew) > $F00 then
    Exit(0);

  Result := PImageNTHeaders(@Header[PImageDosHeader(@Header[0])^._lfanew])^.FileHeader.TimeDateStamp;
end;

end.
