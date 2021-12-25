unit Utils;

interface

uses Windows, SysUtils;

function NtQueryInformationProcess(ProcessHandle: THandle; ProcessInformationClass: DWORD;
  ProcessInformation: Pointer; ProcessInformationLength: DWORD; ReturnLength: PCardinal): Integer; stdcall; external 'ntdll.dll';
function NtQueryInformationThread(ThreadHandle: THandle; ThreadInformationClass: DWORD;
  ThreadInformation: Pointer; ThreadInformationLength: DWORD; ReturnLength: PCardinal): Integer; stdcall; external 'ntdll.dll';
//function DebugActiveProcessStop(PID: Cardinal): BOOL; stdcall; external kernel32;
function OpenThread(dwDesiredAccess: Cardinal; bInheritHandle: BOOL; dwThreadId: Cardinal): THandle; stdcall; external kernel32;

const
  STATUS_SUCCESS = Integer(0);

type
  TProcessBasicInformation = packed record
    ExitStatus: Cardinal;
    PebBaseAddress: Pointer;
    AffinityMask: PULONG;
    BasePriority: DWORD;
    UniqueProcessId: ULONG;
    InheritedFromUniqueProcessId: ULONG;
  end;

  TThreadBasicInformation = packed record
    ExitStatus: Cardinal;
    TebBaseAddress: Pointer;
    UniqueProcess: THandle;
    UniqueThread: THandle;
    AffinityMask: PULONG;
    Priority: DWORD;
    BasePriority: DWORD;
  end;

function FindDynamic(const APattern: AnsiString; ABuf: PByte; ASize: Cardinal): Cardinal;
function FindStatic(const APattern: AnsiString; ABuf: PByte; ASize: Cardinal): Cardinal;

implementation

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

end.
