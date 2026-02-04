unit AntiDumpFix;

interface

uses Windows, Utils;

type
  // This fixes only one type of anti dump, and it's not guaranteed that it'll be the type used for the OEP.
  // If your binary uses virtualization in other parts of the program, it will very likely crash.
  // Other anti dump types check various fields in the PE header of kernel32.dll. Dumps won't run
  // on other systems/after rebooting because the DLL base will have changed.
  TAntiDumpFixer = class
  private
    FhProcess: THandle;
    FImageBase: NativeUInt;

    function RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
  public
    constructor Create(hProcess: THandle; AImageBase: NativeUInt);

    procedure RedirectOEP(OEP, IAT: NativeUInt);
  end;

implementation

{ TAntiDumpFixer }

constructor TAntiDumpFixer.Create(hProcess: THandle; AImageBase: NativeUInt);
begin
  FhProcess := hProcess;
  FImageBase := AImageBase;
end;

function TAntiDumpFixer.RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
begin
  Result := ReadProcessMemory(FhProcess, Pointer(Address), Buf, BufSize, BufSize);
end;

procedure TAntiDumpFixer.RedirectOEP(OEP, IAT: NativeUInt);
const
  PUSH_ARGS_RW_PROTECT: array[0..10] of Byte = ($6A, $00, $54, $6A, $04, $68, $00, $04, $00, $00, $68);
  PUSH_ARGS_OLD_PROTECT: array[0..10] of Byte = ($54, $FF, $74, $24, $04, $68, $00, $04, $00, $00, $68);
var
  Displ: UInt32;
  NewCode: packed record
    PushArgs1: array[0..High(PUSH_ARGS_RW_PROTECT)] of Byte;
    PushImgBase1: UInt32;
    CallInstr1: UInt16;
    VirtualProtectAddr1: UInt32;

    MovInstr: UInt16;
    OptHdrEntrypoint: UInt32;
    Entrypoint: UInt32;

    PushArgs2: array[0..High(PUSH_ARGS_OLD_PROTECT)] of Byte;
    PushImgBase2: UInt32;
    CallInstr2: UInt16;
    VirtualProtectAddr2: UInt32;
    PopStack: Byte;

    JmpInstr: Byte;
    JmpDispl: UInt32;
  end;
  LfaNew: UInt32;
  VProtectAddr: NativeUInt;
  VProtectIAT, i: UInt32;
  IATData: array[0..511] of NativeUInt;
begin
  RPM(OEP + 1, @Displ, 4);

  VProtectAddr := NativeUInt(GetProcAddress(GetModuleHandle(kernel32), 'VirtualProtect'));
  VProtectIAT := 0;
  RPM(IAT, @IATData, SizeOf(IATData));
  for i := 0 to High(IATData) do
    if IATData[i] = VProtectAddr then
    begin
      VProtectIAT := IAT + i * 4;
      Break;
    end;

  if VProtectIAT = 0 then
  begin
    Log(ltFatal, 'VirtualProtect not found in IAT');
    Exit;
  end;

  // VirtualProtect(ImageBase, $400, PAGE_READWRITE, OldProtect)
  Move(PUSH_ARGS_RW_PROTECT, NewCode.PushArgs1, Length(NewCode.PushArgs1));
  NewCode.PushImgBase1 := FImageBase;
  NewCode.CallInstr1 := $15FF;
  NewCode.VirtualProtectAddr1 := VProtectIAT;

  // mov dword ptr [AddressOfEntryPoint], ThemidaEntrypoint
  NewCode.MovInstr := $05C7;
  if not RPM(FImageBase + $3C, @LfaNew, 4) or not RPM(FImageBase + LfaNew + $28, @NewCode.Entrypoint, 4) then
  begin
    Log(ltFatal, 'ReadProcessMemory failed');
    Exit;
  end;
  NewCode.OptHdrEntrypoint := FImageBase + LfaNew + $28;

  // VirtualProtect(ImageBase, $400, OldProtect, _)
  Move(PUSH_ARGS_OLD_PROTECT, NewCode.PushArgs2, Length(NewCode.PushArgs2));
  NewCode.PushImgBase2 := FImageBase;
  NewCode.CallInstr2 := $15FF;
  NewCode.VirtualProtectAddr2 := VProtectIAT;
  // pop eax (undo initial "push 0" for OldProtect)
  NewCode.PopStack := $58;

  // jmp vm
  NewCode.JmpInstr := $E9;
  NewCode.JmpDispl := Displ - (SizeOf(NewCode) - 5);

  if WriteProcessMemory(FhProcess, Pointer(OEP), @NewCode, SizeOf(NewCode), NativeUInt(nil^)) then
  begin
    Log(ltGood, 'Installed VM anti-dump (PE header) mitigation at OEP');
    Log(ltInfo, 'NOTE: We assume there is enough space at the entrypoint, which may not be the case in every binary.');
  end
  else
    Log(ltFatal, 'WriteProcessMemory failed');
end;

end.
