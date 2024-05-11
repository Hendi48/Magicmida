unit Patcher;

interface

uses Windows, SysUtils, Classes, PEInfo, Generics.Collections, Utils;

type
  TPatcher = class
  private
    FFileName: string;
    FStream: TMemoryStream;
    PE: TPEHeader;

    procedure ShrinkPE;
    procedure ShrinkExportSect;

    // Proper section characteristics are important for MSVC applications because they
    // check them during C runtime initialization (especially .rdata).
    procedure MapleCreateDataSections;
    procedure MSVCCreateDataSections;

    function FindDataStartMSVC6: NativeUInt;
    function FindDynTLSMSVC14(out DynTLSInit: NativeUInt): Boolean;
    //function FindDataStartByDisasm: NativeUInt;
  public
    constructor Create(const AFileName: string);
    destructor Destroy; override;

    procedure ProcessShrink;
    procedure ProcessMkData;

    procedure DumpProcessCode(hProcess: THandle);
  end;

implementation

uses Debugger, StrUtils;

{ TPatcher }

constructor TPatcher.Create(const AFileName: string);
begin
  FFileName := AFileName;
  FStream := TMemoryStream.Create;
  FStream.LoadFromFile(AFileName);
  FStream.Position := 0;

  PE := TPEHeader.Create(FStream.Memory);
end;

destructor TPatcher.Destroy;
begin
  FStream.Free;
  PE.Free;

  inherited;
end;

procedure TPatcher.ProcessShrink;
begin
  ShrinkPE;
  ShrinkExportSect;

  PE.SaveToStream(FStream);
  FStream.SaveToFile(FFileName);
end;

procedure TPatcher.ProcessMkData;
var
  Lower: string;
  PosMS: Integer;
begin
  Lower := LowerCase(FFileName);
  PosMS := Lower.LastIndexOf('maplestory');
  if (PosMS > 0) and (Pos('.exe', Lower, PosMS) < PosMS + 10 + 10) then
    MapleCreateDataSections
  else if PE.NTHeaders.OptionalHeader.MajorLinkerVersion = 14 then // MSVC 2015+
    MSVCCreateDataSections
  else
  begin
    Log(ltInfo, 'Data section creation not available for this compiler.');
    Exit;
  end;

  PE.SaveToStream(FStream);
  FStream.SaveToFile(FFileName);
end;

procedure TPatcher.ShrinkPE;
var
  i: Integer;
  Del: TList<Integer>;
  NS: TMemoryStream;

  function IsReferenced(SH: TImageSectionHeader): Boolean;
  var
    i: Integer;
  begin
    for i := 0 to High(PE.NTHeaders.OptionalHeader.DataDirectory) do
      with PE.NTHeaders.OptionalHeader.DataDirectory[i] do
      begin
        if (VirtualAddress >= SH.VirtualAddress) and (VirtualAddress + Size <= SH.VirtualAddress + SH.Misc.VirtualSize) then
          Exit(True);
      end;
    Result := False;
  end;

begin
  Del := TList<Integer>.Create;
  NS := TMemoryStream.Create;
  NS.CopyFrom(FStream, PE.Sections[0].Header.PointerToRawData);
  for i := 0 to High(PE.Sections) do
  begin
    if not IsReferenced(PE.Sections[i].Header) and (PAnsiChar(@PE.Sections[i].Header.Name) <> '.data')
      and (PAnsiChar(@PE.Sections[i].Header.Name) <> '.rdata') and (i > 0) then
    begin
      Del.Add(i);
      if i <> High(PE.Sections) then
        FStream.Seek(PE.Sections[i + 1].Header.PointerToRawData - PE.Sections[i].Header.PointerToRawData, soCurrent);
    end
    else
    begin
      if i <> High(PE.Sections) then
        NS.CopyFrom(FStream, PE.Sections[i + 1].Header.PointerToRawData - PE.Sections[i].Header.PointerToRawData)
      else
        NS.CopyFrom(FStream, PE.SizeOfImage - PE.Sections[i].Header.PointerToRawData);
    end;
  end;
  FStream.Free;
  FStream := NS;

  Del.Reverse;
  for i in Del do
    PE.DeleteSection(i);
  Del.Free;
end;

procedure TPatcher.ShrinkExportSect;
var
  Dir: PImageDataDirectory;
  EH: PImageSectionHeader;
  PBase, PExp: PByte;
  Diff, i: Cardinal;
  NS: TMemoryStream;
  E: PImageExportDirectory;
  N: PCardinal;
  Name: AnsiString;
begin
  Dir := @PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  EH := @PE.GetSectionByVA(Dir.VirtualAddress)^.Header;
  PBase := PByte(FStream.Memory) + EH.PointerToRawData;
  PExp := PBase + (Dir.VirtualAddress - EH.VirtualAddress);
  Move(PExp^, PBase^, Dir.Size);
  FillChar((PBase + Dir.Size)^, $1000 - Dir.Size, 0);
  Dir.VirtualAddress := EH.VirtualAddress;

  Diff := NativeUInt(PExp - PBase);
  E := Pointer(PBase);
  Dec(E.Name, Diff);
  Dec(E.AddressOfFunctions, Diff);
  Dec(E.AddressOfNames, Diff);
  Dec(E.AddressOfNameOrdinals, Diff);
  N := PCardinal(PBase + (E.AddressOfNames - EH.VirtualAddress));
  for i := 0 to E.NumberOfNames - 1 do
  begin
    Dec(N^, Diff);
    Inc(N);
  end;

  Diff := EH.SizeOfRawData - $1000;
  Dec(EH.SizeOfRawData, Diff);
  for i := 0 to High(PE.Sections) do
  begin
    if PE.Sections[i].Header.VirtualAddress > EH.VirtualAddress then
    begin
      Dec(PE.Sections[i].Header.PointerToRawData, Diff);
    end;
  end;

  Name := '.export'#0;
  Move(Name[1], EH.Name[0], Length(Name));
  EH.Characteristics := EH.Characteristics and not IMAGE_SCN_MEM_WRITE and not IMAGE_SCN_MEM_EXECUTE;

  FStream.Position := 0;
  NS := TMemoryStream.Create;
  NS.CopyFrom(FStream, EH.PointerToRawData + $1000);
  FStream.Seek(Diff, soCurrent);
  NS.CopyFrom(FStream, FStream.Size - FStream.Position);
  FStream.Free;
  FStream := NS;
end;

procedure TPatcher.MapleCreateDataSections;
var
  Mem: PByte;
  DataStart, DataSize, A, ZEnd, ZStart, GfidsSize: NativeUInt;
  RDataStart, RDataSize: NativeUInt;
  i: Integer;
  Name: AnsiString;
  ZSize: Cardinal;
  Lock: Boolean;
begin
  Mem := PByte(FStream.Memory);
  DataStart := FindStatic('10000000200000004000000060000000', Mem + $2000000, FStream.Size - $2000000);
  if DataStart = 0 then
  begin
    if PE.NTHeaders.OptionalHeader.MajorLinkerVersion = 6 then
    begin
      DataStart := FindDataStartMSVC6;
      if DataStart = 0 then
        raise Exception.Create('Data section not found');
    end
    else
    begin
      DataStart := FindStatic('2E3F41565F636F6D5F6572726F724040', Mem + ($B00000 - $400000), FStream.Size - ($B00000 - $400000));
      if DataStart = 0 then
      begin
        raise Exception.Create('Data section not found');
      end
      else
      begin
        Inc(DataStart, ($B00000 - $400000) - 8);
        if ((DataStart and $FFF) = $B4) or ((DataStart and $FFF) = $F8) or ((DataStart and $FFF) = $FC) then
          DataStart := DataStart and $FFFFF000;
        Log(ltInfo, 'Old executable');
      end;
    end;
  end
  else
    Inc(DataStart, $2000000);

  if DataStart and $FFF <> 0 then
    raise Exception.CreateFmt('Data section bytes found, but not aligned: %X', [DataStart]);

  Log(ltGood, '.data section at ' + IntToHex(DataStart, 8) + ' (VA ' + IntToHex(DataStart + $400000, 8) + ')');

  PE.AddSectionToArray;
  PE.AddSectionToArray;
  for i := High(PE.Sections) downto 3 do
    PE.Sections[i] := PE.Sections[i - 2];

  ZEnd := 0;
  ZSize := 0;
  Lock := False;
  for A := PE.Sections[3].Header.PointerToRawData - 1 downto DataStart do
  begin
    if (Mem + A)^ = 0 then
    begin
      if ZSize = 0 then
        ZEnd := A+1;
      Inc(ZSize);
      if (ZSize > $2000) then
      begin
        Lock := True;
      end;
    end
    else
    begin
      if Lock then
        Break;
      ZSize := 0;
    end;
  end;
  Inc(A);

  if ZSize = 0 then
    raise Exception.Create('Data section doesn''t contain zeroes');

  // Sometimes first byte of following section is 0
  if ZEnd and $FFF = 1 then
  begin
    Dec(ZEnd);
    Dec(ZSize);
  end;

  if ZEnd and $FFF <> 0 then
    raise Exception.CreateFmt('Real .data section end not found (got %X with a size of %X)', [ZEnd, ZSize]);

  ZStart := (A + $1000) and $FFFFF000;
  Dec(ZSize, ZStart - A);

  GfidsSize := PE.Sections[3].Header.PointerToRawData - ZEnd;

  // .data
  Name := '.data';
  DataSize := PE.Sections[3].Header.PointerToRawData - DataStart - GfidsSize;
  FillChar(PE.Sections[2], SizeOf(TPESection), 0);
  Move(Name[1], PE.Sections[2].Header.Name[0], Length(Name));
  with PE.Sections[2].Header do
  begin
    Misc.VirtualSize := DataSize;
    VirtualAddress := DataStart;
    PointerToRawData := DataStart;
    SizeOfRawData := DataSize - ZSize;
    Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_CNT_INITIALIZED_DATA;
  end;

  // .rdata
  Name := '.rdata';
  RDataStart := PE.NTHeaders.OptionalHeader.BaseOfData;
  RDataSize := DataStart - RDataStart;
  FillChar(PE.Sections[1], SizeOf(TPESection), 0);
  Move(Name[1], PE.Sections[1].Header.Name[0], Length(Name));
  with PE.Sections[1].Header do
  begin
    Misc.VirtualSize := RDataSize;
    VirtualAddress := RDataStart;
    PointerToRawData := RDataStart;
    SizeOfRawData := RDataSize;
    Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_CNT_INITIALIZED_DATA;
  end;

  // .gfids/.vmp
  if GfidsSize <> 0 then
  begin
    PE.AddSectionToArray;
    for i := High(PE.Sections) downto 4 do
      PE.Sections[i] := PE.Sections[i - 1];

    if PE.NTHeaders.OptionalHeader.MajorLinkerVersion >= 14 then
      Name := '.gfids'
    else
      Name := '.vmp';

    FillChar(PE.Sections[3], SizeOf(TPESection), 0);
    Move(Name[1], PE.Sections[3].Header.Name[0], Length(Name));
    with PE.Sections[3].Header do
    begin
      Misc.VirtualSize := GfidsSize;
      VirtualAddress := ZEnd;
      PointerToRawData := ZEnd;
      SizeOfRawData := GfidsSize;
      Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_CNT_INITIALIZED_DATA;
    end;

    Inc(PE.NTHeaders.FileHeader.NumberOfSections, 3);
  end
  else
  begin
    if PE.NTHeaders.OptionalHeader.MajorLinkerVersion >= 14 then
      Log(ltFatal, '.gfids not found');
    Inc(PE.NTHeaders.FileHeader.NumberOfSections, 2);
  end;

  Dec(PE.Sections[0].Header.Misc.VirtualSize, RDataSize + DataSize + GfidsSize);
  Dec(PE.Sections[0].Header.SizeOfRawData, RDataSize + DataSize + GfidsSize);

  Name := '.text'#0#0#0;
  Move(Name[1], PE.Sections[0].Header.Name[0], Length(Name));
  PE.Sections[0].Header.Characteristics := PE.Sections[0].Header.Characteristics and not IMAGE_SCN_MEM_WRITE;
end;

function TPatcher.FindDataStartMSVC6: NativeUInt;
var
  CInitCode: NativeUInt;
begin
  // In MSVC6 binaries, the second (r/w) data section appears to start with the __cinit func list
  CInitCode := FindDynamic('68????????68??????00E8????????83C410C3', PByte(FStream.Memory) + $100000, FStream.Size - $100000);
  if CInitCode = 0 then
    Exit(0);

  Inc(CInitCode, $100000);
  Result := PCardinal(PByte(FStream.Memory) + CInitCode + 6)^;
  if Result and $FFF <> 0 then
    Result := 0
  else
    Dec(Result, PE.NTHeaders.OptionalHeader.ImageBase);
end;

function TPatcher.FindDynTLSMSVC14(out DynTLSInit: NativeUInt): Boolean;
var
  DynTLSCode: NativeUInt;
  CodePtr, GetPtrFunc, DynTLSInitPtr: PByte;
begin
  {
    call    __scrt_get_dyn_tls_init_callback
    mov     esi, eax
    xor     edi, edi
    cmp     [esi], edi
    jz      short ??
    push    esi
    call    __scrt_is_nonwritable_in_current_image
  }
  DynTLSCode := FindDynamic('8BF033FF393E74??56E8', PByte(FStream.Memory) + $1000, FStream.Size - $1000);
  if DynTLSCode = 0 then
  begin
    Log(ltInfo, 'DynTLS code sequence not found.');
    Exit(False);
  end;

  CodePtr := PByte(FStream.Memory) + $1000 + DynTLSCode;
  if (CodePtr - 5)^ <> $E8 then
  begin
    Log(ltInfo, 'DynTLS code sequence mismatch.');
    Exit(False);
  end;

  GetPtrFunc := CodePtr + PInteger(CodePtr - 4)^;
  if GetPtrFunc^ = $E9 then // another indirection via jmp
    GetPtrFunc := GetPtrFunc + PInteger(GetPtrFunc + 1)^ + 5;
  if GetPtrFunc^ <> $B8 then
  begin
    Log(ltInfo, 'DynTLS call analysis failed.');
    Exit(False);
  end;

  DynTLSInit := PCardinal(GetPtrFunc + 1)^ - PE.NTHeaders.OptionalHeader.ImageBase;
  DynTLSInitPtr := PByte(FStream.Memory) + DynTLSInit;

  Log(ltInfo, Format('[MSVC] dyn_tls_init at %.8X', [PCardinal(DynTLSInitPtr)^]));

  // If the function pointer points to 0, the compiler places this var in a writable section
  // and we can't use it as a separator.
  if PCardinal(DynTLSInitPtr)^ = 0 then
    DynTLSInit := 0;

  Result := True;
end;

{
This was a fun idea but it fails when executables have a construct like this as their first written access:
mov ecx, offset FOO
call DereferenceAndWriteEcx

function TPatcher.FindDataStartByDisasm: NativeUInt;
var
  Dis: _Disasm;
  Res: Integer;
  Addresses: TDictionary<NativeUInt, Boolean>;
  AddressesList: TList<NativeUInt>;
  CandidateStart, CandidateEnd, Base: NativeUInt;
  i, j: Integer;
  OK: Boolean;
begin
  FillChar(Dis, SizeOf(Dis), 0);
  Dis.Archi := 32;
  Dis.EIP := NativeUInt(FStream.Memory) + PE.Sections[0].Header.VirtualAddress;
  Dis.VirtualAddr := PE.Sections[0].Header.VirtualAddress;

  CandidateStart := PE.NTHeaders.OptionalHeader.BaseOfData;
  CandidateEnd := PE.Sections[0].Header.VirtualAddress + PE.Sections[0].Header.Misc.VirtualSize;
  Base := PE.NTHeaders.OptionalHeader.ImageBase;

  Addresses := TDictionary<NativeUInt, Boolean>.Create;
  // Disassemble the entire text section and collect written addresses.
  while Dis.VirtualAddr < CandidateStart do
  begin
    Res := Disasm(Dis);
    if Res <= 0 then
    begin
      Inc(Dis.EIP);
      Inc(Dis.VirtualAddr);
      Continue;
    end;

    if ((Dis.Argument1.ArgType and $F0000000) = MEMORY_TYPE) and
        (Dis.Argument1.Memory.BaseRegister = 0) and
        (Dis.Argument1.Memory.Displacement <> 0) and
        (Dis.Argument1.AccessMode <> READ) and
        (NativeUInt(Dis.Argument1.Memory.Displacement) >= CandidateStart + Base) and
        (NativeUInt(Dis.Argument1.Memory.Displacement) < CandidateEnd + Base) then
    begin
      Addresses.AddOrSetValue(Dis.Argument1.Memory.Displacement, True);
    end;

    Inc(Dis.EIP, Res);
    Inc(Dis.VirtualAddr, Res);
  end;

  AddressesList := nil;
  try
    if Addresses.Count = 0 then
      Exit(0);

    AddressesList := TList<NativeUInt>.Create(Addresses.Keys);
    AddressesList.Sort;

    if AddressesList.Count < 3 then
    begin
      Log(ltInfo, Format('Only few mem writes, picking first reference for .data: %.8x.', [AddressesList[0] - Base]));
      Exit((AddressesList[0] - Base) and not $FFF);
    end;

    for i := 0 to AddressesList.Count - 1 do
    begin
      // Check if we have a set of 3 addresses that are all within $40 of each other.
      // This is a pretty dumb heuristic, 3 and $40 are randomly chosen.
      OK := True;
      for j := i + 1 to i + 2 do
        if AddressesList[j] > AddressesList[j - 1] + $40 then
          OK := False;

      if OK then
      begin
        Log(ltInfo, Format('Heuristic picked %.8x as first actual .data write.', [AddressesList[i] - Base]));
        Exit((AddressesList[i] - Base) and not $FFF);
      end;
    end;

    Result := 0;
  finally
    AddressesList.Free;
    Addresses.Free;
  end;
end;
}

procedure TPatcher.MSVCCreateDataSections;
var
  i: Integer;
  DynTLS: NativeUInt;
  BaseOfData, DataStart, DataSize, RDataStart, RDataSize: Cardinal;
  Name: AnsiString;
begin
  BaseOfData := PE.NTHeaders.OptionalHeader.BaseOfData;
  if (BaseOfData > PE.Sections[0].Header.VirtualAddress) and
     (BaseOfData < PE.Sections[0].Header.VirtualAddress + PE.Sections[0].Header.Misc.VirtualSize) and
     ((BaseOfData and $FFF) = 0) then
  begin
    if not FindDynTLSMSVC14(DynTLS) then
      Exit;

    // This is by no means exact. We keep the writable data section as large as possible because
    // we can't determine its real size in a generic way and we don't want to risk access violations.
    if DynTLS <> 0 then
    begin
      DataStart := (DynTLS + $1000) and not $FFF;
    end
    else
    begin
      DataStart := BaseOfData + $1000;
      Log(ltInfo, 'Setting .rdata size to just 1000 (no reference point for actual size)');
    end;

    PE.AddSectionToArray;
    PE.AddSectionToArray;
    for i := High(PE.Sections) downto 3 do
      PE.Sections[i] := PE.Sections[i - 2];

    Inc(PE.NTHeaders.FileHeader.NumberOfSections, 2);

    // .data at [2]
    Name := '.data';
    DataSize := PE.Sections[3].Header.PointerToRawData - DataStart;
    FillChar(PE.Sections[2], SizeOf(TPESection), 0);
    Move(Name[1], PE.Sections[2].Header.Name[0], Length(Name));
    with PE.Sections[2].Header do
    begin
      Misc.VirtualSize := DataSize;
      VirtualAddress := DataStart;
      PointerToRawData := DataStart;
      SizeOfRawData := DataSize;
      Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_CNT_INITIALIZED_DATA;
    end;

    // .rdata at [1]
    Name := '.rdata';
    RDataStart := BaseOfData;
    RDataSize := DataStart - RDataStart;
    FillChar(PE.Sections[1], SizeOf(TPESection), 0);
    Move(Name[1], PE.Sections[1].Header.Name[0], Length(Name));
    with PE.Sections[1].Header do
    begin
      Misc.VirtualSize := RDataSize;
      VirtualAddress := RDataStart;
      PointerToRawData := RDataStart;
      SizeOfRawData := RDataSize;
      Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_CNT_INITIALIZED_DATA;
    end;

    Dec(PE.Sections[0].Header.Misc.VirtualSize, RDataSize + DataSize);
    Dec(PE.Sections[0].Header.SizeOfRawData, RDataSize + DataSize);

    with PE.Sections[0].Header do
      Log(ltInfo, Format('.text : %.8x ~ %.8x', [VirtualAddress, VirtualAddress + Misc.VirtualSize]));
    with PE.Sections[1].Header do
      Log(ltInfo, Format('.rdata: %.8x ~ %.8x', [VirtualAddress, VirtualAddress + Misc.VirtualSize]));
    with PE.Sections[2].Header do
      Log(ltInfo, Format('.data : %.8x ~ %.8x', [VirtualAddress, VirtualAddress + Misc.VirtualSize]));
  end
  else
    Log(ltInfo, 'Assuming sections are not merged.');

  // Rename first section and remove WRITE characteristic.
  Name := '.text'#0#0#0;
  Move(Name[1], PE.Sections[0].Header.Name[0], Length(Name));
  PE.Sections[0].Header.Characteristics := PE.Sections[0].Header.Characteristics and not IMAGE_SCN_MEM_WRITE;
end;

procedure TPatcher.DumpProcessCode(hProcess: THandle);
var
  StartAddr, EndAddr, NumRead: NativeUInt;
  Buf: Pointer;
begin
  StartAddr := PE.NTHeaders.OptionalHeader.ImageBase + PE.Sections[0].Header.VirtualAddress;
  EndAddr := PE.NTHeaders.OptionalHeader.ImageBase + PE.NTHeaders.OptionalHeader.BaseOfData;

  GetMem(Buf, EndAddr - StartAddr);
  try
    if not ReadProcessMemory(hProcess, Pointer(StartAddr), Buf, EndAddr - StartAddr, NumRead) or (NumRead <> EndAddr - StartAddr) then
      RaiseLastOSError;

    FStream.Seek(PE.Sections[0].Header.PointerToRawData, soBeginning);
    FStream.Write(Buf^, EndAddr - StartAddr);
    FStream.SaveToFile(ChangeFileExt(FFilename, '.novm.exe'));

    Log(ltGood, Format('Dumped %X bytes.', [EndAddr - StartAddr]));
  finally
    FreeMem(Buf);
  end;
end;

end.
