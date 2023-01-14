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

    procedure MSCreateDataSections;

    function FindDataStartMSVC6: NativeUInt;
  public
    constructor Create(const AFileName: string);
    destructor Destroy; override;

    procedure Process;
    procedure ProcessMkData;

    procedure DumpProcessCode(hProcess: THandle);
  end;

implementation

uses Unit2, Debugger;

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

procedure TPatcher.Process;
begin
  ShrinkPE;
  ShrinkExportSect;

  PE.SaveToStream(FStream);
  FStream.SaveToFile(FFileName);
end;

procedure TPatcher.ProcessMkData;
begin
  MSCreateDataSections;

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

procedure TPatcher.MSCreateDataSections;
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
    raise Exception.Create('Data section doesn''t contain null bytes');

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
