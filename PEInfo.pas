unit PEInfo;

interface

uses Windows, Classes, SysUtils;

type
  TPESection = record
    Header: TImageSectionHeader;
    Data: PByte;
  end;
  PPESection = ^TPESection;

  TPESections = TArray<TPESection>;

  TPEHeader = class
  private
    FSections: TPESections;
    FDumpSize: Cardinal;
    FLFANew: Cardinal;

    procedure FileAlign(var V: Cardinal);
    procedure SectionAlign(var V: Cardinal);
  public
    NTHeaders: TImageNTHeaders;

    constructor Create(Data: PByte);

    function CreateSection(const Name: AnsiString; Size: Cardinal): PPESection;
    procedure DeleteSection(Idx: Integer);
    function GetSectionByVA(V: Cardinal): PPESection;
    procedure AddSectionToArray;

    function ConvertOffsetToRVAVector(Offset: NativeUInt): NativeUInt;

    function TrimHugeSections(Buf: PByte): Cardinal;
    procedure Sanitize;

    procedure SaveToStream(S: TStream);

    property Sections: TPESections read FSections;

    property LFANew: Cardinal read FLFANew;
    //property ImageBase: Cardinal read NTHeaders.OptionalHeader.ImageBase;
    property DumpSize: Cardinal read FDumpSize;
    property SizeOfImage: Cardinal read NTHeaders.OptionalHeader.SizeOfImage;
  end;

implementation

{ TPEHeader }

constructor TPEHeader.Create(Data: PByte);
var
  NT: PImageNTHeaders;
  Sect: PImageSectionHeader;
  i: Integer;
begin
  FLFANew := PImageDosHeader(Data)._lfanew;
  NT := PImageNTHeaders(Data + FLFANew);
  NTHeaders := NT^;
  FDumpSize := SizeOfImage;

  Sect := PImageSectionHeader(PByte(NT) + SizeOf(TImageNTHeaders));
  SetLength(FSections, NT.FileHeader.NumberOfSections);
  for i := 0 to High(FSections) do
  begin
    FSections[i].Header := Sect^;
    Inc(Sect);
  end;
end;

function TPEHeader.CreateSection(const Name: AnsiString; Size: Cardinal): PPESection;
var
  Prev: PImageSectionHeader;
begin
  Prev := @FSections[High(FSections)].Header;
  SetLength(FSections, Length(FSections) + 1);
  Result := @FSections[High(FSections)];
  FillChar(Result^, SizeOf(Result^), 0);
  Move(Name[1], Result.Header.Name[0], Length(Name));
  with Result.Header do
  begin
    Misc.VirtualSize := Size;
    VirtualAddress := Prev.VirtualAddress + Prev.Misc.VirtualSize;
    if (VirtualAddress and $FFF) <> 0 then
      VirtualAddress := (VirtualAddress + $1000) and (not $FFF);
    PointerToRawData := Prev.PointerToRawData + Prev.SizeOfRawData;
    SizeOfRawData := Size;
    Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_CNT_INITIALIZED_DATA;
  end;
  Inc(NTHeaders.OptionalHeader.SizeOfImage, Size);
  // NumberOfSections is handled by the dumper
end;

procedure TPEHeader.DeleteSection(Idx: Integer);
var
  i: Integer;
  Sz: Cardinal;
  IsLast: Boolean;
begin
  IsLast := Idx = High(FSections);

  if IsLast then
    Sz := NTHeaders.OptionalHeader.SizeOfImage - FSections[Idx].Header.SizeOfRawData
  else
    Sz := FSections[Idx + 1].Header.PointerToRawData - FSections[Idx].Header.PointerToRawData;

  for i := High(FSections) downto Idx + 1 do
  begin
    Dec(FSections[i].Header.PointerToRawData, Sz);
  end;
  Inc(FSections[Idx - 1].Header.Misc.VirtualSize, FSections[Idx].Header.Misc.VirtualSize);
  SectionAlign(FSections[Idx - 1].Header.Misc.VirtualSize);

  if not IsLast then
    Move(FSections[Idx + 1], FSections[Idx], SizeOf(TPESection) * (High(FSections) - Idx));

  SetLength(FSections, High(FSections));
  Dec(NTHeaders.FileHeader.NumberOfSections);
end;

function TPEHeader.GetSectionByVA(V: Cardinal): PPESection;
var
  i: Integer;
begin
  for i := 0 to High(FSections) do
    if FSections[i].Header.VirtualAddress + FSections[i].Header.Misc.VirtualSize > V then
      Exit(@FSections[i]);

  Result := nil;
end;

procedure TPEHeader.Sanitize;
var
  i: Integer;
begin
  for i := 0 to High(FSections) do
  begin
    with FSections[i].Header do
    begin
      PointerToRawData := VirtualAddress;
      SizeOfRawData := Misc.VirtualSize;
    end;
  end;
  NTHeaders.OptionalHeader.SizeOfHeaders := FSections[0].Header.PointerToRawData;
  // Must have write access in code section (in case .text and .data were merged)
  FSections[0].Header.Characteristics := FSections[0].Header.Characteristics or IMAGE_SCN_MEM_WRITE;
end;

procedure TPEHeader.SaveToStream(S: TStream);
var
  i: Integer;
  LulzMem: PByte;
begin
  S.Seek(FLFANew, soBeginning);
  S.Write(NTHeaders, SizeOf(NTHeaders));
  for i := 0 to High(FSections) do
  begin
    S.Write(FSections[i].Header, SizeOf(TImageSectionHeader));
  end;
  // Zero out some leftovers that may be in the header
  GetMem(LulzMem, $200);
  FillChar(LulzMem^, $200, 0);
  S.Write(LulzMem^, $200);
  FreeMem(LulzMem);
end;

function TPEHeader.TrimHugeSections(Buf: PByte): Cardinal;
var
  i, j, ZeroStart: Integer;
  SectionStart, OldSectionSize, NewSectionSize, Delta: Cardinal;
begin
  Result := 0;
  for i := 0 to NTHeaders.FileHeader.NumberOfSections - 1 do
  begin
    SectionStart := FSections[i].Header.PointerToRawData;
    ZeroStart := -1;
    for j := (FSections[i].Header.SizeOfRawData div 4) - 1 downto 0 do
      if PCardinal(Buf + SectionStart + Cardinal(j) * 4)^ = 0 then
        ZeroStart := j * 4
      else
        Break;

    // We could reduce every single section to its minimal raw size, but having file offset = rva
    // is pretty convenient, so we only trim sections that were obviously bloated up
    if (ZeroStart <> -1) and (FSections[i].Header.SizeOfRawData - Cardinal(ZeroStart) > 1 * 1024 * 1024) then
    begin
      OldSectionSize := FSections[i].Header.SizeOfRawData;
      SectionAlign(OldSectionSize); // Because of Sanitize(), the actual size is always section-aligned in our case

      NewSectionSize := ZeroStart;
      FileAlign(NewSectionSize);
      //Log(ltInfo, 'Reducing ' + PAnsiChar(@FSections[i].Header.Name) + Format('ZeroStart: %X, NewSectionSize: %X, OldSize: %X', [ZeroStart, NewSectionSize, OldSectionSize]));
      Delta := OldSectionSize - NewSectionSize;
      Inc(Result, Delta);
      FSections[i].Header.SizeOfRawData := NewSectionSize;
      if i < High(FSections) then
      begin
        Move(Buf[FSections[i + 1].Header.PointerToRawData], Buf[SectionStart + NewSectionSize], FDumpSize - SectionStart - OldSectionSize);
        for j := i + 1 to High(FSections) do
          Dec(FSections[j].Header.PointerToRawData, Delta);
      end;
    end;
  end;
end;

procedure TPEHeader.AddSectionToArray;
begin
  SetLength(FSections, Length(FSections) + 1);
end;

procedure TPEHeader.FileAlign(var V: Cardinal);
var
  Delta: Cardinal;
begin
  Delta := V mod NTHeaders.OptionalHeader.FileAlignment;
  if Delta > 0 then
    Inc(V, NTHeaders.OptionalHeader.FileAlignment - Delta);
end;

procedure TPEHeader.SectionAlign(var V: Cardinal);
var
  Delta: Cardinal;
begin
  Delta := V mod NTHeaders.OptionalHeader.SectionAlignment;
  if Delta > 0 then
    Inc(V, NTHeaders.OptionalHeader.SectionAlignment - Delta);
end;

function TPEHeader.ConvertOffsetToRVAVector(Offset: NativeUInt): NativeUInt;
var
  i: Integer;
begin
	for i := 0 to High(FSections) do
		if (FSections[i].Header.PointerToRawData <= Offset) and ((FSections[i].Header.PointerToRawData + FSections[i].Header.SizeOfRawData) > Offset) then
			Exit((Offset - FSections[i].Header.PointerToRawData) + FSections[i].Header.VirtualAddress);

  Result := 0;
end;

end.
