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

    procedure Align(var V: Cardinal);
  public
    NTHeaders: TImageNTHeaders;

    constructor Create(Data: PByte);

    function CreateSection(const Name: AnsiString; Size: Cardinal): PPESection;
    procedure DeleteSection(Idx: Integer);
    function GetSectionByVA(V: Cardinal): PPESection;
    procedure AddSectionToArray;

    function ConvertOffsetToRVAVector(Offset: NativeUInt): NativeUInt;

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
  Align(FSections[Idx - 1].Header.Misc.VirtualSize);

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
  // Must have write access in code section
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
  GetMem(LulzMem, $200);
  FillChar(LulzMem^, $200, 0);
  S.Write(LulzMem^, $200);
  FreeMem(LulzMem);
end;

procedure TPEHeader.AddSectionToArray;
begin
  SetLength(FSections, Length(FSections) + 1);
end;

procedure TPEHeader.Align(var V: Cardinal);
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
