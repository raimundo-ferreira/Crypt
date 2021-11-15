unit uCrypt;

interface

type
  TCrypt = class
  private
    class function Encode(const aString: AnsiString): AnsiString;
    class function Decode(const aString: AnsiString): AnsiString;
    class function PreProcess(const aString: AnsiString): AnsiString;
    class function PostProcess(const aString: AnsiString): AnsiString;
    class function InternalDecrypt(const aString: AnsiString; aKeySecret: Word): AnsiString;
    class function InternalEncrypt(const aString: AnsiString; aKeySecret: Word): AnsiString;
  public
    class function Decrypt(const aString: AnsiString; aKeySecret: Word): AnsiString;
    class function Encrypt(const aString: AnsiString; aKeySecret: Word): AnsiString;
  end;

implementation

const
  C1 = 52845;
  C2 = 22719;

{ TCrypt }

class function TCrypt.Decode(const aString: AnsiString): AnsiString;
const
  Map: array[AnsiChar] of Byte = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53,
    54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2,
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
    46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0);
var
  I: LongInt;
begin
  case Length(aString) of
    2:
    begin
      I := Map[aString[1]] + (Map[aString[2]] shl 6);
      SetLength(Result, 1);
      Move(I, Result[1], Length(Result))
    end;
    3:
    begin
      I := Map[aString[1]] + (Map[aString[2]] shl 6) + (Map[aString[3]] shl 12);
      SetLength(Result, 2);
      Move(I, Result[1], Length(Result))
    end;
    4:
    begin
      I := Map[aString[1]] + (Map[aString[2]] shl 6) + (Map[aString[3]] shl 12) +
        (Map[aString[4]] shl 18);
      SetLength(Result, 3);
      Move(I, Result[1], Length(Result))
    end;
  end;
end;

class function TCrypt.Encode(const aString: AnsiString): AnsiString;
const
  Map: array[0..63] of AnsiChar = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz0123456789+/';
var
  I: LongInt;
begin
  I := 0;
  Move(aString[1], I, Length(aString));
  case Length(aString) of
    1:
      Result := Map[I mod 64] + Map[(I shr 6) mod 64];
    2:
      Result := Map[I mod 64] + Map[(I shr 6) mod 64] +
        Map[(I shr 12) mod 64];
    3:
      Result := Map[I mod 64] + Map[(I shr 6) mod 64] +
        Map[(I shr 12) mod 64] + Map[(I shr 18) mod 64]
  end;
end;

class function TCrypt.Decrypt(const aString: AnsiString;
  aKeySecret: Word): AnsiString;
begin
  Result := InternalDecrypt(PreProcess(aString), aKeySecret)
end;

class function TCrypt.Encrypt(const aString: AnsiString;
  aKeySecret: Word): AnsiString;
begin
  Result := PostProcess(InternalEncrypt(aString, aKeySecret))
end;

class function TCrypt.InternalDecrypt(const aString: AnsiString;
  aKeySecret: Word): AnsiString;
var
  I: Word;
  Seed: Word;
begin
  Result := aString;
  Seed := aKeySecret;
  for I := 1 to Length(Result) do
  begin
    Result[I] := AnsiChar(Byte(Result[I]) xor (Seed shr 8));
    Seed := (Byte(aString[I]) + Seed) * Word(C1) + Word(C2)
  end;
end;

class function TCrypt.InternalEncrypt(const aString: AnsiString;
  aKeySecret: Word): AnsiString;
var
  I: Word;
  Seed: Word;
begin
  Result := aString;
  Seed := aKeySecret;
  for I := 1 to Length(Result) do
  begin
    Result[I] := AnsiChar(Byte(Result[I]) xor (Seed shr 8));
    Seed := (Byte(Result[I]) + Seed) * Word(C1) + Word(C2)
  end;
end;

class function TCrypt.PreProcess(const aString: AnsiString): AnsiString;
var
  SS: AnsiString;
begin
  SS := AnsiString(aString);
  Result := '';
  while SS <> '' do
  begin
    Result := Result + Decode(Copy(SS, 1, 4));
    Delete(SS, 1, 4)
  end;
end;

class function TCrypt.PostProcess(const aString: AnsiString): AnsiString;
var
  SS: AnsiString;
begin
  SS := AnsiString(aString);
  Result := '';
  while SS <> '' do
  begin
    Result := Result + Encode(Copy(SS, 1, 3));
    Delete(SS, 1, 3)
  end;
end;

end.
