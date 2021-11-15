unit uMain;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.Memo.Types,
  FMX.StdCtrls, FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo;

type
  TfrmCrypt = class(TForm)
    memTexto: TMemo;
    lblTitulo: TLabel;
    btnCrypt: TButton;
    btnDecrypt: TButton;
    memResultado: TMemo;
    procedure btnCryptClick(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmCrypt: TfrmCrypt;

implementation

{$R *.fmx}

uses uCrypt;

const
  SeedKey = 12345;

procedure TfrmCrypt.btnCryptClick(Sender: TObject);
begin
  memResultado.Lines.Clear;
  if not(memTexto.Text.IsEmpty) then
    memResultado.Text := TCrypt.Encrypt(memTexto.Text, SeedKey);
end;

procedure TfrmCrypt.btnDecryptClick(Sender: TObject);
begin
  memResultado.Lines.Clear;
  if not(memTexto.Text.IsEmpty) then
    memResultado.Text := TCrypt.Decrypt(memTexto.Text, SeedKey);
end;

end.
