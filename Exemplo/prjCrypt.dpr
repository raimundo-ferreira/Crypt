program prjCrypt;

uses
  System.StartUpCopy,
  FMX.Forms,
  uMain in 'uMain.pas' {frmCrypt},
  uCrypt in '..\src\uCrypt.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmCrypt, frmCrypt);
  Application.Run;
end.
