VERSION 5.00
Begin VB.Form fSynthTab
  Caption = "Sekmeler"
  ClientWidth = 4000
  ClientHeight = 2000
  Begin TabDlg.SSTab SSTab1
    Left = 105
    Top = 105
    Width = 3600
    Height = 1600
    Tab = 1
    TabCaption(0) = "General"
    TabCaption(1) = "Detail"
    TabCaption(2) = "Summary"
    Begin VB.TextBox txtGeneral
      Left = 200
      Top = 600
      Width = 1000
      Height = 300
    End
    Begin VB.Frame fraDetail
      Left = 200
      Top = 900
      Width = 2000
      Height = 500
      Begin VB.Label lblIc
        Left = 20
        Top = 20
        Width = 500
        Height = 200
        Caption = "ic"
      End
    End
  End
End
