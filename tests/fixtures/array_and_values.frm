VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC0000F8754DA1}#2.2#0"; "C:\Windows\System32\MSCOMCTL.OCX"
Begin VB.Form fSynthArray
  Caption = "Settings' welcome note"
  ClientWidth = 6000
  ClientHeight = 3000
  MDIChild = -1  'True
  Begin VB.TextBox txtAd
    Index = 2
    Left = 100
    Top = 200
    Width = 1200
    Height = 300
    Locked = -1  'True
  End
  Begin VB.TextBox txtAd
    Index = 0
    Left = 100
    Top = 500
    Width = 1200
    Height = 300
    Locked = 0   'False
  End
  Begin VB.TextBox txtAd
    Index = 1
    Left = 100
    Top = 800
    Width = 1200
    Height = 300
  End
  Begin VB.TextBox txtSerbest
    Left = 0
    Top = 0
    Width = 100
    Height = 100
    BorderStyle = 0  'None
  End
  Begin VB.Line Line1
    BorderColor = &HFFFFFF&
    X1 = 10
    Y1 = 20
    X2 = 10
    Y2 = 120
  End
  Begin VB.Menu mnuDosya
    Caption = "&Dosya"
    Begin VB.Menu mnuCikis
      Caption = "Çýkýþ"
    End
  End
  Begin VB.PictureBox picKutu
    Left = 5
    Top = 6
    Width = 7
    Height = 8
    Visible = 0   'False
    Picture = "fSynthArray.frx":10AA
    BeginProperty Font
      Name = "Arial"
      Size = 8,25
      Weight = 700
    EndProperty
  End
End
Attribute VB_Name = "fSynthArray"
Private Sub Form_Load()
  ' code, not design data
  BeginNotAControl = 1
End Sub
