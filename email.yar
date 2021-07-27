rule Email_Oltalama : email
{
  meta:
		Author = "Hasan Ali YILDIR <@tinim123>"
		Description ="Oltalama Ornek Kural"

  strings:
    $eml_1="From:"
    $eml_2="To:"
    $eml_3="Subject:"

    $degisken_1="Merhaba" nocase
    $degisken_1="Sayin kullanici" nocase

    $uzanti_1="Tikla" nocase
    $uzanti_2="Kabul Et" nocase
    $uzanti_3="Onayla" nocase
    $uzanti_4="Buradan" nocase
    $uzanti_5="Simdi" nocase
    $uzanti_6="Sifre Degistir" nocase 

    $lie_1="Unauthorized" nocase
    $lie_2="Expired" nocase
    $lie_3="Deleted" nocase
    $lie_4="Suspended" nocase
    $lie_5="Revoked" nocase
    $lie_6="Unable" nocase

  condition:
    all of ($eml*) and
    any of ($degisken*) and
    any of ($uzanti*) and
    any of ($lie*)
}