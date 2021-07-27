/*
Resmi Sitelere Atılan Fake Siteleri Tespit Edebilmek Adına
*/

rule fakeSite : web
 {
    meta:
        Yazar = "Hasan Ali Yildir"
    strings:

        $url_1 = ".xyz" nocase
        $url_2 = ".biz" nocase
        $url_3 = ".travel" nocase
        $url_4 = ".ru" nocase
        $url_5 = ".onion" nocase

        $text_1= "click" nocase
        $text_2= "check" nocase
        $text_3= "password" nocase
        $text_4= "click" nocase
        $text_5= "contact" nocase   
    condition:
        any of ($url*) and
        any of ($text*)
}
