rule Explorer_Check_Size {
    meta:
        description = "Ortalama boyut disi explorer.exe"
        author = "Hasan Ali Yildir"
    condition:
        uint16(0) == 0x5a4d
        and filename == "explorer.exe"
        and ( filesize < 1000KB or filesize > 3000KB )
}

rule Chorome_Check_Size {
    meta:
        description = "Ortalama boyut disi chrome.exe"
        author = "Hasan Ali Yildir"
    condition:
        uint16(0) == 0x5a4d
        and filename == "chrome.exe"
        and ( filesize < 500KB or filesize > 1300KB )
}

rule Firefox_Check_Size {
    meta:
        description = "Ortalama boyut disi firefox.exe"
        author = "Hasan Ali Yildir"
    condition:
        uint16(0) == 0x5a4d
        and filename == "firefox.exe"
        and ( filesize < 265KB or filesize > 910KB )
}