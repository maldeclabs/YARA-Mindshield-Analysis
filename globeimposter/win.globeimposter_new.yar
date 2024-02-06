rule ransomware_globeimposter_windows_check_1
{
    meta:
        author = "rivitna"
        family = "ransomware.globeimposter.windows"
        description = "GlobeImposter ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $a1 = "\x00010001\x00" ascii
        $a2 = "\x000123456789ABCDEF\x00" ascii
        $a3 = { 33 C0 [0-1] EB 05 B8 00 AF FF FF C2 0? }

        $b1 = "\x00Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\x00" wide
        $b2 = "\x00LOCALAPPDATA\x00" wide 
        $b3 = "\x00APPDATA\x00" wide
        $b4 = "\x00public\x00" wide
        $b5 = "\x00ALLUSERSPROFILE\x00" wide

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (filesize < 100000) and
        (
            (all of ($a*)) and
            (3 of ($b*))
        )
}