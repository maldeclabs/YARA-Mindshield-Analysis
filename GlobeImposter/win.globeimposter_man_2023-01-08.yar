import "hash"

rule win_globeimposter_man_2023_01_08
{
    meta:
        author = "vitor mob"
        date = "2023-01-08"
        version = "1"
        description = "Detects win.satana"
        hash_sha256 = "d16518abb5dc4d76f4f423d02b0b8c99fe5edb89edf3c60ca64ebb2a6879a15e"
        malware_bazaar = "https://bazaar.abuse.ch/sample/d16518abb5dc4d76f4f423d02b0b8c99fe5edb89edf3c60ca64ebb2a6879a15e/"

    strings:
		$sigRich = "Rich" wide ascii
        $path = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii
		$sequence = "0123456789ABCDEF" wide ascii

    condition:
        $sigRich and $path and $sequence
}

rule win_globeimposter_man_2023_hash {
    meta:
        description = "Check SHA256 hash"
    condition:
        hash.sha256(0, filesize) == "d16518abb5dc4d76f4f423d02b0b8c99fe5edb89edf3c60ca64ebb2a6879a15e"
}
