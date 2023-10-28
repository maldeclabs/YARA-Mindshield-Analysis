rule win_globeimposter_man_2023_03_09
{
    meta:
        author = "vitor mob"
        date = "2023-03-09"
        version = "1"
        description = "Detects win.satana"
		hash_sha256 = "f433f2bb54439aef2f42823d954bcd61a7b3e537b220cc7f8028ab49faa5c01b"
		malware_bazaar = "https://bazaar.abuse.ch/sample/f433f2bb54439aef2f42823d954bcd61a7b3e537b220cc7f8028ab49faa5c01b"

	strings:
		$sigWRich = "WRich" wide ascii
        $path = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii
		$sequence = "0123456789ABCDEF" wide ascii

	condition:
		$sigWRich and $path and $sequence
	
}

rule win_globeimposter_man_2023_03_09_hash {
    meta:
        description = "Check SHA256 hash"
    condition:
        hash.sha256(0, filesize) == "f433f2bb54439aef2f42823d954bcd61a7b3e537b220cc7f8028ab49faa5c01b"
}