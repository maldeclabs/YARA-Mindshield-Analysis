import "hash"

rule win_globeimposter_auto_2021 {
    meta:
        author = "vitor mob"
        malware_bazaar = "https://bazaar.abuse.ch/sample/750984dff0d13260e17e9bb1a3482f1bae834d6e0de1bcd199028748a9f998dc/"
        hash_sha256 = "750984dff0d13260e17e9bb1a3482f1bae834d6e0de1bcd199028748a9f998dc"
        date = "2021-02-14"

    strings:
        $crypto = "CryptoKeyRights.exe" wide ascii
        $net = ".NET Framework 4" wide ascii
        $sql = "Select School from LecturersProfile where LecturerID = '" wide ascii
        $provider = "Provider = Microsoft.Jet.OLEDB.4.0; Data Source = C:\\Users\\Joey\\Documents\\College.mdb; Persist Security Info = False" wide ascii

    condition:
        any of them
}

rule win_globeimposter_auto_2021_feik_copyright  {
    meta:
        description = "Check for Feik string"
    strings:
        $feik = "2017 Feik" wide ascii
		$inter = "Feik ltd" wide ascii
    condition:
        $feik or $inter
}

rule win_globeimposter_auto_2021_hash {
    meta:
        description = "Check SHA256 hash"
    condition:
        hash.sha256(0, filesize) == "750984dff0d13260e17e9bb1a3482f1bae834d6e0de1bcd199028748a9f998dc"
}

