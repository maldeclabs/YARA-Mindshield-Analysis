rule linux_GonnaCry_man_2023 {
    meta:
        author = "vitor mob"
        malware_bazaar = "https://bazaar.abuse.ch/sample/f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac/#yara"
        hash_sha256 = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
        date = "2023-07-25 "

    strings:
	   $path = "/home/tarcisio/tests/" wide ascii
	   $extentions = "doc docx xls xlsx ppt pptx pst ost msg eml vsd vsdx txt csv rtf wks wk1 pdf dwg onetoc2 snt jpeg jpg docb docm dot dotm dotx xlsm xlsb xlw xlt xlm xlc xltx xltm pptm pot pps ppsm ppsx ppam potx potm edb hwp 602 sxi sti sldx sldm sldm vdi vmdk vmx gpg aes ARC PAQ bz2 tbk bak tar tgz gz 7z rar zip backup iso vcd bmp png gif raw cgm tif tiff nef psd ai svg djvu m4u m3u mid wma flv 3g2 mkv 3gp mp4 mov avi asf mpeg vob mpg wmv fla swf wav mp3 sh class jar java rb asp php jsp brd sch dch dip pl vb vbs ps1 bat cmd js asm h pas cpp c cs suo sln ldf mdf ibd myi myd frm odb dbf db mdb accdb sql sqlitedb sqlite3 asc lay6 lay mml sxm otg odg uop std sxd otp odp wb2 slk dif stc sxc ots ods 3dm max 3ds uot stw sxw ott odt pem p12 csr crt key pfx der" wide ascii
	   $generate_key = {
            E8 59 EE FF FF        // call    _malloc
            48 89 45 F0           // mov     [rbp+var_10], rax
            48 83 7D F0 00        // cmp     [rbp+var_10], 0
            74 71                 // jz      short loc_22A3
            C7 45 FC 00 00 00 00  // mov     [rbp+var_4], 0
            EB 50                 // jmp     short loc_228B
            // ---------------------------------------------------------------------------
            // loc_223B:
            E8 F0 EF FF FF        // call    _rand
            48 63 D0              // movsxd  rdx, eax
            48 69 D2 D3 20 0D D2  // imul    rdx, 0FFFFFFFFD20D20D3h
            48 C1 EA 20           // shr     rdx, 20h
            01 C2                 // add     edx, eax
            89 D1                 // mov     ecx, edx
            C1 F9 06              // sar     ecx, 6
            99                    // cdq
            29 D1                 // sub     ecx, edx
            89 CA                 // mov     edx, ecx
            89 55 EC              // mov     [rbp+var_14], edx
            8B 55 EC              // mov     edx, [rbp+var_14]
            6B D2 4E              // imul    edx, 4Eh ; 'N'
            29 D0                 // sub     eax, edx
            89 45 EC              // mov     [rbp+var_14], eax
            8B 45 FC              // mov     eax, [rbp+var_4]
            48 63 D0              // movsxd  rdx, eax
            48 8B 45 F0           // mov     rax, [rbp+var_10]
            48 01 C2              // add     rdx, rax
            8B 45 EC              // mov     eax, [rbp+var_14]
            48 98                 // cdqe
            48 8D 0D DF 2E 00 00  // lea     rcx, charset_10485 ; "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM"...
			} 
    condition:
        any of them
}
