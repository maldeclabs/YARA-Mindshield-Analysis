rule ransomware_globeimposter_windows_check_2 {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-07-11"
        version = "1"
        description = "Detects win.globeimposter."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.globeimposter"
        malpedia_rule_date = "20230705"
        malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
        malpedia_version = "20230715"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { ff15???????? 03c7 50 ff15???????? 85c0 743b 8b7c2410 }
            // n = 7, score = 700
            //   ff15????????         |                     
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   743b                 | je                  0x3d
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]

        $sequence_1 = { c1e008 33c8 8bc2 c1e808 23c5 }
            // n = 5, score = 700
            //   c1e008               | shl                 eax, 8
            //   33c8                 | xor                 ecx, eax
            //   8bc2                 | mov                 eax, edx
            //   c1e808               | shr                 eax, 8
            //   23c5                 | and                 eax, ebp

        $sequence_2 = { 58 e9???????? 7904 6af6 ebf4 }
            // n = 5, score = 700
            //   58                   | pop                 eax
            //   e9????????           |                     
            //   7904                 | jns                 6
            //   6af6                 | push                -0xa
            //   ebf4                 | jmp                 0xfffffff6

        $sequence_3 = { 33c8 8bc2 334e10 c1e810 23c5 }
            // n = 5, score = 700
            //   33c8                 | xor                 ecx, eax
            //   8bc2                 | mov                 eax, edx
            //   334e10               | xor                 ecx, dword ptr [esi + 0x10]
            //   c1e810               | shr                 eax, 0x10
            //   23c5                 | and                 eax, ebp

        $sequence_4 = { 33d2 0fafc6 2bf8 0fb7c1 c1e710 0bf8 8bc7 }
            // n = 7, score = 700
            //   33d2                 | xor                 edx, edx
            //   0fafc6               | imul                eax, esi
            //   2bf8                 | sub                 edi, eax
            //   0fb7c1               | movzx               eax, cx
            //   c1e710               | shl                 edi, 0x10
            //   0bf8                 | or                  edi, eax
            //   8bc7                 | mov                 eax, edi

        $sequence_5 = { 6ac4 58 eb2f 56 ff750c 8b7510 }
            // n = 6, score = 700
            //   6ac4                 | push                -0x3c
            //   58                   | pop                 eax
            //   eb2f                 | jmp                 0x31
            //   56                   | push                esi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]

        $sequence_6 = { 0f6e7608 0ff4f0 0f6e7e0c 0ff4f8 0fd4ca }
            // n = 5, score = 700
            //   0f6e7608             | movd                mm6, dword ptr [esi + 8]
            //   0ff4f0               | pmuludq             mm6, mm0
            //   0f6e7e0c             | movd                mm7, dword ptr [esi + 0xc]
            //   0ff4f8               | pmuludq             mm7, mm0
            //   0fd4ca               | paddq               mm1, mm2

        $sequence_7 = { 8bef 8bf0 8b06 8d7604 }
            // n = 4, score = 700
            //   8bef                 | mov                 ebp, edi
            //   8bf0                 | mov                 esi, eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d7604               | lea                 esi, [esi + 4]

        $sequence_8 = { 83c0fc 3918 7506 83e804 4f 75f6 }
            // n = 6, score = 700
            //   83c0fc               | add                 eax, -4
            //   3918                 | cmp                 dword ptr [eax], ebx
            //   7506                 | jne                 8
            //   83e804               | sub                 eax, 4
            //   4f                   | dec                 edi
            //   75f6                 | jne                 0xfffffff8

        $sequence_9 = { ff15???????? 85c0 7405 3975fc 7405 6afe 58 }
            // n = 7, score = 700
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   3975fc               | cmp                 dword ptr [ebp - 4], esi
            //   7405                 | je                  7
            //   6afe                 | push                -2
            //   58                   | pop                 eax

    condition:
        7 of them and filesize < 327680
}