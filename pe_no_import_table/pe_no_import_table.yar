import "pe"

rule pe_no_import_table {
    meta:
        author = "qux"
        description = "Detects exe does not have import table"
        date = "2023-10-05"
        yarahub_reference_md5 = "00000000001111111111222222222233"
        yarahub_uuid = "f2d5b2f7-a391-4db6-be86-124fb343ef62"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    condition:
        pe.is_pe
        and pe.number_of_imports == 0
}