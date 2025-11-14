
rule Life360 {
    meta:
        author = "956"
        description = "Yara rule to locate and extract databases relating to Life360."
        category = "Location"
        creation_date = "2025-11-14"
        family = "All"
    strings:
        $db = "L360EventStore.db"
        $db_service = "L360EventStore_service.db"
        $db_failed = "FailedLocationTopic.sqlite"
    condition:
        any of them
}

rule VulgarWords {
    meta:
        author = "956"
        description = "Yara rule to locate the Vulgar Words database on iOS devices."
        category = "Other"
        creation_date = "2025-11-14"
        family = "iOS"
    strings:
        $VulgarWords_db = "VulgarWordUsage.db"
    condition:
        $VulgarWords_db
}

/*

// This can be important but because it is a LevelDB, there are a lot of files associated with it so it can get messy.
rule SemanticLocation {
    meta:
        author = "956"
        description = "Yara rule to locate database relating to Google Timeline."
        category = "Location"
        creation_date = "2025-11-14"
        family = "All"
    strings:
        $rawsignal_db = "app_semanticlocation_rawsignal_db"
    condition:
        any of them
}

*/


/*

Examples:
    strings:
        $hex_example = {AA BB 11 22}
        $regex_example = /foo./is
        $string_example = "foobar" nocase

        notes:
            wildcards 
                ?   - Place holder character
                ~   - Not operator (ex. { F4 23 ~00 62 B4 } will match only if the byte is not 00)
                []  - Jumps (ex. { F4 23 [4-6] 62 B4 } will match any aribitrary sequence from 4 to 6 bytes. Starts with F4 23 and ends with 62 B4, making the total length 8-10 bytes)
                    - [-] Would match from 0 to infinite. Could be useful if you have a known starting byte cluster and a known ending byte cluster but the middle is unknown data.
                |   - Or operator (ex. { F4 23 ( 62 B4 | 56 ) 45 } would match F42362B445 or F4235645)
            modifiers
                nocase  - Case Insensitive (ex. $text_string = "foobar" nocase)
                wide    - If the characters are encoded as two bytes (ex. $wide_string = "Borland" wide)
                xor     - Single byte xor (ex. $xor_string = "This program cannot" xor --- would match "This program cannot", "Uihr!qsnfs`l!b`oonu", "Vjkq\"rpmepco\"acllmv")
                base64  - Will search the string with 3 permutations of Base64 encoding (ex. $a = "This program cannot" base64)
                fullword- The string will match only if it appears in the file delimited by non-alphanumeric characters.
            regex
                - Starts with /
                i - case insensitive
                s - makes the . match new-line characters
            private - will be ignored (ex. $text_string = "foobar" private)

    conditions
        any of them
        all of them
        filesize //ex. filesize > 100KB
        uint16(0) == 0x5A4D // Checks the PE header (Portable Executable)

*/