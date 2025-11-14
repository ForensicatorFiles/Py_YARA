
rule Life360 {
    meta:
        author = "Forensicator956"
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
        author = "Forensicator956"
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
        author = "Forensicator956"
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
