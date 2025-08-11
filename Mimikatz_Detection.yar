rule Mimikatz_Detection
{
    meta:
        description = "Detects common Mimikatz strings in memory or files"
        author = "Silas"
        date = "2025-08-11"
        threat = "Credential dumping tool"
    strings:
        $str1 = "sekurlsa::logonpasswords" nocase
        $str2 = "privilege::debug" nocase
        $str3 = "mimikatz" nocase
        $str4 = "kerberos::list" nocase
    condition:
        any of ($str1, $str2, $str3, $str4)
}
