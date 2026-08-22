rule Suspicious_Script_Download_Cradle
{
    meta:
        description = "Script contains a common download-and-execute pattern (e.g. IEX(New-Object Net.WebClient).DownloadString / -EncodedCommand)"
        severity = "high"
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "IEX(" nocase
        $s3 = "Invoke-Expression" nocase
        $s4 = "-EncodedCommand" nocase
        $s5 = "FromBase64String" nocase
    condition:
        2 of them
}
