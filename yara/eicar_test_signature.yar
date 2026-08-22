rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test file -- the industry-standard, harmless signature used to verify AV engines detect something (not real malware)"
        severity = "critical"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
