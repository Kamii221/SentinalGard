rule Possible_Process_Injection_APIs
{
    meta:
        description = "PE file imports a combination of APIs commonly used for process injection (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread) -- present in many legitimate tools too, treat as a heuristic signal, not proof"
        severity = "medium"
    strings:
        $mz = "MZ"
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
    condition:
        $mz at 0 and all of ($a1, $a2, $a3)
}
