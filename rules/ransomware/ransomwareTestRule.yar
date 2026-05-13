rule ransomwareTestRule
{
    strings:
        $a = "RANSOMVIRUS"
    condition:
        $a
}