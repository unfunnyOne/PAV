rule keyloggerTestRule
{
    strings:
        $a = "KEYLOGGERVIRUS"
    condition:
        $a
}