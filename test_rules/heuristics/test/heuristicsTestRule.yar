rule heuristicsTestRule
{
    strings:
        $a = "IsDebugged"
    condition:
        $a
}