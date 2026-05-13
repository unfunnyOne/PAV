rule trojanTestRule
{
    strings:
        $a = "TROJANVIRUS"
    condition:
        $a
}