rule trojanTestRule2
{
    strings:
        $a = "TROJANVIRUS"
    condition:
        $a
}