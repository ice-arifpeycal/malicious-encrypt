$string1 = "IHopeThisIsSecureEnough"
$string2 = "GoodLuckDecrypting"

$bytes1 = [System.Text.Encoding]::UTF8.GetBytes($string1)
$bytes2 = [System.Text.Encoding]::UTF8.GetBytes($string2)

$length = [Math]::Max($bytes1.Length, $bytes2.Length)
$bytes1 = $bytes1 + (New-Object byte[] ($length - $bytes1.Length))
$bytes2 = $bytes2 + (New-Object byte[] ($length - $bytes2.Length))

$keyBytes = @()
for ($i = 0; $i -lt $length; $i++) {
    $keyBytes += $bytes1[$i] -bxor $bytes2[$i]
}

$key = $keyBytes[0..15]

$ivString = "ICECTF{not_flag}"
$ivBytes = [System.Text.Encoding]::UTF8.GetBytes($ivString)

$IV = $ivBytes[0..15]

function Encrypt-String($plainText, $key, $IV) {
    $aes = [System.Security.Cryptography.Aes]::Create() 
    $aes.Key = $key 
    $aes.IV = $IV  
    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV) 
    $plainTextBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText) 
    $encryptedBytes = $encryptor.TransformFinalBlock($plainTextBytes, 0, $plainTextBytes.Length) 
    $aes.Dispose()  
    return [Convert]::ToBase64String($IV + $encryptedBytes)
}

$flagPart1 = ""
$encryptedFlagPart1 = Encrypt-String -plainText $flagPart1 -key $key -IV $IV

$charArray = $encryptedFlagPart1.ToCharArray()

for ($i = 0; $i -lt $charArray.Length - 1; $i += 2) {
    $temp = $charArray[$i]
    $charArray[$i] = $charArray[$i + 1]
    $charArray[$i + 1] = $temp
}

$shuffledFlag = -join $charArray

$flagPart2 = ""

Set-Content -Path "flag1.txt.enc" -Value $shuffledFlag

Write-Output "Flag Part 2: $flagPart2"
