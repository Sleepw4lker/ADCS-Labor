Function New-RandomPassword {

    [cmdletbinding()]
    param (
        [int]$PasswordLength = 8
    )

    process {

        # https://activedirectoryfaq.com/2017/08/creating-individual-random-passwords/
        
        function Get-RandomCharacters {

            param(
                $length, $characters
            )

            $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
            $private:ofs="" 

            return [String]$characters[$random]
        }

        function Get-RandomizedString {

            param(
                [string]$inputString
            )

            $characterArray = $inputString.ToCharArray()   
            $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
            $outputString = -join $scrambledStringArray

            return $outputString 
        }

        $password = Get-RandomCharacters -length ($PasswordLength - 3) -characters 'abcdefghiklmnoprstuvwxyz'
        $password += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
        $password += Get-RandomCharacters -length 1 -characters '1234567890'
        $password += Get-RandomCharacters -length 1 -characters '!"§$%&/()=?}][{@#*+'

        $password = Get-RandomizedString -inputString $password

        return $password

    }
    
}