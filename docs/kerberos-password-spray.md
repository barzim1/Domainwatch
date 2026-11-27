# Podejrzenie password sprayingu przez Kerberos

[Reguła SPL](../detections/kerberos-password-spray.spl) wykrywa pierwsze osiągnięcie progu **5 różnych kont w ciągu 5 minut** dla tej samej pary kontroler domeny i adres klienta. Liczy błędy preautoryzacji Kerberos z dziennika Security (4771, `0x18`). Seria błędów jednego konta nadal należy do zakresu [oddzielnej reguły](../detections/kerberos-bruteforce.spl).

Próg jest punktem startowym dla labu. Zdarzenie 4771 opisuje niepowodzenie logowania i nie pozwala stwierdzić, czy hasło powtórzyło się między kontami. Współdzielone adresy klientów i błędna konfiguracja usług również mogą powodować trafienia. Reguła liczy próby widziane przez każdy kontroler osobno, więc rozproszenie zdarzeń między kontrolerami może obniżyć licznik. Przy `::1` sprawdź procesy na kontrolerze, który zapisał zdarzenie.

## Weryfikacja w Splunku

1. W katalogu repozytorium uruchom `python3 tests/kerberos_password_spray_search.py`. Wklej wypisane zapytanie do **Search & Reporting**.
2. Oczekuj sześciu wierszy `PASS`. Przypadek dodatni zawiera pięć kont i kolejny błąd ponad progiem. Reguła ma zwrócić jeden wiersz w momencie osiągnięcia progu. Przypadki kontrolne weryfikują wielokrotne próby jednego konta, rozdzielenie prób przez adres i kontroler, wyjście poza okno oraz inny kod błędu.
3. Uruchom właściwą regułę na historycznych logach. Brak trafienia jest oczekiwany, jeśli w logach są wyłącznie serie dotyczące jednego konta.

## Triage

Sprawdź, czy `Client_Address` należy do jednego urządzenia, czy może reprezentować kilka urządzeń. Porównaj listę `accounts` z rolą maszyny i typowym ruchem. Sprawdź udane żądania TGT (4768) dla tych samych kont i adresu po serii błędów. Próg i zakres czasu dostosuj do zachowania konkretnego środowiska.

[Microsoft Learn – zdarzenie 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771) · [MITRE ATT&CK – T1110.003](https://attack.mitre.org/techniques/T1110/003/)
