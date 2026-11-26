# Seria błędów preautoryzacji Kerberos

[Reguła SPL](../detections/kerberos-bruteforce.spl) wykrywa co najmniej pięć zdarzeń 4771 z kodem `0x18` w ruchomym oknie dwóch minut dla tej samej kombinacji kontrolera domeny, konta i adresu klienta. Kod oznacza nieprawidłową preautoryzację, zwykle podanie błędnego hasła. Jedną z legalnych przyczyn są usługi próbujące używać zapisanego wcześniej hasła po jego zmianie.

Przy każdej pasującej próbie zapytanie liczy błędy z dwóch minut poprzedzających tę próbę wraz z bieżącym zdarzeniem. Dzięki temu seria po obu stronach granicy pełnej minuty nadal może przekroczyć próg. Kolejne pasujące wiersze mogą opisywać tę samą serię. `first_failure` to czas najstarszego błędu uwzględnionego w danym wierszu. `::ffff:192.0.2.10` i `192.0.2.10` są liczone jako ten sam adres. Grupa wyników jest liczona osobno dla każdego kontrolera domeny.

## Weryfikacja

1. W katalogu repozytorium uruchom `python3 tests/kerberos_bruteforce_search.py` i wklej całe wypisane zapytanie do **Search & Reporting**. Test używa zdarzeń syntetycznych tworzonych na czas wyszukiwania.
2. Oczekuj pięciu wierszy `PASS`: seria na granicy dawnych przedziałów, szersze odstępy, inny kod, podział prób pomiędzy kontrolery i podział prób pomiędzy adresy. Pierwszy przypadek sprawdza również mieszany zapis adresu IP, zapis kodu w dziesiętnym formacie i ekstrakcję pól z XML.
3. Uruchom właściwą regułę na historycznych logach 4771. Jeżeli nie widzisz trafień, sprawdź, czy kontroler wysyła zdarzenia z audytu niepowodzeń **Audit Kerberos Authentication Service** oraz czy Splunk ma pola `Failure_Code`, `Account_Name` i `Client_Address` lub dane XML.

## Triage

Sprawdź, jakie urządzenie używało adresu źródłowego i czy błędy rozpoczęły się po zmianie hasła. Poszukaj podobnych zdarzeń dla innych kont z tego samego adresu oraz udanych zdarzeń 4768 dla tego konta po serii błędów. `::1` oznacza próbę z samego kontrolera domeny, więc w takim przypadku sprawdź lokalne procesy i usługi. Próg pięciu prób pochodzi z labu i wymaga kalibracji przed wdrożeniem w szerszym środowisku.

[Microsoft Learn – zdarzenie 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771) · [Splunk – streamstats](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.1/search-commands/streamstats)
