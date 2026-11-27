# Triage konta w Splunku

[Dashboard Classic XML](../dashboard/account-triage.xml) przedstawia chronologię zdarzeń dotyczących konta. Obejmuje niepowodzenia preautoryzacji Kerberos (4771), żądania TGT (4768) oraz zmiany członkostwa w grupach (4728, 4729, 4732, 4733, 4756 i 4757).

| Pole | Jak je czytać |
|---|---|
| `role` | Konto, dla którego żądano biletu, wykonawca zmiany grupy albo członek wskazany przez SID. |
| `related_failure` | Czas ostatniego błędu 4771 z kodem `0x18` przed wydaniem TGT, widoczny tylko dla tego samego kontrolera, adresu i konta oraz odstępu do 10 minut. |
| `seconds_since_failure` | Odstęp między powiązanym błędem i wydaniem TGT. |

Kolejność zdarzeń sama nie wskazuje przyczyny. Wydanie TGT potwierdza wynik żądania biletu. Do potwierdzenia sesji szukaj również zdarzeń logowania na właściwym hoście. Korelacja obejmuje tylko zdarzenia z wybranego zakresu czasu. Jeśli zaczynasz od konkretnego wydania TGT, ustaw zakres zaczynający się przynajmniej 10 minut wcześniej.

Wpisz nazwę konta w postaci `sAMAccountName`, bez prefiksu domeny. Jeśli analizujesz zmiany dotyczące konta jako **członka** grupy, podaj jego dokładny SID. Gdy dziennik tekstowy zawiera rozpoznaną nazwę członka zamiast SID, panel może pokazać to zdarzenie po dopasowaniu wykonawcy. Dopasowanie członka wymaga SID obecnego w logu. Gdy kilka domen używa tej samej krótkiej nazwy konta, weryfikuj domenę w zdarzeniach źródłowych.

## Instalacja i sprawdzenie

1. W Splunk Web utwórz prywatny **Classic Dashboard** o ID `domainwatch_account_triage`.
2. W **Edit → Source** wklej cały [XML dashboardu](../dashboard/account-triage.xml) i zapisz.
3. Wpisz znaną nazwę konta, ustaw zakres obejmujący historyczne zdarzenia i kliknij **Submit**. Porównaj kilka wierszy z logami Security w **Search & Reporting**. Gdy chcesz zobaczyć zmiany grup dotyczące członka, podaj SID z pola `member_identity` w dashboardzie zmian grup i ponownie użyj **Submit**.

Uruchomienie panelu w Splunku potwierdziło wyświetlanie błędów 4771 po nazwie konta oraz zmian 4728 i 4729 po SID członka.

### Test powiązań TGT

W katalogu repozytorium uruchom `python3 tests/account_triage_search.py`. Wklej wypisane zapytanie do **Search & Reporting**, wybierz **Last 24 hours** i sprawdź dziewięć przypadków. `actual_seconds=-1` oznacza brak powiązania z poprzednim błędem. Przypadek `same-host-ip` ma zwrócić `35` sekund.

Test syntetyczny w Splunku zakończył się wynikiem **9/9 PASS**. W przypadku zgodnego konta, kontrolera i adresu odstęp do poprzedniego błędu wyniósł 35 sekund. Przypadki kontrolne potwierdziły brak powiązania przy innym adresie lub kontrolerze, nieudanym żądaniu oraz po upływie 10 minut.

[Microsoft Learn – zdarzenie 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768) · [zdarzenie 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771) · [zdarzenie 4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)
