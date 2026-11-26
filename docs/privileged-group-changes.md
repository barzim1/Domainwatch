# Zmiany członkostwa w grupach administracyjnych

[Reguła SPL](../detections/privilege-escalation.spl) pokazuje, kto zmienił członkostwo, jakiej grupy dotyczyła zmiana i którego członka dodano lub usunięto. Zdarzenie może wynikać z zatwierdzonej pracy administratora. Potwierdź kontekst przed eskalacją.

| Zakres grupy | Dodanie | Usunięcie |
|---|---:|---:|
| Globalna | 4728 | 4729 |
| Lokalna | 4732 | 4733 |
| Uniwersalna | 4756 | 4757 |

Reguła identyfikuje wbudowaną grupę Administrators po SID `S-1-5-32-544` oraz Domain Admins, Schema Admins i Enterprise Admins po końcówkach domenowych SID `512`, `518` i `519`. Jeśli SID jest niedostępny, sprawdza standardową angielską nazwę grupy i oznacza wynik jako `NAME`. Potwierdź wtedy SID w AD lub w źródłowym zdarzeniu. Do monitorowania grup delegowanych potrzebna jest osobna lista SID. Reguła analizuje bezpośrednie zmiany członkostwa.

## Weryfikacja w Splunku

1. Potwierdź, że na monitorowanym hoście audyt udanych operacji **Audit Security Group Management** jest włączony. Sprawdź w Splunku rzeczywisty indeks i źródło dziennika Security. Reguła domyślnie używa `index=main` oraz standardowych oznaczeń źródła lub kanału. W razie różnic dostosuj pierwszy wiersz do konfiguracji labu.
2. Wybierz przedział z historycznymi zdarzeniami lub zaimportuj syntetyczne próbki do testowego indeksu. Sprawdź wyniki według poniższej tabeli.
3. Porównaj `actor` z sekcją **Subject**, `member` i `member_identity` z **Member**, a `group_name` i `group_sid` z **Group**. Gdy `member` ma wartość `-`, posłuż się `member_identity`. Przy braku wyników wyszukaj same identyfikatory zdarzeń z tabeli i sprawdź `_raw`, zanim zmienisz filtr grup.
4. Jeśli używasz istniejącego panelu dashboardu, wklej do niego aktualne zapytanie i sprawdź kolumny po zapisaniu.

| Próbka | Oczekiwany wynik |
|---|---|
| 4728 z SID Domain Admins, inny wykonawca niż dodawany członek | `DODANO`, `SID`, osobne wartości wykonawcy i członka |
| 4729 z SID Domain Admins | `USUNIĘTO`, `SID` |
| 4732 i 4733 z SID wbudowanych Administrators | Odpowiednio `DODANO` i `USUNIĘTO`, oba `SID` |
| 4756 i 4757 z SID Enterprise Admins | Odpowiednio `DODANO` i `USUNIĘTO`, oba `SID` |
| 4732 w angielskim tekście, nazwa Administrators, brak SID grupy | `DODANO`, `NAME` |
| 4732 z niestandardowym SID i nazwą Administrators | Brak wyniku |
| 4728 dotyczący zwykłej grupy | Brak wyniku |

## Wynik weryfikacji w Splunku

Zapytanie według samych identyfikatorów zdarzeń zwróciło 22 wyniki. Pełna reguła zwróciła 4 dopasowania.

| Identyfikator zdarzenia | Typ operacji | Liczba dopasowań |
|---|---|---:|
| 4728 | Dodanie do globalnej grupy zabezpieczeń | 2 |
| 4729 | Usunięcie z globalnej grupy zabezpieczeń | 1 |
| 4732 | Dodanie do lokalnej grupy zabezpieczeń | 1 |

## Triage

W trakcie triage sprawdź zgłoszenie zmiany, tożsamość wykonawcy i członka oraz czas operacji. Dodanie, po którym szybko nastąpiło usunięcie, nadal wymaga sprawdzenia, czy w międzyczasie użyto przyznanego dostępu. Jeśli masz `SubjectLogonId`, możesz skorelować zmianę z logowaniem 4624 na tym samym hoście.

[Microsoft Learn – Audit Security Group Management](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management) · [Microsoft Learn – pola zdarzenia 4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732) · [Microsoft Learn – grupy zabezpieczeń AD](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
