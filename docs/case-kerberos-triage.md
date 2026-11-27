# Studium przypadku – triage serii błędów Kerberos

**Pytanie analityka.** Ile odrębnych serii trzeba przejrzeć, gdy wyszukiwanie Kerberos zwraca 15 trafień dla jednego konta?

## Obserwacja

W historii labu znalazłem zdarzenia **4771 z kodem `0x18`**, czyli błędy preautoryzacji Kerberos. Wszystkie trafienia dotyczyły tej samej kombinacji kontrolera, konta i adresu `::1`. Adres wskazywał na źródło lokalne względem kontrolera. W realnym triage’u zawęża to sprawdzenie do procesów, usług i zadań działających na tym hoście.

## Jak uporządkowałem wyniki

Starsza reguła liczyła zdarzenia w stałych dwuminutowych przedziałach. Pięć prób rozłożonych po obu stronach granicy przedziału mogło się podzielić na dwie grupy, z których żadna nie osiągała progu. [Nowa reguła](../detections/kerberos-bruteforce.spl) liczy błędy w ruchomym oknie dwóch minut dla każdego zdarzenia. [Panel serii](../dashboard/kerberos-series.xml) grupuje nakładające się okna dla tej samej kombinacji kontrolera, adresu i konta.

| Seria według kolejności zdarzeń | Najwyższa liczba błędów w 2 min | Okna, które osiągnęły próg |
|---|---:|---:|
| A | 15 | 11 |
| B | 8 | 4 |

Łącznie **15 okien dało 2 serie do sprawdzenia**. Szczyt opisuje największą liczbę błędów w pojedynczym oknie. Liczba okien mówi, ile wierszy spełniło próg w wyszukiwaniu szczegółowym. Okna się nakładają, więc ich liczników nie sumuję jako liczby prób.

## Decyzja triage

1. **Potwierdzam źródło.** Przy `::1` sprawdzam, czy dany host wykonywał zadanie lub usługę z zapisanymi poświadczeniami i czy w tym czasie zmieniono hasło.
2. **Sprawdzam, czy wzorzec dotyczy wielu kont.** W historycznych logach z tego labu [reguła podejrzenia password sprayingu](kerberos-password-spray.md) nie przekroczyła progu. Przypadek dodatni tej reguły potwierdziłem na danych syntetycznych.
3. **Sprawdzam dalszy przebieg.** W [widoku triage konta](account-triage.md) szukam wydania TGT po błędzie oraz zmian uprawnień. Wydanie TGT i zmiana grupy to osobne zdarzenia do zweryfikowania. Sama chronologia nie dowodzi wspólnej przyczyny.

**Co uzasadniałoby eskalację?** Niewyjaśnione próby, brak zatwierdzonej zmiany lub odnotowany późniejszy dostęp zwiększają potrzebę dalszej analizy. W zgłoszeniu podaję przedział czasu, konto, adres, kontroler, typy zdarzeń i wynik sprawdzenia zmian. Do potwierdzenia sesji szukam zdarzeń logowania na właściwym hoście.

## Co zostało sprawdzone w Splunku

- **Logi historyczne.** Reguła zwróciła 15 okien, a dashboard pogrupował je w dwie serie. Oś triage wyświetliła błędy 4771 i zmiany członkostwa po dopasowaniu SID.
- **Próbki syntetyczne.** Test reguły Kerberos przeszedł **5/5**, w tym przypadek przecinający granicę dawnego przedziału. Test korelacji TGT przeszedł **9/9**. W przypadku dodatnim Splunk powiązał wydanie TGT z błędem sprzed 35 sekund przy zgodnym koncie, kontrolerze i adresie.

[Instrukcja odtworzenia weryfikacji](kerberos-bruteforce.md) · [Microsoft Learn – zdarzenie 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
