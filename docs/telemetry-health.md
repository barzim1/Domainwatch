# Stan telemetrii Windows

[Panel stanu telemetrii](../dashboard/telemetry-health.xml) pokazuje osobno Windows Security i Sysmon dla wybranego hosta. Pierwsza kolumna czasowa (`last_ingested`) pokazuje najnowszy czas indeksowania, a druga (`last_event`) najnowszy czas zdarzenia. Obie wartości dotyczą całego kanału i mogą pochodzić z różnych logów.

| Status | Warunek |
|---|---|
| AKTYWNE | Najnowsze indeksowanie i najnowszy czas zdarzenia są młodsze niż 30 min. |
| CISZA | Z ostatnich 24 h są logi, ale ostatnie indeksowanie było co najmniej 30 min temu. |
| STARE ZDARZENIA | Splunk dostał dane w ciągu ostatnich 30 min, ale najnowszy odnotowany czas zdarzenia jest starszy. |
| BRAK DANYCH | W wyszukaniu nie ma żadnych pasujących logów z ostatnich 24 h według czasu indeksowania. |

Okno indeksowania obejmuje 24 h. Zakres czasu zdarzeń sięga od najstarszych logów do teraz, więc uwzględnia opóźniony import starszych zdarzeń. Przy `STARE ZDARZENIA` sprawdź czas systemowy hosta i czy forwarder nadrabia kolejkę. Próg 30 min służy do ręcznej kontroli labu. Wyłączona VM lub mały ruch mogą dać status `CISZA`.

## Instalacja i sprawdzenie

1. W Splunk Web utwórz prywatny **Classic Dashboard** o ID `domainwatch_telemetry_health`. W **Edit → Source** wklej cały [XML panelu](../dashboard/telemetry-health.xml) i zapisz.
2. W polu **Host w Splunku** wpisz nazwę z pola `host` widoczną w wyszukiwaniu. W labie domyślną wartością jest `DC01`. Panel ma wyświetlić dwa wiersze.
3. Wpisz nazwę nieistniejącego hosta i sprawdź, czy oba kanały mają `BRAK DANYCH`. Następnie przywróć właściwy host.
4. Jeżeli na działającym hoście jeden kanał raportuje `BRAK DANYCH`, sprawdź dane powiązane z tym hostem w `index=main` oraz wartości `source` i `sourcetype`. Zmień dopasowanie w XML, jeśli konfiguracja forwardera stosuje inne nazwy.

[Splunk – wyszukiwanie po czasie indeksowania z pola `_indextime`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/time-format-variables-and-modifiers/time-modifiers)
