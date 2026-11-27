# Stacja WS01 w domenie DomainWatch

Cel tego etapu to potwierdzenie, że zwykłe logowanie konta domenowego można prześledzić z dwóch miejsc. Na WS01 szukamy zdarzenia 4624 z typem logowania 2, a na DC01 wydania biletu TGT opisanego zdarzeniem 4768 z kodem powodzenia.

| VM | Rola |
|---|---|
| DC01 | Kontroler domeny i serwer DNS dla `lab.local` |
| SOC-Lab-Ubuntu-01 | Splunk Enterprise. Odbiera dane od forwarderów na TCP 9997. |
| WS01 | Nowa stacja Windows 11 Pro lub Enterprise z Universal Forwarderem |

## 1. Utwórz VM

- W VMware sprawdź **DC01 → Settings → Network Adapter**. Zanotuj tryb i numer sieci wirtualnej, jeśli używasz ustawienia **Custom**. Po instalacji WS01 podłącz do tej samej sieci VMware. Ustawienia obu istniejących maszyn pozostaw bez zmian.
- Użyj posiadanego, licencjonowanego obrazu Windows 11 Pro albo [Windows 11 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise). Ustaw co najmniej 2 vCPU, 4 GB RAM i dysk 64 GB. VM powinna korzystać z UEFI, Secure Boot i wirtualnego TPM. Opcje zależą od wersji VMware. [Wymagania Microsoftu](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements) · [Konfiguracja VMware](https://knowledge.broadcom.com/external/article?legacyId=86207)
- W ustawieniach nowego Windowsa nazwij komputer **WS01**. Zaloguj się lokalnie z uprawnieniami do zmiany ustawień sieci i dołączenia do domeny.

## 2. Sprawdź DNS i dołącz do domeny

1. Na **DC01** uruchom `ipconfig` i odczytaj IPv4 karty podłączonej do sieci labu. Jeśli na DC01 działa DNS domeny, w **WS01 → Win + R → ncpa.cpl → Ethernet → Właściwości → IPv4** wpisz ten adres jako preferowany DNS. Przypisanie adresu IP WS01 zostaw w trybie właściwym dla tej sieci, np. DHCP, jeśli jest dostępny.
2. Na **WS01** otwórz PowerShell i uruchom te polecenia.

   ```powershell
   Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.lab.local
   nltest /dsgetdc:lab.local
   ```

   Oczekiwany wynik to rekord SRV i odnalezienie `DC01` jako kontrolera domeny. W razie błędu sprawdź najpierw kartę VMware i DNS na WS01. [Diagnostyka Microsoftu](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/domain-join-networking-errors)

3. Na WS01 wybierz **Win + R → sysdm.cpl → Nazwa komputera → Zmień → Domena** i wpisz `lab.local`. Użyj konta uprawnionego do dołączania komputerów w tym labie. Po sukcesie zrestartuj WS01. [Dołączanie do AD](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/join-computer-to-domain)

## 3. Wyślij log Security do Splunka

1. Na Ubuntu odczytaj adres IP interfejsu labu poleceniem `ip -4 addr`. Na WS01 sprawdź `Test-NetConnection <IP_Ubuntu> -Port 9997`, podstawiając ten adres bez nawiasów. Oczekuj `TcpTestSucceeded : True`.
2. Na WS01 zainstaluj [Splunk Universal Forwarder dla Windows](https://www.splunk.com/en_us/download/universal-forwarder.html). W instalatorze wybierz własny odbiornik, wskaż adres Ubuntu i port **9997** w polu **Receiving Indexer**. Włącz zbieranie **Security Event Log** i użyj konta usługi z prawem odczytu tego kanału. W instalacji samodzielnej pole **Deployment Server** możesz zostawić puste. [Instrukcja instalatora](https://help.splunk.com/en/data-management/forward-data/universal-forwarder-manual/10.6/install-the-universal-forwarder/install-a-windows-universal-forwarder)
3. W Splunku uruchom `index=main (host=WS01 OR host=WS01.lab.local) | stats count by host source sourcetype` na **Last 24 hours**. Jeśli nazwa jest inna, odszukaj host pod nazwą z forwardera i dostosuj [zapytanie](../searches/workstation-logon-evidence.spl). Jeśli dziennik Security lokalnie zawiera zdarzenia, lecz Splunk ich nie zwraca, sprawdź usługę `SplunkForwarder`, odczyt kanału i ustawienia odbiornika.

## 4. Weryfikacja logowania

- Gdy Splunk widzi logi WS01, wyloguj się z lokalnej sesji i zaloguj **raz** w konsoli VM jako zwykły użytkownik domenowy. Zapisz czas próby i adres IPv4 WS01. Na stacji `whoami` powinno wskazywać konto domenowe.
- Uruchom [zapytanie odbiorcze](../searches/workstation-logon-evidence.spl) w **Search & Reporting**, z przedziałem obejmującym logowanie. Odszukaj to samo konto i bliskie znaczniki czasu. Porównaj `client_ip_on_dc` w 4768 z rzeczywistym IP WS01. Zdarzenie 4624 ma pochodzić z WS01, a 4768 z DC01.
- Zdarzenia dają dwa różne dowody. 4624 typu 2 dokumentuje utworzenie sesji interaktywnej na WS01. 4768 z powodzeniem dokumentuje wydanie TGT przez DC. Przy braku jednego z nich sprawdź audyt sukcesów, zakres czasu, dane źródłowe i typ sesji. Logowanie z pamięci podręcznej i logowanie przez RDP mogą mieć inny typ. Do powiązania użyj czasu, konta i źródła.

[Microsoft Learn – zdarzenie 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624) · [zdarzenie 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
