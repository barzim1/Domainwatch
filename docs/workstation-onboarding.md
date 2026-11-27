# Stacja WS01 w domenie DomainWatch

Cel tego etapu to potwierdzenie, że zwykłe logowanie konta domenowego można prześledzić z dwóch miejsc. Na WS01 szukamy zdarzenia 4624 z typem logowania 2, a na DC01 wydania biletu TGT opisanego zdarzeniem 4768 z kodem powodzenia.

| VM | Rola |
|---|---|
| DC01 | Kontroler domeny i serwer DNS dla `lab.local` |
| SOC-Lab-Ubuntu-01 | Splunk Enterprise. Odbiera dane od forwarderów na TCP 9997. |
| WS01 | Osobna VM z Windows 10 Pro 64-bit i Universal Forwarderem |

## 1. Utwórz VM

- Na hoście uruchom VMware Workstation i utwórz nową VM. W **WS01 → Settings → Network Adapter** wybierz **NAT** oraz **Connect at power on**, zgodnie z ustawieniem DC01 w tym labie. Jeśli w innym labie DC01 używa sieci **Custom**, wybierz na WS01 tę samą sieć VMnet. [Tryby sieci VMware](https://knowledge.broadcom.com/external/article?articleNumber=309842)
- Użyj obrazu ISO Windows 10 64-bit i w instalatorze wybierz **Windows 10 Pro**, jeśli masz licencję na tę edycję dla VM. System instalujesz na dysku wirtualnym WS01. Jako punkt startowy przydziel VM 2 vCPU, 4 GB RAM i 64 GB dysku. W tym scenariuszu sprawdzamy lokalną domenę AD. [Pobieranie Windows 10](https://www.microsoft.com/pl-pl/software-download/windows10) · [Edycje obsługujące dołączenie do domeny](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/join-computer-to-domain)
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
2. Na WS01 zainstaluj [Splunk Universal Forwarder 10.2.x dla Windows x64](https://www.splunk.com/en_us/download/previous-releases/universal-forwarder.html). Seria 10.2 obsługuje Windows 10 x64 i przesyłanie do Splunk Enterprise 10.4.x. W instalatorze wskaż adres Ubuntu i port **9997** w polu **Receiving Indexer**. Włącz **Security Event Log** i użyj konta usługi z prawem odczytu tego kanału. W instalacji samodzielnej **Deployment Server** może zostać pusty. [Zgodność z Windows 10](https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/10.2/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises) · [Zgodność forwardera i indeksatora](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/compatibility-matrix/splunk-products-version-compatibility/compatibility-between-forwarders-and-splunk-enterprise-indexers)
3. W Splunku uruchom `index=main (host=WS01 OR host=WS01.lab.local) | stats count by host source sourcetype` na **Last 24 hours**. Jeśli nazwa jest inna, odszukaj host pod nazwą z forwardera i dostosuj [zapytanie](../searches/workstation-logon-evidence.spl). Jeśli dziennik Security lokalnie zawiera zdarzenia, lecz Splunk ich nie zwraca, sprawdź usługę `SplunkForwarder`, odczyt kanału i ustawienia odbiornika.

## 4. Weryfikacja logowania

- Gdy Splunk widzi logi WS01, wyloguj się z lokalnej sesji i zaloguj **raz** w konsoli VM jako zwykły użytkownik domenowy. Zapisz czas próby i adres IPv4 WS01. Na stacji `whoami` powinno wskazywać konto domenowe.
- Uruchom [zapytanie odbiorcze](../searches/workstation-logon-evidence.spl) w **Search & Reporting**, z przedziałem obejmującym logowanie. Odszukaj to samo konto i bliskie znaczniki czasu. Porównaj `client_ip_on_dc` w 4768 z rzeczywistym IP WS01. Zdarzenie 4624 ma pochodzić z WS01, a 4768 z DC01.
- Zdarzenia dają dwa różne dowody. 4624 typu 2 dokumentuje utworzenie sesji interaktywnej na WS01. 4768 z powodzeniem dokumentuje wydanie TGT przez DC. Przy braku jednego z nich sprawdź audyt sukcesów, zakres czasu, dane źródłowe i typ sesji. Logowanie z pamięci podręcznej i logowanie przez RDP mogą mieć inny typ. Do powiązania użyj czasu, konta i źródła.

[Microsoft Learn – zdarzenie 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624) · [zdarzenie 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
