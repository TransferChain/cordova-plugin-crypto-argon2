# TransferChain Argon2 — geliştirici kılavuzu

**Sürüm:** 1.0.0. Argon2i, Argon2d ve Argon2id ile raw anahtar türetir. Argon2
sürümü **1.3 / 0x13** olarak sabittir. PHC string üretmez; pepper veya
associated-data parametresi sunmaz. [Kurulum ve kullanım](README.md).

## Kaynak haritası

| Dosya                                       | Sorumluluk                                         |
| ------------------------------------------- | -------------------------------------------------- |
| [www/Argon2.js](www/Argon2.js)              | Unicode doğrulama ve binary salt                   |
| [Android](src/android/Argon2.java)          | argon2kt Java API, yamalı JNI, çağrıya özel buffer |
| [iOS Swift](src/ios/Argon2.swift)           | Parametre kontrolü, bağımsız C context, GCD        |
| [Bridging header](src/ios/TCArgon2Bridge.h) | Swift → reference C erişimi                        |
| [Reference C](src/ios/vendor/argon2/)       | Sürümlenen portable Argon2 kaynakları              |
| [plugin.xml](plugin.xml)                    | Maven sürümü, derlenen C kaynakları ve kayıt       |

## API ve parametreler

```js
let key
try {
  key = await CryptoKit.Argon2.derive({
    password, salt, variant: 'argon2id', time: 3,
    memoryCost: 65536, parallelization: 4, keyLength: 32
  })
  await consumeKey(key)
} finally {
  key?.fill(0)
}
```

Örnek deviceready sonrasında çalışır. Girdi ve consumer fonksiyonları çağıran
tarafından sağlanır; sahip olunan secret bufferlar işlem bitince temizlenir.
Ayrıntılar: [API](docs/API.md).

Bu değerler sözleşme örneğidir. Mobil cihaz gecikmesi/bellek bütçesi ölçülmeden
üretim politikası olarak kabul edilmemelidir.

| Parametre       | Sözleşme                                              |
| --------------- | ----------------------------------------------------- |
| variant         | Zorunlu: argon2i, argon2d, argon2id                   |
| password        | String; en fazla 1024 UTF-16 code unit; boş olabilir  |
| salt            | Uint8Array/ArrayBuffer; 8–1024 byte                   |
| time            | Integer; 1–10 geçiş                                   |
| memoryCost      | Integer **KiB**; 8 × parallelization ile 65.536 arası |
| parallelization | Integer; 1–4 mantıksal lane                           |
| keyLength       | Integer **byte**; 4–1024                              |
| Sonuç           | Promise<Uint8Array>; keyLength byte                   |

Bütün maliyet alanları zorunludur; varsayılan veya sessiz clamp yoktur. Parola
UTF-8 olarak işlenir, normalize/trim edilmez; tek surrogate reddedilir. Salt ve
bütün parametreler saklanan veriyle birlikte sürümlenmelidir.

Lane sayısı JS kuyruğunun veya OS toplam thread sayısının yerine geçmez. Argon2
memory block yuvarlaması uygulanabilir; saklanan parametreyi yuvarlanmış tahsis
boyutuyla sessizce değiştirmeyin.

## Android: argon2kt

plugin.xml, com.lambdapioneer.argon2kt:argon2kt:1.6.0 bağımlılığını sabitler.
Java kodu variant değerini Argon2Mode'a çevirir ve Argon2Version.V13 kullanır.
Password/salt direct ByteBuffer'a kopyalanır; sonuç rawHashAsByteArray ile
alınır. İş bittiğinde input buffer'ları, raw hash ve encoded output buffer'ları
silinir.

Bouncy Castle kullanılmaz. argon2kt yükseltirken sadece Maven sürümünü
değiştirmek yeterli değildir: JNI ABI'leri, direct buffer davranışı, native
allocation ömrü ve 16 KiB ELF hizalaması kontrol edilmelidir.

### Projeye ait JNI düzeltmesi

[src/android/native/Argon2Jni.cpp](src/android/native/Argon2Jni.cpp), upstream
JNI sembollerini korur. Sonuçlar malloc/NewDirectByteBuffer yerine JVM
sahipliğinde ByteBuffer.allocateDirect ile ayrılır. Java finally bu buffer'ları
sıfırlar; allocation geri kazanımı JVM yaşam döngüsündedir, anında free
garantisi değildir. JNI class/field araması çağrıya özeldir; thread'ler arasında
local JNI referansı saklanmaz. C hata yolları ayrılmış çıktı buffer'larını
sıfırlar.

Java Argon2Kt SoLoaderShim ile libtransferchain_argon2 yükler.
[argon2.gradle](src/android/argon2.gradle) CMake hedefini bağlar ve upstream
libargon2jni/libargon2native kopyalarını APK'dan çıkarır. Maven 1.6.0
Java/Kotlin arayüzü korunur. CMake, iOS ile aynı sabitlenmiş reference C
kaynağını derler; O2, stack protector, RELRO/NOW ve 16 KiB ELF hizalaması
kullanır. Dört Android ABI'si derlenir. JNI MIT lisansı native/LICENSE.argon2kt
içindedir.

Bu dosyalar değiştirilirse -Xcheck:jni host testi, üç variant vektörleri,
paralel çağrı testi, Android APK içeriği ve sanitizer kontrolleri birlikte
çalıştırılmalıdır. JVM/sağlayıcı iç kopyalarının tümünü sıfırladığımız iddia
edilmez.

## iOS: Swift + reference C

Portable reference C uygulaması kullanılır; SIMD/CLI derlenmez. Swift
TCArgon2Bridge.h üzerinden C API'ye erişir. plugin.xml derlenecek C dosyalarının
tam listesidir. Yeni source eklerken yalnızca dosyayı kopyalamak yeterli
değildir.

Kaynak provenance:

| Kaynak      | Sabitlenen kimlik                                         |
| ----------- | --------------------------------------------------------- |
| argon2kt    | 1.6.0; commit 226d943ad1c6344a049c08a437e09688ceb07929    |
| Reference C | 20190702; commit 62358ba2123abd17fccf2a108a301d4b52c01a7c |

iOS vendor klasöründeki LICENSE ve SHA256SUMS korunur. Yerel src/argon2.h
forwarding header'ı copied/linked Cordova kurulumunda include çözümü içindir.

## Thread, bellek ve hata sözleşmesi

Android Cordova thread pool, iOS background çalışma katmanı kullanılır. Global
BUSY guard yoktur; bağımsız çağrılar paralel çalışabilir. Çağıran eşzamanlı iş
sayısını ve toplam bellek bütçesini sınırlar. Gerçek C hesaplaması başladıktan
sonra JS Promise'ini bırakmak hesaplamayı iptal etmez. Bellek bütçesi memoryCost
dışında transport/sonuç buffer'larını ve başka plugin işlemlerini de
içermelidir.

Native hata kodları INVALID_ARGUMENT, RESOURCE_LIMIT, OPERATION_FAILED; Android
native yükleme sorunu NATIVE_UNAVAILABLE olabilir. Sonuç/parola içeriğini
loglamayın.

## Geliştirme ve doğrulama

Yeni variant veya parametre eklerken üç katmanı birlikte değiştirin: www
metadata sözleşmesi, Java/Swift sınırları, host ve platform test vektörleri.
Örneğin memoryCost tavanını artırmak sadece sayı değişikliği değildir; eşzamanlı
işlem ve düşük bellek cihaz politikası yeniden ölçülmelidir.

[Bridge testleri](tests/js/bridge.test.js),
[Java testleri](tests/native/Argon2Tests.java) ve
[C referansı](tests/reference/argon2-reference.c) plugin içinde bulunur. Üç
variant, Unicode, maliyet sınırları ve paralel çağrı izolasyonu korunmalıdır.
[Test kurulumu](docs/TESTING.md) native harness gereksinimlerini açıklar; host
sonuçları cihaz bellek profilinin yerine geçmez.
