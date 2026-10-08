# Qalqon Antivirus

Windows uchun konsol (command line) antivirus dasturi. Go tilida yozilgan, bitta
`qalqon.exe` fayldan iborat — o'rnatish shart emas.

## Imkoniyatlar

| Imkoniyat | Tavsif |
|---|---|
| **Imzo bo'yicha aniqlash** | Fayllarning SHA-256 xeshi virus bazasi bilan solishtiriladi. Baza [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) dan yangilanadi. |
| **Qoidalar** | Skriptlardagi (`.vbs`, `.js`, `.bat`, `.ps1`, `.hta`, `.lnk`) zararli naqshlar: fleshka qurtlari, yuklovchi troyanlar, yashirin PowerShell, ransomware (shadow copy o'chirish), kripto-maynerlar, EICAR test fayli. |
| **Evristika** | Ikki kengaytmali fayllar (`hujjat.pdf.exe`), RTLO belgisi bilan niqoblangan nomlar, rasm/hujjat sifatida niqoblangan `.exe`, yorliq (shortcut) virusi. |
| **ZIP arxivlar** | Arxiv ichidagi fayllar ham tekshiriladi. |
| **Fleshkani tozalash** | `autorun.inf`, yorliq virusi o'chiriladi, virus yashirgan fayl va papkalar qayta ko'rinadigan qilinadi. |
| **Jarayonlar** | Ishlab turgan dasturlar tekshiriladi; zararli jarayon to'xtatilib, fayli karantinga o'tkaziladi. |
| **Avtoyuklash** | Reestrdagi `Run`/`RunOnce` kalitlari, Startup papkalari va Winlogon (`Shell`, `Userinit`) tekshiriladi. |
| **Karantin** | Zararli fayllar kodlangan holda saqlanadi — keyin tiklash yoki butunlay o'chirish mumkin. |
| **Real vaqt kuzatuvi** | Yuklamalar, Ish stoli, Startup papkalaridagi yangi fayllar va yangi ulangan fleshkalar avtomatik tekshiriladi. |

## Ishga tushirish

`qalqon.exe` ni ikki marta bosing — administrator huquqi so'raladi va menyu ochiladi:

```
╔══════════════════════════════════════════════════════════╗
║  QALQON ANTIVIRUS  v1.0.0                                ║
║  Kompyuter va fleshkalarni viruslardan himoya qilish     ║
╚══════════════════════════════════════════════════════════╝
  1. Tezkor tekshiruv (jarayonlar, avtoyuklash, Yuklamalar, Temp)
  2. To'liq tekshiruv (barcha disklar)
  3. Papka yoki faylni tekshirish
  4. Fleshkani tekshirish va tozalash (USB)
  5. Avtoyuklash dasturlari
  6. Ishlab turgan jarayonlarni tekshirish
  7. Karantin
  8. Virus bazasini yangilash
  9. Real vaqt kuzatuvi (monitor)
  0. Chiqish
```

**Birinchi ishga tushirishda virus bazasini yangilang** (menyuda `8` yoki `qalqon update`).

### Buyruqlar satri

Administrator sifatida ochilgan `cmd` yoki PowerShell'da:

```bat
qalqon quick                         :: tezkor tekshiruv
qalqon full                          :: barcha disklar
qalqon scan D:\Yuklamalar E:\        :: tanlangan papkalar
qalqon usb                           :: barcha fleshkalarni tekshirish va tozalash
qalqon usb E:                        :: faqat E: diskni
qalqon startup                       :: avtoyuklash ro'yxati
qalqon processes                     :: ishlab turgan jarayonlar
qalqon monitor                       :: real vaqt kuzatuvi
qalqon update                        :: oxirgi 48 soatdagi yangi imzolar
qalqon update --full                 :: to'liq baza (bir necha yuz ming imzo)
qalqon update --file hashes.txt      :: o'z xeshlar ro'yxatingizni qo'shish
qalqon quarantine list               :: karantin ro'yxati
qalqon quarantine restore 2          :: 2-faylni tiklash
qalqon quarantine delete 2           :: 2-faylni butunlay o'chirish
qalqon quarantine clear              :: karantinni tozalash
```

Tekshiruv sozlamalari:

| Bayroq | Ma'nosi |
|---|---|
| `--action ask` | topilgan tahdid bilan nima qilishni so'rash (standart) |
| `--action report` | faqat hisobot, hech narsa o'zgartirilmaydi |
| `--action quarantine` / `--yes` | so'ramasdan karantinga o'tkazish |
| `--action delete` | so'ramasdan butunlay o'chirish |
| `--workers N` | parallel oqimlar soni |
| `--max-size MB` | mazmuni tekshiriladigan eng katta fayl (standart 50 MB) |
| `--no-color` | ranglarsiz chiqish |

Chiqish kodi: `0` — tahdid yo'q (yoki hammasi zararsizlantirildi), `1` — zararsizlantirilmagan tahdid qoldi.
Buni Windows Task Scheduler'da muntazam tekshiruv uchun ishlatish mumkin:

```bat
schtasks /create /tn "Qalqon tezkor tekshiruv" /tr "C:\Qalqon\qalqon.exe quick --yes" /sc daily /st 12:00 /rl highest
```

### Ma'lumotlar papkasi

`C:\ProgramData\Qalqon\` (`QALQON_HOME` muhit o'zgaruvchisi bilan o'zgartirish mumkin):

- `signatures.txt` — virus bazasi (`sha256 [nomi]` har satrda; o'zingiz ham qo'shishingiz mumkin)
- `exclusions.txt` — tekshirilmaydigan papka/fayllar (har satrda bitta yo'l)
- `Quarantine\` — karantin
- `logs\` — kunlik jurnallar
- `autoruns-backup.txt` — o'chirilgan avtoyuklash yozuvlarining zaxirasi

abuse.ch yuklab olish uchun kalit talab qilsa, uni [auth.abuse.ch](https://auth.abuse.ch/) dan bepul oling va
`QALQON_ABUSE_KEY` muhit o'zgaruvchisiga yozing.

## Sinab ko'rish

Antivirus ishlashini xavfsiz tekshirish uchun [EICAR test fayli](https://www.eicar.org/download-anti-malware-testfile/)dan foydalaning:
Bloknotga quyidagi satrni yozib, `eicar.com` nomi bilan saqlang va `qalqon scan` bilan tekshiring:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

## Yig'ish (build)

[Go 1.22+](https://go.dev/dl/) kerak:

```bat
build.bat
```

yoki Linux/macOS'dan:

```sh
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o qalqon.exe .
go test ./...
```

Har bir push'da GitHub Actions `qalqon.exe` ni yig'adi — uni Actions sahifasidagi *Artifacts* bo'limidan yuklab olish mumkin.

## Loyiha tuzilishi

```
main.go, app.go           buyruqlar va menyu, tahdidlarni qayta ishlash
usb.go                    fleshkani tozalash
startup.go                avtoyuklashni tekshirish
monitor.go                real vaqt kuzatuvi
update.go                 virus bazasini yangilash
quarantine_cmd.go         karantin buyruqlari
internal/engine           skaner: imzolar, qoidalar, evristika, ZIP
internal/quarantine       karantin ombori
internal/system           Windows API: disklar, jarayonlar, reestr, UAC
internal/ui               konsol ranglari va so'rovlar
```

## Cheklovlar

Qalqon — imzo va evristikaga asoslangan oddiy skaner. U tijorat antiviruslari kabi
xulq-atvor tahlili, bulutli tekshiruv yoki yadro darajasidagi himoyani bermaydi.
Windows Defender'ni o'chirmang — Qalqon'ni qo'shimcha vosita sifatida ishlating.
