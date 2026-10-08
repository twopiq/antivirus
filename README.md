# Qalqon Antivirus

Windows uchun antivirus dasturi. Go tilida yozilgan, bitta `qalqon.exe` fayldan iborat.
Konsol (command line) va o'zbekcha interaktiv menyu.

## Imkoniyatlar

### Aniqlash

| Usul | Tavsif |
|---|---|
| **ClamAV bazasi** | `main.cvd` va `daily.cvd` (millionlab imzo): fayl xeshlari (`.hdb`, `.hsb`), PE bo'lim xeshlari (`.mdb`, `.msb`), tana imzolari (`.ndb` — joker belgilar, oraliqlar, muqobillar, `EP+n`/`EOF-n` siljishlari), noto'g'ri aniqlashlar ro'yxati (`.fp`, `.sfp`, `.ign2`). |
| **MalwareBazaar** | abuse.ch'ning yangi zararli fayllar xeshlari (har 6 soatda). |
| **PE tahlili** | Pakerlar (UPX, VMProtect, Themida...), shifrlangan kod (entropiya), yoziladigan+bajariladigan bo'limlar, g'alati kirish nuqtasi, yashirilgan importlar, boshqa jarayonga kod kiritish (injection, process hollowing), klaviatura kuzatuvi va h.k. Raqamli imzosi (Authenticode) haqiqiy dasturlar uchun evristik ogohlantirishlar o'chiriladi — noto'g'ri aniqlashlar kamayadi. |
| **Office makroslari** | `.doc/.xls/.ppt` va `.docm/.xlsm` ichidagi VBA makroslari ochiladi (MS-OVBA) va avtomatik ishga tushib, fayl yuklab oluvchi/ishga tushiruvchi makroslar aniqlanadi. Excel 4.0 makroslari, Follina (`ms-msdt:`), masofaviy shablon. |
| **Hujjatlar** | PDF (avtomatik JavaScript, `/Launch`, ichiga joylangan `.exe`), RTF (Equation Editor exploit), HTML smuggling. |
| **Skriptlar** | `.vbs`, `.js`, `.bat`, `.ps1`, `.hta`, `.lnk`: fleshka qurtlari, yuklovchi troyanlar, yashirin PowerShell, ransomware. |
| **Fayl nomi** | Ikki kengaytmali fayllar (`hujjat.pdf.exe`), RTLO bilan niqoblangan nomlar, rasm sifatida niqoblangan `.exe`. |
| **Arxivlar** | ZIP, GZIP, TAR — ichma-ich 4 darajagacha, "zip bomb"dan himoya bilan. |

### Tizimni tekshirish

- Ishlab turgan jarayonlar va ularga yuklangan DLL'lar
- Avtoyuklash: reestr `Run`/`RunOnce` (barcha foydalanuvchilar), Startup papkalari, **rejalashtirilgan vazifalar**,
  **xizmatlar va drayverlar**, **IFEO** (dasturni almashtirish), **AppInit_DLLs**, Winlogon `Shell`/`Userinit`
- Imzosiz dasturlarning Temp/AppData'dan avtomatik ishga tushishi
- **hosts fayli**: bank, ijtimoiy tarmoq, Windows Update yoki antivirus saytlarini o'g'irlash/bloklash
- **Fleshka**: `autorun.inf`, yorliq (shortcut) virusi, yashirilgan fayllarni tiklash

### Real vaqt himoyasi

`qalqon install` dan keyin har safar Windows'ga kirganda fonda ishlaydi:

- Yuklamalar, Ish stoli, Hujjatlar, Startup papkalaridagi yangi fayllar (ReadDirectoryChangesW orqali darhol),
  Temp va AppData'dagi bajariladigan fayllar
- Har bir yangi ishga tushgan dastur
- Ulangan har bir fleshka (tekshirish + tozalash + yashirilgan fayllarni tiklash)

XAVFLI fayllar darhol to'xtatiladi va karantinga o'tkaziladi, ekranda ogohlantirish chiqadi.
SHUBHALI fayllar faqat xabar qilinadi.

## O'rnatish

1. `qalqon.exe` ni yuklab oling.
2. Uni ikki marta bosing → administrator ruxsatini bering → menyuda **10 → 1 (O'rnatish)**.
   Yoki administrator `cmd` da: `qalqon install`

O'rnatish quyidagilarni bajaradi:

- `C:\Program Files\Qalqon\qalqon.exe` ga nusxalaydi
- Task Scheduler vazifalari: `\Qalqon\Himoya` (kirishda real vaqt himoyasi), `\Qalqon\Yangilash`
  (har 6 soatda va yoqilgandan 15 daqiqa keyin), `\Qalqon\Tekshiruv` (har chorshanba tezkor tekshiruv)
- Virus bazasini yuklaydi
- "Dasturlar va imkoniyatlar" ro'yxatiga qo'shadi (u yerdan o'chirish mumkin)
- `C:\ProgramData\Qalqon` ruxsatlarini cheklaydi — zararli dastur o'zini ishonchli ro'yxatga yoza olmaydi

Holatni ko'rish: `qalqon status`. O'chirish: `qalqon uninstall` (`--purge` — baza va karantin ham).

## Buyruqlar

```bat
qalqon                               :: interaktiv menyu
qalqon install | uninstall | status
qalqon protect                       :: real vaqt himoyasi shu oynada
qalqon quick                         :: tezkor tekshiruv (jarayonlar, avtoyuklash, hosts, Yuklamalar, Temp...)
qalqon full                          :: barcha disklar
qalqon scan D:\Yuklamalar E:\        :: tanlangan papkalar
qalqon usb [E:]                      :: fleshkani tekshirish va tozalash
qalqon startup                       :: avtoyuklash, vazifalar, xizmatlar, IFEO, hosts
qalqon processes                     :: ishlab turgan jarayonlar
qalqon update                        :: ClamAV + MalwareBazaar
qalqon update --source clamav        :: faqat ClamAV
qalqon update --full                 :: MalwareBazaar to'liq bazasi
qalqon update --file main.cvd        :: qo'lda yuklangan bazani import qilish (.cvd .cld .hdb .hsb .ndb .txt)
qalqon quarantine list | restore N | delete N | clear
qalqon allow C:\dastur\setup.exe     :: noto'g'ri aniqlangan faylni ishonchli deb belgilash
qalqon allow list | remove N
qalqon exclude add D:\Loyihalar      :: papkani tekshiruvdan chiqarish
qalqon version
```

Tekshiruv sozlamalari:

| Bayroq | Ma'nosi |
|---|---|
| `--action ask` | nima qilishni so'rash (standart) |
| `--action auto` | XAVFLI fayllarni karantinga, SHUBHALI haqida faqat xabar |
| `--action report` | faqat hisobot |
| `--action quarantine` / `--yes` | hammasini karantinga |
| `--action delete` | hammasini o'chirish |
| `--quiet` | faqat natijalar (rejalashtirilgan vazifalar uchun) |
| `--no-cache` | o'zgarmagan fayllarni ham qayta tekshirish |
| `--workers N`, `--max-size MB`, `--no-color` | |

Chiqish kodi: `0` — tahdid yo'q (yoki hammasi zararsizlantirildi), `1` — tahdid qoldi.

## Virus bazasi

`qalqon update` quyidagilarni yuklaydi:

- **ClamAV** `daily.cvd` va `main.cvd` — `database.clamav.net` dan. Yangi versiya borligi DNS orqali
  (`current.cvd.clamav.net`) tekshiriladi, 4 soatda bir martadan ko'p yuklanmaydi (ClamAV CDN cheklovi).
  Fayl yaxlitligi MD5 bilan tekshiriladi. Shaxsiy oyna (mirror) uchun: `QALQON_CLAMAV_MIRROR=https://...`
- **MalwareBazaar** — oxirgi 48 soatdagi zararli fayllar xeshlari. abuse.ch kalit talab qilsa,
  uni [auth.abuse.ch](https://auth.abuse.ch/) dan bepul olib, `QALQON_ABUSE_KEY` ga yozing.

Agar kompyuterda internet bo'lmasa yoki CDN bloklasa, `main.cvd`/`daily.cvd` ni boshqa joyda yuklab
(masalan [cvdupdate](https://github.com/Cisco-Talos/cvdupdate) bilan) `qalqon update --file` orqali import qiling.

Bazalar ixcham jadvallarga kompilyatsiya qilinadi va xotiraga akslantiriladi (mmap): millionlab imzo
bir zumda ochiladi va kam xotira oladi.

ClamAV'ning mantiqiy (`.ldb`), bytecode (`.cbc`) imzolari va ba'zi murakkab `.ndb` imzolari qo'llab-quvvatlanmaydi —
`update` ularning sonini ko'rsatadi.

## Ma'lumotlar papkasi

`C:\ProgramData\Qalqon\` (`QALQON_HOME` bilan o'zgartirish mumkin):

| | |
|---|---|
| `sources\` | manba bazalar: `main.cvd`, `daily.cvd`, `bazaar.txt`, `custom.txt` (o'z xeshlaringiz), `allow.txt` (ishonchli fayllar) |
| `db\` | kompilyatsiya qilingan baza |
| `exclusions.txt` | istisno papkalar |
| `Quarantine\` | karantin (fayllar kodlangan, ishga tushmaydi) |
| `logs\` | kunlik jurnallar |
| `autoruns-backup.txt`, `hosts.backup-*` | o'chirilgan avtoyuklash yozuvlari va hosts faylining zaxirasi |

## Sinab ko'rish

[EICAR test fayli](https://www.eicar.org/download-anti-malware-testfile/): Bloknotga quyidagi satrni yozib,
`eicar.com` nomi bilan saqlang. Real vaqt himoyasi yoqilgan bo'lsa, u darhol karantinga o'tkaziladi.

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

## Yig'ish

[Go 1.22+](https://go.dev/dl/) kerak: `build.bat`, yoki

```sh
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o qalqon.exe .
go test ./...
```

Har bir push'da GitHub Actions `qalqon.exe` ni Windows'da yig'adi (*Actions → Artifacts*).

## Loyiha tuzilishi

```
main.go                   buyruqlar va menyu
app.go, cache.go          tekshiruv, tahdidlarni qayta ishlash, kesh
protect.go                real vaqt himoyasi
startup.go                avtoyuklash, xizmatlar, vazifalar, hosts
usb.go                    fleshkani tozalash
update.go                 bazani yangilash (ClamAV, MalwareBazaar, import)
install_windows.go        o'rnatish, Task Scheduler vazifalari
lists.go                  ishonchli fayllar, istisnolar, holat
internal/engine           skaner: PE, Office, PDF/RTF, skriptlar, arxivlar, evristika
internal/bodysig          ClamAV .ndb tana imzolari
internal/sigdb            virus bazasi: CVD o'qish, kompilyatsiya, mmap jadvallar
internal/quarantine       karantin
internal/system           Windows API: jarayonlar, reestr, vazifalar, xizmatlar, Authenticode, papka kuzatuvi
internal/ui               konsol
```

## Cheklovlar

Qalqon kuchli imzo bazasi (ClamAV + MalwareBazaar), statik tahlil va real vaqt fayl/jarayon kuzatuvidan
foydalanadi, lekin tijorat antiviruslarida bo'lgan yadro darajasidagi drayver (fayl ochilishidan *oldin*
bloklash), xulq-atvor tahlili, bulutli reputatsiya va xotirani skanerlash yo'q. Shuning uchun
real vaqt himoyasi faylni yozilgandan yoki dastur ishga tushgandan bir necha soniya keyin ushlaydi.
Windows Defender'ni o'chirmang — Qalqon'ni qo'shimcha himoya sifatida ishlating.
