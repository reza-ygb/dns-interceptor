# راهنمای نصب APT (امضاشده) – dns-interceptor

این سند شامل دستورهای نصب امن از مخزن APT امضاشده، مسیر جایگزین (fallback) برای دور زدن مشکل ریدایرکت، و اطلاعات کلید است.

## وضعیت فعلی
- ریپو APT امضا و تست شده (Good signature)
- Fingerprint کلید:

```
0CDF 9B89 F572 1F36 4263  EE59 E0A9 C376 7CB3 A436
```

- UID: dns-interceptor APT Signing <packages@reza-ygb.github.io>
- الگوریتم/اندازه: RSA 4096
- انقضا: 2027-09-16

## نصب (fallback که همین الان کار می‌کند)
این مسیر از raw.githubusercontent.com استفاده می‌کند و مشکل ریدایرکت github.io به دامنه yaghobpoor.me را دور می‌زند.

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://raw.githubusercontent.com/reza-ygb/dns-interceptor/gh-pages/keyring/KEY.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/dns-interceptor.gpg

echo "deb [signed-by=/etc/apt/keyrings/dns-interceptor.gpg] https://raw.githubusercontent.com/reza-ygb/dns-interceptor/gh-pages stable main" \
  | sudo tee /etc/apt/sources.list.d/dns-interceptor.list >/dev/null

sudo apt update
sudo apt install dns-interceptor
```

تأیید Fingerprint (اختیاری):

```bash
curl -fsSL https://raw.githubusercontent.com/reza-ygb/dns-interceptor/gh-pages/keyring/KEY.asc \
  | gpg --show-keys --with-fingerprint --keyid-format LONG
# باید ببینید: 0CDF 9B89 F572 1F36 4263  EE59 E0A9 C376 7CB3 A436
```

## نصب از github.io (بعد از رفع ریدایرکت)
وقتی تنظیمات Pages اصلاح شود و ریدایرکت حذف شود:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://reza-ygb.github.io/dns-interceptor/keyring/dns-interceptor.gpg \
  | sudo tee /etc/apt/keyrings/dns-interceptor.gpg >/dev/null
sudo chmod 0644 /etc/apt/keyrings/dns-interceptor.gpg

echo "deb [signed-by=/etc/apt/keyrings/dns-interceptor.gpg] https://reza-ygb.github.io/dns-interceptor stable main" \
  | sudo tee /etc/apt/sources.list.d/dns-interceptor.list >/dev/null

sudo apt update
sudo apt install dns-interceptor
```

## رفع دائمی مشکل ریدایرکت
در GitHub → Settings → Pages:
- دامنه سفارشی را خالی کنید (در حال حاضر به http://yaghobpoor.me/dns-interceptor اشاره می‌کند)
- HTTPS را Enforce کنید

## برنامه فردا
- آماده‌سازی PPA (Launchpad): Debianization استاندارد (debian/)، ساخت source package و dput
- راه‌اندازی CI برای build/tags/release و dput خودکار به PPA
- نظم‌دهی سایر پروژه‌ها با تمپلیت مشترک (pyproject, debian/, Makefile, Actions)
- تصمیم درباره Flatpak (به‌علت sandbox مناسب ابزارهای network/raw socket نیست؛ تمرکز روی PPA/DEB/AppImage)
