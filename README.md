<p align="center">
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version"/>
  <img src="https://img.shields.io/badge/ГОСТ-Криптография-critical?style=for-the-badge" alt="GOST"/>
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/KAT-RFC%20%2B%20ГОСТ-brightgreen?style=for-the-badge" alt="KAT Verified"/>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/maxyotka/gost-crypto"><img src="https://pkg.go.dev/badge/github.com/maxyotka/gost-crypto.svg" alt="Go Reference"/></a>
  <a href="https://goreportcard.com/report/github.com/maxyotka/gost-crypto"><img src="https://goreportcard.com/badge/github.com/maxyotka/gost-crypto" alt="Go Report Card"/></a>
  <a href="https://github.com/maxyotka/gost-crypto/actions/workflows/test.yml"><img src="https://github.com/maxyotka/gost-crypto/actions/workflows/test.yml/badge.svg" alt="CI"/></a>
  <a href="https://github.com/maxyotka/gost-crypto/releases/latest"><img src="https://img.shields.io/github/v/release/maxyotka/gost-crypto?sort=semver" alt="Release"/></a>
</p>

# gost-crypto

Библиотека криптографических алгоритмов по актуальным российским стандартам ГОСТ для Go.

Нулевые внешние зависимости. Constant-time операции. Обнуление чувствительных данных в памяти.
KAT-верификация по RFC и ГОСТ.

## Алгоритмы

| Пакет | Стандарт | Описание | KAT |
|-------|----------|----------|-----|
| `gost341112` | ГОСТ Р 34.11-2012 | Стрибог — хеш-функция (256/512 бит) | RFC 6986 |
| `gost341215` | ГОСТ Р 34.12-2015 | Кузнечик (128-бит) и Магма (64-бит) — блочные шифры | RFC 7801, RFC 8891 |
| `gost341315` | ГОСТ Р 34.13-2015 | Режимы: ECB, CBC, CFB, CTR, OFB, MAC (m>=n) | ГОСТ 34.13 Прил. А |
| `gost341012` | ГОСТ Р 34.10-2012 | Цифровая подпись — 7 кривых (256+512 бит) | RFC 7091 |
| `mgm` | RFC 9058 | Multilinear Galois Mode — AEAD | RFC 9058 |
| `vko` | RFC 7836 | Ключевое согласование (256/512-бит кривые) | RFC 7836 |
| `kdf` | R 50.1.113-2016 | KDF, HMAC, CMAC, PBKDF2, key wrap | — |

## Кривые ГОСТ Р 34.10-2012

| Кривая | Размер | OID |
|--------|--------|-----|
| `CurveParamSetA()` | 256 бит | id-tc26-gost-3410-2012-256-paramSetA |
| `CurveParamSetB()` | 256 бит | CryptoPro-A |
| `CurveParamSetC()` | 256 бит | CryptoPro-B |
| `CurveParamSetD()` | 256 бит | CryptoPro-C |
| `Curve512ParamSetA()` | 512 бит | id-tc26-gost-3410-2012-512-paramSetA |
| `Curve512ParamSetB()` | 512 бит | id-tc26-gost-3410-2012-512-paramSetB |
| `Curve512ParamSetC()` | 512 бит | id-tc26-gost-3410-2012-512-paramSetC |

## Установка

```bash
go get github.com/maxyotka/gost-crypto
```

## Быстрый старт

```go
package main

import (
    "fmt"
    "github.com/maxyotka/gost-crypto/gost341112"
)

func main() {
    h := gost341112.New256()
    h.Write([]byte("Hello, ГОСТ!"))
    fmt.Printf("%x\n", h.Sum(nil))
}
```

## Производительность

Precomputed S+L таблицы для Кузнечика, zero heap allocations на шифрах.

| Алгоритм | MB/s | Allocs |
|----------|------|--------|
| Кузнечик Encrypt | 25 | 0 |
| Магма Encrypt | 60 | 0 |
| Стрибог-256 8KB | 26 | 1 |

## Режимы шифрования (ГОСТ 34.13-2015)

Все режимы поддерживают параметр m (длина shift register):
- `len(iv) == blockSize` — стандартный режим (m=n)
- `len(iv) > blockSize` — ГОСТ shift register (m>n)

```go
// Стандартный CBC (m=n)
cbc := gost341315.NewCBCEncrypter(block, iv16)

// ГОСТ CBC с shift register (m=2n)
cbc := gost341315.NewCBCEncrypter(block, iv32)
```

## Структура проекта

```
gost-crypto/
├── gost341112/     # Стрибог — хеш-функция ГОСТ Р 34.11-2012
├── gost341215/     # Кузнечик + Магма — блочные шифры ГОСТ Р 34.12-2015
├── gost341315/     # Режимы работы ГОСТ Р 34.13-2015
├── gost341012/     # Цифровая подпись ГОСТ Р 34.10-2012 (7 кривых)
├── mgm/            # MGM AEAD (RFC 9058)
├── vko/            # Ключевое согласование VKO (RFC 7836)
├── kdf/            # KDF, HMAC, CMAC, PBKDF2, key wrap
└── internal/       # S-boxes, GF(2^n), constant-time утилиты
```

## Разработка

```bash
go test ./...           # все тесты
go test -cover ./...    # покрытие
go test -bench=. ./...  # бенчмарки
```

## Лицензия

### Open Source — AGPL-3.0

Для open-source проектов и личного использования: [AGPL-3.0](LICENSE).

Если вы используете gost-crypto в своём ПО и **распространяете** его (включая SaaS) — вы обязаны открыть исходный код своего ПО под AGPL-3.0.

### Коммерческая лицензия

Для закрытого коммерческого ПО доступна коммерческая лицензия: [подробнее](COMMERCIAL-LICENSE.md).

```
Copyright (C) 2026 maxyotka

SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
```
