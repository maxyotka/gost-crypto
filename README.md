<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version"/>
  <img src="https://img.shields.io/badge/ГОСТ-Криптография-critical?style=for-the-badge" alt="GOST"/>
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=for-the-badge" alt="License"/>
</p>

# gost-crypto

Библиотека криптографических алгоритмов по актуальным российским стандартам ГОСТ для Go.

Нулевые внешние зависимости. Constant-time операции. Обнуление чувствительных данных в памяти.

## Алгоритмы

| Пакет | Стандарт | Описание | Статус |
|-------|----------|----------|--------|
| `gost341112` | ГОСТ Р 34.11-2012 | Стрибог — хеш-функция (256/512 бит) | done |
| `gost341215` | ГОСТ Р 34.12-2015 | Кузнечик (128-бит) и Магма (64-бит) — блочные шифры | done |
| `gost341315` | ГОСТ Р 34.13-2015 | Режимы работы: ECB, CBC, CFB, CTR, OFB, MAC | done |
| `gost341012` | ГОСТ Р 34.10-2012 | Цифровая подпись на эллиптических кривых | done |
| `mgm` | MGM | Multilinear Galois Mode — AEAD | done |
| `vko` | VKO | Ключевое согласование | done |
| `kdf` | KDF | KDF, HMAC, CMAC, PBKDF2, key wrap | done |

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

## Структура проекта

```
gost-crypto/
├── gost341112/     # Стрибог — хеш-функция ГОСТ Р 34.11-2012
├── gost341215/     # Кузнечик + Магма — блочные шифры ГОСТ Р 34.12-2015
├── gost341315/     # Режимы работы ГОСТ Р 34.13-2015
├── gost341012/     # Цифровая подпись ГОСТ Р 34.10-2012
├── mgm/            # MGM AEAD
├── vko/            # Ключевое согласование VKO
├── kdf/            # KDF, HMAC, CMAC, PBKDF2, key wrap
└── internal/       # S-boxes, GF(2^n), constant-time утилиты
```

## Разработка

```bash
go test ./...           # все тесты
go test -cover ./...    # покрытие
go test -bench=. ./...  # бенчмарки
golangci-lint run       # линтер
```

## Лицензия

### Open Source — AGPL-3.0

Для open-source проектов и личного использования: [AGPL-3.0](LICENSE).

Это означает: если вы используете gost-crypto в своём ПО и **распространяете** его (включая SaaS) — вы обязаны открыть исходный код своего ПО под AGPL-3.0.

### Коммерческая лицензия

Для использования в **закрытом коммерческом ПО** без обязательств AGPL доступна коммерческая лицензия.

Коммерческая лицензия позволяет:
- Использовать gost-crypto в closed-source продуктах
- Распространять без раскрытия исходного кода
- Встраивать в SaaS без ограничений AGPL
- Получать приоритетную поддержку

**Запрос:** [max@gundyrev.com](mailto:max@gundyrev.com)

```
Copyright (C) 2026 maxyotka

SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
```
