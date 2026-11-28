# BitCrack OpenCL — New Version v1
## Структура проекта и план работ



new_version_v1/
├── README.md                          ← Главное описание проекта
├── STRUCTURE.md                       ← Подробное описание структуры + план работ (ты его добавишь)
│
├── cl/                                ← Все OpenCL ядра (одна папка)
│   ├── secp256k1.cl
│   ├── sha256.cl
│   ├── ripemd160.cl
│   ├── keysearch.cl                   ← с твоей системой massiv_main2
│   └── bitcrack.cl                    ← (опционально) склеенный вариант
│
├── src/                               ← Исходники C++
│   ├── CLKeySearchDevice.cpp
│   ├── CLKeySearchDevice.h
│   ├── ... (остальные файлы)
│
├── include/                           ← Заголовочные файлы (если нужно)
│
├── build/                             ← Сборка
│
└── docs/                              ← Документация
    └── progress.md




### Цель проекта
Создать максимально быструю, современную и стабильную OpenCL-версию BitCrack с сохранением уникальной системы поиска пользователя (massiv_main2 + super_chek).

---

### Текущая структура папок



---

### Что уже сделано (Этап 1 — Ядра)

- [x] Полностью переписан `secp256k1.cl` (более чистая и быстрая арифметика)
- [x] Полностью переписан `sha256.cl`
- [x] Полностью переписан `ripemd160.cl`
- [x] Полностью переписан `keysearch.cl` с сохранением твоей системы:
  - `massiv_main2`
  - `super_chek1 / super_chek2`
  - `target_one = 22`
- [x] Обновлены `CLKeySearchDevice.cpp` и `CLKeySearchDevice.h`

---

### Текущий статус

| Компонент                  | Статус          | Комментарий                              |
|---------------------------|-----------------|------------------------------------------|
| secp256k1.cl              | Готов           | Современная версия                       |
| sha256.cl                 | Готов           |                                          |
| ripemd160.cl              | Готов           |                                          |
| keysearch.cl              | Готов           | Сохранена твоя логика сравнения          |
| CLKeySearchDevice.cpp/.h  | Готов           | Согласовано с новыми ядрами              |
| Система сборки ядер       | Не сделано      | Нужно решить, как подключать .cl файлы   |
| Host-часть (остальное)    | Частично        | Нужно проверить остальные cpp файлы      |
| Тестирование              | Не начато       |                                          |

---

### План дальнейших работ (по этапам)

**Этап 2 — Система сборки ядер (сейчас)**
- Решить, как программа будет загружать ядра (один файл или несколько)
- Сделать так, чтобы всё работало из папки `cl/`

**Этап 3 — Проверка и доработка host-части**
- Проверить остальные файлы (KeySearchDevice, main и т.д.)
- Согласовать всё между собой

**Этап 4 — Первое тестирование**
- Собрать проект
- Проверить, что ядра компилируются
- Проверить базовую работоспособность

**Этап 5 — Оптимизация производительности**
- Более агрессивные оптимизации в secp256k1
- Настройка параметров запуска (-b, -t, -p)
- Возможные улучшения batch-операций

**Этап 6 — Финальная стабилизация**
- Исправление багов
- Документация
- Релиз v1.0

---

### Важные правила работы

1. Все изменения делаем только в `new_version_v1`
2. Старую версию (`old example`) не трогаем — она образец
3. Каждый важный файл переписывается полностью
4. Твоя система `massiv_main2` сохраняется всегда
5. После каждого этапа обновляем этот файл STRUCTURE.md

---

### Следующий шаг (сейчас)

Решаем систему подключения OpenCL-ядер.

Варианты:
1. Оставить отдельные файлы в папке `cl/` и научить программу их читать/склеивать
2. Сделать один большой `bitcrack.cl` (проще для текущей сборки)




|   .gitattributes
|   .gitignore
|   BitCrack.props
|   BitCrack.sln
|   LICENSE.MIT
|   Makefile
|   README.md
|   Отличия.txt
|
+---AddressUtil
|       AddressUtil.h
|       AddressUtil.vcxproj
|       Base58.cpp
|       hash.cpp
|       Makefile
|
+---AddrGen
|       AddrGen.vcxproj
|       main.cpp
|       Makefile
|
+---clKeyFinder
|       clKeyFinder.vcxproj
|
+---CLKeySearchDevice
|       bitcrack.cl
|       CLKeySearchDevice.cpp
|       CLKeySearchDevice.h
|       CLKeySearchDevice.vcxproj
|       keysearch.cl
|       Makefile
|
+---clMath
|       clMath.vcxproj
|       ripemd160.cl
|       secp256k1.cl
|       sha256.cl
|
+---CLUnitTests
|       CLUnitTests.vcxproj
|       main.cpp
|       Makefile
|       secp256k1test.cl
|
+---clUtil
|       clContext.cpp
|       clContext.h
|       clerrors.cpp
|       clUtil.cpp
|       clutil.h
|       clUtil.vcxproj
|       Makefile
|
+---CmdParse
|       CmdParse.cpp
|       CmdParse.h
|       CmdParse.vcxproj
|       Makefile
|
+---CryptoUtil
|       checksum.cpp
|       CryptoUtil.h
|       CryptoUtil.vcxproj
|       hash.cpp
|       Makefile
|       ripemd160.cpp
|       Rng.cpp
|       sha256.cpp
|
+---cudaInfo
|       cudaInfo.vcxproj
|       main.cpp
|       Makefile
|
+---CudaKeySearchDevice
|       CudaAtomicList.cu
|       CudaAtomicList.cuh
|       CudaAtomicList.h
|       cudabridge.cu
|       cudabridge.h
|       CudaDeviceKeys.cu
|       CudaDeviceKeys.cuh
|       CudaDeviceKeys.h
|       CudaHashLookup.cu
|       CudaHashLookup.cuh
|       CudaHashLookup.h
|       CudaKeySearchDevice.cpp
|       CudaKeySearchDevice.cu
|       CudaKeySearchDevice.h
|       CudaKeySearchDevice.vcxproj
|       Makefile
|
+---cudaMath
|       cudaMath.vcxproj
|       ptx.cuh
|       ripemd160.cuh
|       secp256k1.cuh
|       sha256.cuh
|
+---cudaUtil
|       cudaUtil.cpp
|       cudaUtil.h
|       cudaUtil.vcxproj
|       Makefile
|
+---embedcl
|       embedcl.vcxproj
|       main.cpp
|       Makefile
|
+---KeyFinder
|       ConfigFile.cpp
|       ConfigFile.h
|       DeviceManager.cpp
|       DeviceManager.h
|       KeyFinder.vcxproj
|       main.cpp
|       Makefile
|
+---KeyFinderLib
|       KeyFinder.cpp
|       KeyFinder.h
|       KeyFinderLib.vcxproj
|       KeyFinderShared.h
|       KeySearchDevice.h
|       KeySearchTypes.h
|       Makefile
|
+---Logger
|       Logger.cpp
|       Logger.h
|       Logger.vcxproj
|       Makefile
|
+---secp256k1lib
|       Makefile
|       secp256k1.cpp
|       secp256k1.h
|       secp256k1lib.vcxproj
|
+---tools
|       embedcl.exe
|
\---util
        Makefile
        util.cpp
        util.h
        util.vcxproj
