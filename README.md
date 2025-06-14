# VanityGen

Быстро находит адреса Ethereum с заданными шаблонами:

- Длинные повторы символов
- Высокий процент одного символа

## Как использовать:
```
./vanitygen 6     # Ищет 6+ одинаковых символов
./vanitygen 7 40  # Или 7+ символов, или 40% повторов
```

## Сборка:
```
sudo pacman -S libssl-dev libsecp256k1
mkdir build && cd build
cmake .. && make
```

Результаты сохраняются в extreme_addresses.txt