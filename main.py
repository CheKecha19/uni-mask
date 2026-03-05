#!/usr/bin/env python3
"""
Универсальный маскировщик чувствительных данных.
Поддерживает:
- IP-адреса
- "company" (регистронезависимо)
- Хеши (MD5, SHA1, SHA256 и др.)
- Email
- Номера телефонов (российские и международные)
- Номера кредитных карт (с проверкой Луна)
- СНИЛС (РФ)
- ИНН (РФ)
- Паспортные данные РФ (серия + номер)

Все замены уникальны для каждого исходного значения, восстановление по маске.
"""

import re
import json
import argparse
from pathlib import Path
from typing import Dict, Pattern

# ---------- Функция проверки номера карты по алгоритму Луна ----------
def luhn_check(card_number: str) -> bool:
    """Проверка номера карты алгоритмом Луна (упрощённо, только цифры)."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) not in (15, 16):  # Обычно 16, но бывают 15
        return False
    # Алгоритм Луна
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit
    return checksum % 10 == 0

# ---------- Регулярные выражения для каждой категории ----------
# Каждая запись: (pattern, префикс, опциональная функция валидации)
# Функция валидации принимает строку и возвращает bool (True, если это действительно тот тип)
PATTERNS = {
    'ip': (
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ip',
        None
    ),
    'company': (
        r'company',
        'cmp',
        None
    ),
    'hash': (
        r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{56}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{96}\b|\b[a-fA-F0-9]{128}\b',
        'hash',
        None
    ),
    'email': (
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'email',
        None
    ),
    'phone': (
        # Российские: +7 xxx xxx-xx-xx, 8 xxx xxx xx xx, также международные
        r'(\+?7|8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}|\+?\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{1,4}[\s-]?\d{1,9}',
        'phone',
        None  # Можно добавить более строгую проверку, но пока упрощённо
    ),
    'credit_card': (
        r'\b(?:\d[ -]*?){13,16}\b',  # 13-16 цифр с возможными разделителями
        'cc',
        luhn_check  # Дополнительная проверка алгоритмом Луна
    ),
    'snils': (
        r'\b\d{3}-\d{3}-\d{3} \d{2}\b|\b\d{11}\b',  # СНИЛС: XXX-XXX-XXX YY или 11 цифр подряд
        'snils',
        None
    ),
    'inn': (
        r'\b\d{10}\b|\b\d{12}\b',  # ИНН юрлица (10) или физлица (12)
        'inn',
        None
    ),
    'passport_rf': (
        # Серия паспорта РФ: 4 цифры, затем номер: 6 цифр (возможен пробел/дефис)
        r'\b\d{2}[\s-]?\d{2}[\s-]?\d{6}\b',
        'passport',
        None  # Можно усложнить, но пока так
    )
}

def compile_patterns():
    """Объединяет все паттерны в один regex с именованными группами."""
    parts = []
    for name, (pattern, prefix, validator) in PATTERNS.items():
        parts.append(f'(?P<{name}>{pattern})')
    combined = '|'.join(parts)
    return re.compile(combined, re.IGNORECASE)

# ---------- Основные функции ----------
def mask_file(input_file, output_file, mask_file, custom_prefixes=None):
    """
    Маскирует входной файл.
    custom_prefixes: словарь {имя_категории: префикс} для переопределения префиксов.
    """
    if custom_prefixes is None:
        custom_prefixes = {}

    combined_re = compile_patterns()

    # Словари для маппинга: категория -> {исходное_значение: псевдоним}
    maps = {name: {} for name in PATTERNS}
    counters = {name: 1 for name in PATTERNS}

    def replace_match(match):
        for name in PATTERNS:
            value = match.group(name)
            if value is not None:
                # Дополнительная валидация, если есть
                validator = PATTERNS[name][2]
                if validator and not validator(value):
                    return value  # не заменяем, если проверка не пройдена
                # Получаем префикс: либо кастомный, либо из PATTERNS
                prefix = custom_prefixes.get(name, PATTERNS[name][1])
                if value not in maps[name]:
                    maps[name][value] = f'{prefix}{counters[name]}'
                    counters[name] += 1
                return maps[name][value]
        return match.group(0)  # не должно достигаться

    with open(input_file, 'r', encoding='utf-8') as f_in, \
         open(output_file, 'w', encoding='utf-8') as f_out:
        for line in f_in:
            masked_line = combined_re.sub(replace_match, line)
            f_out.write(masked_line)

    # Сохраняем обратный маппинг (псевдоним -> исходное) для всех категорий
    reverse_maps = {}
    for name, mapping in maps.items():
        reverse_maps[name] = {v: k for k, v in mapping.items()}
    with open(mask_file, 'w', encoding='utf-8') as f_mask:
        json.dump(reverse_maps, f_mask, ensure_ascii=False, indent=2)

    print(f"Маскирование завершено. Результат: {output_file}")
    print(f"Маска сохранена в: {mask_file}")


def unmask_file(input_file, output_file, mask_file):
    """Восстанавливает исходный файл по маске."""
    with open(mask_file, 'r', encoding='utf-8') as f_mask:
        reverse_maps = json.load(f_mask)

    # Объединяем все псевдонимы в один словарь
    all_aliases = {}
    for cat_map in reverse_maps.values():
        all_aliases.update(cat_map)

    if not all_aliases:
        print("Предупреждение: маска пуста.")
        return

    # Сортируем по убыванию длины, чтобы избежать частичных замен (например, ip1 и ip10)
    aliases = sorted(all_aliases.keys(), key=len, reverse=True)
    pattern = r'\b(' + '|'.join(re.escape(a) for a in aliases) + r')\b'
    unmask_re = re.compile(pattern)

    def replace_match(match):
        alias = match.group(1)
        return all_aliases[alias]

    with open(input_file, 'r', encoding='utf-8') as f_in, \
         open(output_file, 'w', encoding='utf-8') as f_out:
        for line in f_in:
            original_line = unmask_re.sub(replace_match, line)
            f_out.write(original_line)

    print(f"Восстановление завершено. Результат: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Маскирование/демаскирование широкого спектра чувствительных данных."
    )
    parser.add_argument('--mode', '-m', required=True, choices=['mask', 'unmask'],
                        help="Режим: mask (замена) или unmask (восстановление)")
    parser.add_argument('--input', '-i', required=True,
                        help="Входной файл")
    parser.add_argument('--output', '-o',
                        help="Выходной файл (по умолчанию: исходное имя + .masked / .restored)")
    parser.add_argument('--mask', '-k',
                        help="Файл маски (JSON). При mask создаётся, при unmask читается.")
    # Опциональные префиксы для каждой категории
    for name in PATTERNS:
        parser.add_argument(f'--{name}-prefix', default=None,
                            help=f"Префикс для замены {name} (по умолчанию: {PATTERNS[name][1]})")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Ошибка: входной файл {input_path} не найден.")
        return

    # Определяем выходной файл
    if args.output:
        output_path = args.output
    else:
        if args.mode == 'mask':
            output_path = input_path.with_suffix('.masked' + input_path.suffix)
        else:
            output_path = input_path.with_suffix('.restored' + input_path.suffix)

    # Определяем файл маски
    if args.mask:
        mask_path = args.mask
    else:
        if args.mode == 'mask':
            mask_path = input_path.with_suffix('.mask.json')
        else:
            print("Ошибка: в режиме unmask необходимо указать файл маски (--mask).")
            return

    if args.mode == 'mask':
        # Собираем кастомные префиксы
        custom_prefixes = {}
        for name in PATTERNS:
            prefix_val = getattr(args, f'{name}_prefix')
            if prefix_val is not None:
                custom_prefixes[name] = prefix_val
        mask_file(input_path, output_path, mask_path, custom_prefixes)
    else:
        if not Path(mask_path).exists():
            print(f"Ошибка: файл маски {mask_path} не найден.")
            return
        unmask_file(input_path, output_path, mask_path)


if __name__ == '__main__':

    main()
