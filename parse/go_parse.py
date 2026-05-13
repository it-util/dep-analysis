def clean_version(version):
    # Убираем +incompatible
    if '+incompatible' in version:
        version = version.replace('+incompatible', '')
    
    # Убираем комментарии если попали
    if '//' in version:
        version = version.split('//')[0].strip()
    
    return version


def is_local_module(name):
    # Локальные пути
    if name.startswith('./') or name.startswith('../'):
        return True
    
    # Подмодули semaphore
    if '/pro' in name or '/internal' in name:
        return True
    
    return False


def go_parse(path_to_file):
    with open(path_to_file, 'r') as file:
        lines = file.readlines() # возвращает список строк
    
    dependencies = []
    in_require_block = False

    for line in lines:
        line = line.strip()
        
        # Начало блока require
        if line.startswith('require ('):
            in_require_block = True
            continue
        
        # Конец блока require
        if in_require_block and line == ')':
            in_require_block = False
            continue
        
        # Парсим строки внутри блока require
        if in_require_block and line and not line.startswith('//'):
            # Разделяем строку на части
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                
                # Пропускаем локальные модули
                if is_local_module(name):
                    continue
                
                # Очищаем версию
                version = clean_version(version)
                
                dependencies.append({
                    'name': name,
                    'version': version
                })

    return dependencies