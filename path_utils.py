import os
import sys
import shutil

# Возвращает абсолютный путь к ресурсу
def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Возвращает путь к рабочей (копируемой) версии базы данных
def get_working_db_path():
    app_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)
    return os.path.join(app_dir, "data", "PM.db")

# Проверяет наличие рабочей базы данных. Если отсутствует, копирует оригинал из ресурсов в рабочую директорию
def ensure_database_exists():
    working_db = get_working_db_path()
    if not os.path.exists(working_db):
        original_db = get_resource_path("data/PM.db")
        shutil.copyfile(original_db, working_db)
    return working_db

# Возвращает путь к файлу соли (salt.salt) в рабочей директории
def get_salt_path():
    app_dir = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)
    return os.path.join(app_dir, "data", "salt.salt")

# Проверяет наличие файла соли. Если его нет, копирует оригинал из ресурсов
def ensure_salt_exists():
    salt_path = get_salt_path()
    if not os.path.exists(salt_path):
        original_salt = get_resource_path("data/salt.salt")
        shutil.copyfile(original_salt, salt_path)
    return salt_path
