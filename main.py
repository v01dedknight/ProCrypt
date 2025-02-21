import sys
import os
import random
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QCheckBox, QPushButton, QSpinBox, QLabel, QDoubleSpinBox, QFileDialog, QLineEdit, QMessageBox, QTableView, QInputDialog
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QStringListModel, Qt
from PyQt5 import QtCore
from PyQt5.uic import loadUi
from PyQt5.QtSql import QSqlDatabase, QSqlTableModel
import hashlib
import string
import re
import py7zr
from PIL import Image
from PIL.ExifTags import TAGS
import subprocess
import shutil
import sqlite3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

# Генерирует ключ шифрования из пароля с использованием соли
def generate_key_from_password(password, salt):
    return PBKDF2(password, salt, dkLen=32)  # dkLen=32 делает ключ подходящим для AES-256

# Шифрует пароль с использованием AES-256
def encrypt_password(password, encryption_key):
    cipher = AES.new(encryption_key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted).decode('utf-8')

# Расшифровывает пароль, зашифрованный AES-256
def decrypt_password(encrypted_password, encryption_key):
    encrypted_data = base64.b64decode(encrypted_password)
    iv = encrypted_data[:AES.block_size]
    encrypted_password = encrypted_data[AES.block_size:]
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_password), AES.block_size).decode('utf-8')

# Возвращает абсолютный путь к ресурсу, совместимый с PyInstaller
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller упаковывает ресурсы в эту папку
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Возвращает путь к базе данных и копирует её в рабочую директорию, если это необходимо
def get_database_path():
    app_data_dir = os.path.abspath(".")  # Рабочая директория приложения
    db_source_path = resource_path('data/PM.db')  # База данных внутри архива
    db_target_path = os.path.join(app_data_dir, 'PM.db')  # Копия базы данных в рабочей директории

    # Если базы данных ещё нет в рабочей директории, скопировать её
    if not os.path.exists(db_target_path):
        try:
            shutil.copy(db_source_path, db_target_path)
        except Exception as e:
            QMessageBox.critical(None, "Ошибка", f"Не удалось скопировать базу данных: {e}")
            sys.exit(1)  # Завершение программы, если копирование невозможно

    return db_target_path

# Функция для инициализации базы данных
# Создаёт таблицу Passwords в базе данных PM.db, если её ещё нет
def initialize_password_manager_db():
    db_path = get_database_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Создание таблицы "Passwords"
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password TEXT,
            archive_name TEXT,
            archive_folder TEXT
        )
    ''')

    conn.commit()
    conn.close()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        ui_path = os.path.join(os.path.dirname(__file__), 'data', 'main.ui')
        loadUi(ui_path, self)  # Загрузка главного окна

        # Подключение события внутри окна для работы с метаданными
        self.browse_button_2.clicked.connect(self.browse_image)
        self.watch_md_button.clicked.connect(self.display_metadata)
        self.I_agree_checkBox_2.stateChanged.connect(self.toggle_clear_button)
        self.clear_md_button.clicked.connect(self.clear_metadata)

        # Блокировка кнопки для очистки метаданных
        self.clear_md_button.setEnabled(False)

        # Настройка виджетов
        self.setup_gen_enc_arch_tab()

        # Настройка интерфейса
        self.setup_password_manager()

        # Виджеты внутри вкладки с проверкой защиты
        self.protect_tab = self.tabWidget.findChild(QWidget, 'Protect')
        self.pass_edit_prcheck = self.protect_tab.findChild(QLineEdit, 'pass_edit_prcheck')
        self.pass_edit_prcheck.textChanged.connect(self.toggle_test_button)
        self.pass_edit_prcheck.textChanged.connect(self.toggle_save_button)
        self.toggle_test_button()
        self.toggle_save_button()
        self.ProcPower_SpinBox = self.protect_tab.findChild(QDoubleSpinBox, 'ProcPower_SpinBox')
        self.Test_button = self.protect_tab.findChild(QPushButton, 'Test_button')
        self.years_label = self.protect_tab.findChild(QLabel, 'years')
        self.months_label = self.protect_tab.findChild(QLabel, 'months')
        self.days_label = self.protect_tab.findChild(QLabel, 'days')
        self.hours_label = self.protect_tab.findChild(QLabel, 'hours')
        self.minutes_label = self.protect_tab.findChild(QLabel, 'minutes')
        self.seconds_label = self.protect_tab.findChild(QLabel, 'seconds')
        self.Save_button = self.protect_tab.findChild(QPushButton, 'Save_button')

        # Подключение события при нажатии кнопки к методу расчёта времени
        self.Test_button.clicked.connect(self.calculate_time)
        self.Save_button.clicked.connect(self.save_results)

        # Виджеты внутри вкладки MakePass
        self.makepass_tab = self.tabWidget.findChild(QWidget, 'MakePass')
        self.symbols_button = self.makepass_tab.findChild(QCheckBox, 'spsymbols_button')
        self.Generate_button = self.makepass_tab.findChild(QPushButton, 'Generate_button')
        self.length_spinBox = self.makepass_tab.findChild(QSpinBox, 'length_spinBox')
        self.main_lineEdit = self.makepass_tab.findChild(QLineEdit, 'main_lineEdit')
        self.china_button = self.makepass_tab.findChild(QCheckBox, 'china_button')
        self.all_button = self.makepass_tab.findChild(QCheckBox, 'all_button')
        self.all_button.stateChanged.connect(self.toggle_all_checkboxes)

        # Флажки для алфавитов
        self.english_button = self.makepass_tab.findChild(QCheckBox, 'english_button')
        self.numbers_button = self.makepass_tab.findChild(QCheckBox, 'numbers_button')
        self.russian_button = self.makepass_tab.findChild(QCheckBox, 'russian_button')
        self.bulgarian_button = self.makepass_tab.findChild(QCheckBox, 'bulgarian_button')
        self.serbian_button = self.makepass_tab.findChild(QCheckBox, 'serbian_button')
        self.macedonian_button = self.makepass_tab.findChild(QCheckBox, 'macedonian_button')
        self.greek_button = self.makepass_tab.findChild(QCheckBox, 'greek_button')
        self.japanese_button = self.makepass_tab.findChild(QCheckBox, 'japanese_button')
        self.korean_button = self.makepass_tab.findChild(QCheckBox, 'korean_button')
        self.german_button = self.makepass_tab.findChild(QCheckBox, 'german_button')
        self.spanish_button = self.makepass_tab.findChild(QCheckBox, 'spanish_button')
        self.french_button = self.makepass_tab.findChild(QCheckBox, 'french_button')
        self.Generate_button.clicked.connect(self.generate_password)

        # Подключение галочек к методу проверки состояния
        self.symbols_button.stateChanged.connect(self.toggle_generate_button)
        self.english_button.stateChanged.connect(self.toggle_generate_button)
        self.numbers_button.stateChanged.connect(self.toggle_generate_button)
        self.china_button.stateChanged.connect(self.toggle_generate_button)
        self.russian_button.stateChanged.connect(self.toggle_generate_button)
        self.bulgarian_button.stateChanged.connect(self.toggle_generate_button)
        self.serbian_button.stateChanged.connect(self.toggle_generate_button)
        self.macedonian_button.stateChanged.connect(self.toggle_generate_button)
        self.greek_button.stateChanged.connect(self.toggle_generate_button)
        self.japanese_button.stateChanged.connect(self.toggle_generate_button)
        self.korean_button.stateChanged.connect(self.toggle_generate_button)
        self.german_button.stateChanged.connect(self.toggle_generate_button)
        self.spanish_button.stateChanged.connect(self.toggle_generate_button)
        self.french_button.stateChanged.connect(self.toggle_generate_button)

        # Установка названия окна
        self.setWindowTitle("ProCrypt")

        # Запрет на изменение размера окна
        self.setFixedSize(self.size())

        # Загрузка иконки для окна
        icon_path = os.path.join(os.path.dirname(__file__), 'data', 'icon.png')
        self.setWindowIcon(QIcon(icon_path))

        # Проверка начального состояния галочек
        self.toggle_generate_button()

    # Получить расшифрованный пароль из базы данных
    def get_password_from_database(self, record_id, input_password):
        db_path = os.path.join(os.path.dirname(__file__), 'PM.db')
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Извлекаем данные из базы
            cursor.execute("SELECT password, salt FROM Passwords WHERE id = ?", (record_id,))
            result = cursor.fetchone()
            conn.close()

            if result and result[0]:
                encrypted_password, salt = result[0], base64.b64decode(result[1])

                # Генерируем ключ из введённого пароля
                encryption_key = generate_key_from_password(input_password, salt)

                # Расшифровываем пароль
                return decrypt_password(encrypted_password, encryption_key)

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось получить пароль: {e}")
        return None

    # Настройка вкладки password_manager
    def setup_password_manager(self):
        # Подключение виджетов
        self.pass_fordb_lineEdit = self.findChild(QLineEdit, "pass_fordb_lineEdit")
        self.pass_delete_pushButton = self.findChild(QPushButton, "pass_delete_pushButton")
        self.pass_copy_pushButton = self.findChild(QPushButton, "pass_copy_pushButton")
        self.pass_edit_pushButton = self.findChild(QPushButton, "pass_edit_pushButton")
        self.open_arch_pushButton = self.findChild(QPushButton, "open_arch_pushButton")
        self.iagree_checkBox = self.findChild(QCheckBox, "iagree_checkBox")
        self.db_tableView = self.findChild(QTableView, "db_tableView")

        # Подключение события
        self.iagree_checkBox.stateChanged.connect(self.toggle_password_manager_buttons)
        self.pass_delete_pushButton.clicked.connect(self.delete_selected_password)
        self.pass_copy_pushButton.clicked.connect(self.copy_password_to_lineedit)
        self.pass_edit_pushButton.clicked.connect(self.edit_password_in_database)
        self.open_arch_pushButton.clicked.connect(self.open_selected_archive)
        self.toggle_password_manager_buttons()  # Начальное состояние

        # Настройка отображения таблицы
        self.setup_password_manager_table()

    # Обновление пароля в базе данных из pass_fordb_lineEdit
    def edit_password_in_database(self):
        selection_model = self.db_tableView.selectionModel()
        if not selection_model.hasSelection():
            QMessageBox.warning(self, "Ошибка", "Выберите запись для редактирования.")
            return

        # Новый пароль из поля
        new_password = self.pass_fordb_lineEdit.text().strip()
        if not new_password:
            QMessageBox.warning(self, "Ошибка", "Поле пароля не может быть пустым.")
            return

        # Индекс выбранной строки
        index = selection_model.currentIndex()
        row = index.row()
        record = self.passwords_model.record(row)
        record_id = record.value("id")

        # Обновление пароля в базе данных
        query = QSqlDatabase.database().exec(
            f"UPDATE Passwords SET password='{new_password}' WHERE id={record_id}"
        )
        if query.lastError().isValid():
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить пароль: {query.lastError().text()}")
        else:
            self.refresh_password_manager_table()
            QMessageBox.information(self, "Успех", "Пароль успешно обновлён.")

    # Вкл выкл кнопок в Password Manager
    def toggle_password_manager_buttons(self):
        state = self.iagree_checkBox.isChecked()
        self.pass_delete_pushButton.setEnabled(state)
        self.pass_copy_pushButton.setEnabled(state)
        self.pass_edit_pushButton.setEnabled(state)
        self.open_arch_pushButton.setEnabled(state)

    # Настройка отображения таблицы Passwords в db_tableView с фильтрацией NULL-значений
    def setup_password_manager_table(self):
        db_path = get_database_path()

        # Подключение базы данных
        self.db = QSqlDatabase.addDatabase("QSQLITE")
        self.db.setDatabaseName(db_path)

        if not self.db.open():
            QMessageBox.critical(self, "Ошибка", "Не удалось подключиться к базе данных.")
            return

        # Настройка модели таблицы
        self.passwords_model = QSqlTableModel(self, self.db)
        self.passwords_model.setTable("Passwords")
        
        # Фильтрация записи, где хотя бы один столбец NULL
        self.passwords_model.setFilter("password IS NOT NULL AND archive_name IS NOT NULL AND archive_folder IS NOT NULL")
        self.passwords_model.select()  # Применение фильтра и загрузка данных

        # Названия столбцов
        self.passwords_model.setHeaderData(1, Qt.Horizontal, "Пароль")
        self.passwords_model.setHeaderData(2, Qt.Horizontal, "Название архива")
        self.passwords_model.setHeaderData(3, Qt.Horizontal, "Путь к архиву")

        # Настройка представления
        self.db_tableView.setModel(self.passwords_model)
        self.db_tableView.setEditTriggers(QTableView.NoEditTriggers)  # Только для просмотра
        self.db_tableView.hideColumn(0)  # Убрать колонку 'id'

    # Обновление данных в db_tableView с учётом фильтра
    def refresh_password_manager_table(self):
        self.passwords_model.setFilter("password IS NOT NULL AND archive_name IS NOT NULL AND archive_folder IS NOT NULL")
        self.passwords_model.select()

    # Копирует пароль из выбранной записи в pass_fordb_lineEdit
    def copy_password_to_lineedit(self):
        selection_model = self.db_tableView.selectionModel()
        if not selection_model.hasSelection():
            QMessageBox.warning(self, "Ошибка", "Выберите запись для копирования пароля.")
            return

        # Индекс выбранной строки
        index = selection_model.currentIndex()
        row = index.row()
        record = self.passwords_model.record(row)
        password = record.value("password")

        if password is None:
            QMessageBox.warning(self, "Ошибка", "У выбранной записи нет пароля.")
            return

        # Очистить поле и вставить пароль
        self.pass_fordb_lineEdit.clear()
        self.pass_fordb_lineEdit.setText(password)

    # Открыть архив с использованием пароля из базы данных.
    def open_selected_archive(self):
        selected_index = self.db_tableView.currentIndex()
        if not selected_index.isValid():
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, выберите запись в таблице.")
            return

        # Получаем данные о выбранной записи
        record_id = self.passwords_model.data(self.passwords_model.index(selected_index.row(), 0))  # ID записи
        archive_path = self.passwords_model.data(self.passwords_model.index(selected_index.row(), 2))  # Путь к архиву
        encrypted_password = self.passwords_model.data(self.passwords_model.index(selected_index.row(), 1))  # Зашифрованный пароль

        if not archive_path:
            QMessageBox.warning(self, "Ошибка", "Путь к архиву отсутствует в базе данных.")
            return

        # Преобразуем путь в абсолютный, если он относительный
        if not os.path.isabs(archive_path):
            archive_path = os.path.abspath(os.path.join(os.path.dirname(__file__), archive_path))

        if not os.path.isfile(archive_path):
            QMessageBox.warning(self, "Ошибка", f"Файл архива не найден по пути: {archive_path}")
            return

        try:
            # Получаем соль из базы данных
            db_path = os.path.join(os.path.dirname(__file__), 'PM.db')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT salt FROM Passwords WHERE id = ?", (record_id,))
            result = cursor.fetchone()
            conn.close()

            if not result or not result[0]:
                QMessageBox.critical(self, "Ошибка", "Соль для записи не найдена.")
                return

            salt = base64.b64decode(result[0])  # Декодируем соль
            encryption_key = generate_key_from_password("your_password_for_key", salt)  # Пароль для ключа

            # Расшифровываем пароль
            decrypted_password = decrypt_password(encrypted_password, encryption_key)

            # Открываем архив
            with py7zr.SevenZipFile(archive_path, mode='r', password=decrypted_password) as archive:
                extract_path = QFileDialog.getExistingDirectory(self, "Выберите папку для извлечения")
                if not extract_path:
                    return  # Пользователь отменил выбор
                archive.extractall(extract_path)
                QMessageBox.information(self, "Успех", f"Архив успешно извлечён в: {extract_path}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть архив: {e}")


    # Удаляет выбранную запись из базы данных Passwords
    def delete_selected_password(self):
        selected_index = self.db_tableView.currentIndex()
        if not selected_index.isValid():
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, выберите запись для удаления.")
            return

        # Получаем ID записи
        record_id = self.passwords_model.data(self.passwords_model.index(selected_index.row(), 0))  # ID записи

        db_path = os.path.join(os.path.dirname(__file__), 'PM.db')
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Удаляем запись из базы данных
            cursor.execute("DELETE FROM Passwords WHERE id = ?", (record_id,))
            conn.commit()
            conn.close()

            # Обновляем таблицу
            self.refresh_password_manager_table()
            QMessageBox.information(self, "Успех", "Запись успешно удалена.")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить запись: {e}")


    # Настройка вкладки GenEncArch
    def setup_gen_enc_arch_tab(self):
        self.method_comboBox.addItems(["LZMA2", "LZMA", "PPMd", "BZip2"])
        self.method_comboBox.setCurrentText("LZMA2")
        self.level_comboBox.addItems([
            "0 - Без сжатия", "1 - Скоростной", "3 - Быстрый",
            "5 - Нормальный", "7 - Максимальный", "9 - Ультра"
        ])
        self.level_comboBox.setCurrentText("5 - Нормальный")
        self.enc_method_comboBox.addItem("AES-256")
        self.enc_method_comboBox.setCurrentText("AES-256")

        # Связка кнопок с функциями
        self.browse_button.clicked.connect(self.select_folder)
        self.create_arc_button.clicked.connect(self.create_encrypted_archive)
        self.nopass_checkBox.stateChanged.connect(self.toggle_password_options)
        self.I_agree_checkBox.stateChanged.connect(self.toggle_create_button)

        self.saveindb_checkBox = self.findChild(QCheckBox, "saveindb_checkBox")

        # Изначально выключить кнопку создания архива
        self.create_arc_button.setEnabled(False)

    # Активировать или деактивировать кнопку создания архива в зависимости от чекбокса
    def toggle_create_button(self):
        self.create_arc_button.setEnabled(self.I_agree_checkBox.isChecked())

    # Открыть проводник для выбора папки
    def select_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Выберите папку для архивации")
        if folder_path:
            self.folder_edit.setText(folder_path)

    # Включить/выключить элементы управления для шифрования
    def toggle_password_options(self):
        nopass_active = self.nopass_checkBox.isChecked()
        self.password_arch_edit.setEnabled(not nopass_active)
        self.filenames_checkBox.setEnabled(not nopass_active)
        self.enc_method_comboBox.setEnabled(not nopass_active)

    # Создать архив с учётом состояния чекбоксов
    def create_encrypted_archive(self):
        folder_path = self.folder_edit.text().strip()
        if not folder_path or not os.path.isdir(folder_path):
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, выберите корректную папку!")
            return

        options = QFileDialog.Options()
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить архив",
            "",
            "7z Archives (*.7z)",
            options=options
        )

        if not save_path:
            return  # Пользователь отменил выбор

        password = self.password_arch_edit.text().strip() if not self.nopass_checkBox.isChecked() else None
        if not password and not self.nopass_checkBox.isChecked():
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, укажите пароль или выберите режим без шифрования!")
            return

        # Настройка параметров архивации
        method = self.method_comboBox.currentText()
        compression_level = self.level_comboBox.currentText().split(" - ")[0]  # Уровень сжатия
        encrypt_filenames = self.filenames_checkBox.isChecked()  # Шифрование имён файлов
        enable_sorting = self.sorting_checkBox.isChecked()  # Сортировка файлов

        # Категории для сортировки
        categories = {
            "Видео": [".mp4", ".avi", ".mkv", ".mov"],
            "Фото": [".jpg", ".jpeg", ".png", ".bmp", ".gif"],
            "Документы": [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt"],
            "Другое": []
        }

        # Создание временной структуры, если включена сортировка
        temp_dir = None
        source_path = folder_path  # По умолчанию архивировать исходную папку
        if enable_sorting:
            temp_dir = os.path.join(os.path.dirname(save_path), "temp_sorted")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Создание подпапки с именем исходной директории
            original_folder_name = os.path.basename(folder_path)
            sorted_folder = os.path.join(temp_dir, original_folder_name)
            os.makedirs(sorted_folder, exist_ok=True)

            try:
                # Распределение файлов по категориям
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_ext = os.path.splitext(file)[1].lower()

                        # Определение категории
                        target_category = "Другое"  # По умолчанию
                        for category, extensions in categories.items():
                            if file_ext in extensions:
                                target_category = category
                                break

                        # Копировать файл в соответствующую категорию
                        category_dir = os.path.join(sorted_folder, target_category)
                        os.makedirs(category_dir, exist_ok=True)
                        shutil.copy(file_path, category_dir)

                # Архивировать подпапку, содержащую исходное имя
                source_path = sorted_folder
            except Exception as e:
                shutil.rmtree(temp_dir, ignore_errors=True)
                QMessageBox.critical(self, "Ошибка", f"Ошибка при сортировке файлов: {e}")
                return

        try:
            # Формировать команду для создания архива
            command = [
                rf"C:\Program Files\7-Zip\7z.exe", "a",  # Команда "add" для создания архива
                save_path,  # Путь к создаваемому архиву
                source_path,  # Исходная папка для архивации
                f"-mx={compression_level}",  # Уровень сжатия
                f"-m0={method.lower()}"  # Метод сжатия
            ]

            # Добавить параметры шифрования имён файлов, если включен чекбокс
            if encrypt_filenames:
                command.append("-mhe=on")

            # Добавить пароль, если чекбокс не активен
            if password:
                command.append(f"-p{password}")

            # Процесс создания архива
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Проверка результата
            if result.returncode == 0:
                QMessageBox.information(self, "Успех", f"Архив успешно создан: {save_path}")
                
                # Сохранить информацию в базу данных, если активен чекбокс
                if self.saveindb_checkBox.isChecked():
                    self.save_archive_to_database(password, os.path.basename(save_path), save_path)

            else:
                QMessageBox.critical(self, "Ошибка", f"Не удалось создать архив: {result.stderr.decode()}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка при создании архива: {e}")
        finally:
            # Удаление временной папки, если она была создана
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    # Сохраняет запись с зашифрованным паролем в базу данных
    def save_archive_to_database(self, password, archive_name, archive_folder):
        db_path = os.path.join(os.path.dirname(__file__), 'PM.db')
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Генерация соли
            salt = os.urandom(16)

            # Генерация ключа и шифрование пароля
            encryption_key = generate_key_from_password(password, salt)
            encrypted_password = encrypt_password(password, encryption_key)

            # Сохранение данных в базу
            cursor.execute('''
                INSERT INTO Passwords (password, archive_name, archive_folder, salt)
                VALUES (?, ?, ?, ?)
            ''', (encrypted_password, archive_name, archive_folder, base64.b64encode(salt).decode('utf-8')))

            conn.commit()
            conn.close()
            self.refresh_password_manager_table()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить запись: {e}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить запись в базу данных: {e}")

    # Создание архива с указанным паролем
    def create_single_archive(self, source, destination, password=None):
        command = [
            rf"C:\Program Files\7-Zip\7z.exe", "a",
            destination,
            source,
            "-mx=5",  # Уровень сжатия
        ]
        if password:
            command.append(f"-p{password}")
            command.append("-mhe=on")

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise Exception(result.stderr.decode())

    # Включить или отключить кнопку в зависимости от состояния чекбокса
    def toggle_clear_button(self, state):
        self.clear_md_button.setEnabled(state == QtCore.Qt.Checked)

    # Удалить метаданные и копия изображения
    def clear_metadata(self):
        file_path = self.picture_edit.text().strip()
        if not file_path or not os.path.isfile(file_path):
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, выберите корректный файл изображения!")
            return

        # Открыть диалог для выбора пути сохранения нового файла
        options = QFileDialog.Options()
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить изображение без метаданных",
            os.path.splitext(file_path)[0] + "_no_metadata.jpg",
            "Images (*.jpg *.jpeg)",
            options=options
        )

        if not save_path:
            return  # Пользователь отменил выбор

        try:
            # Убрать метаданные из изображения
            with Image.open(file_path) as img:
                data = list(img.getdata())  # Извлечение пикселей
                new_image = Image.new(img.mode, img.size)  # Новое изображение
                new_image.putdata(data)  # Перемещение пикселей в новое изображение

                # Сохранение нового изображения без метаданных
                new_image.save(save_path)
                QMessageBox.information(self, "Успех", f"Изображение сохранено без метаданных: {save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить метаданные: {e}")

    # Обработчик для выбора изображения
    def browse_image(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите изображение",
            "",
            "Images (*.jpg *.jpeg)",
            options=options
        )
        if file_path:
            self.picture_edit.setText(file_path)  # Путь в поле ввода

    # Обработчик для отображения метаданных
    def display_metadata(self):
        file_path = self.picture_edit.text().strip()
        if not file_path or not os.path.isfile(file_path):
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, выберите корректный файл изображения!")
            return

        try:
            # Открыть изображение и извлечь EXIF-данные
            image = Image.open(file_path)
            exif_data = image._getexif()
            metadata = []

            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)  # Имя тега
                    metadata.append(f"{tag_name}: {value}")
            else:
                metadata.append("Метаданные отсутствуют")

            # Отображение метаданных
            model = QStringListModel()
            model.setStringList(metadata)
            self.listView.setModel(model)

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать метаданные: {e}")

    # Переключение всех чекбоксов
    def toggle_all_checkboxes(self, state):
        self.russian_button.setChecked(state)
        self.bulgarian_button.setChecked(state)
        self.serbian_button.setChecked(state)
        self.macedonian_button.setChecked(state)
        self.greek_button.setChecked(state)
        self.japanese_button.setChecked(state)
        self.korean_button.setChecked(state)
        self.german_button.setChecked(state)
        self.spanish_button.setChecked(state)
        self.french_button.setChecked(state)
        self.symbols_button.setChecked(state)
        self.english_button.setChecked(state)
        self.numbers_button.setChecked(state)
        self.china_button.setChecked(state)

    # Переключение кнопки генерации
    def toggle_generate_button(self):
        if (self.symbols_button.isChecked() or self.english_button.isChecked() or self.numbers_button.isChecked() or
            self.china_button.isChecked() or self.russian_button.isChecked() or self.bulgarian_button.isChecked() or
            self.serbian_button.isChecked() or self.macedonian_button.isChecked() or self.greek_button.isChecked() or
            self.japanese_button.isChecked() or self.korean_button.isChecked() or self.german_button.isChecked() or
            self.spanish_button.isChecked() or self.french_button.isChecked()):
            self.Generate_button.setEnabled(True)
        else:
            self.Generate_button.setEnabled(False)

    # Переключение кнопки проверки
    def toggle_test_button(self):
        password = self.pass_edit_prcheck.text()
        if password:
            self.Test_button.setEnabled(True)
        else:
            self.Test_button.setEnabled(False)

    # Переключение кнопки сохранения
    def toggle_save_button(self):
        password = self.pass_edit_prcheck.text()
        if password:
            self.Save_button.setEnabled(True)
        else:
            self.Save_button.setEnabled(False)

    # Вычисление времени подбора пароля
    def calculate_time(self):
        password = self.pass_edit_prcheck.text()
        if not password:
            self.output_label.setText("Введите пароль!")
            return

        password_length = len(password)
        if self.dictionaries_checkBox.isChecked():
            charset_size = self.determine_charset_size(password)
        else:
            charset_size = sum([
                32,  # special characters
                20902,  # chinese characters
                256,  # russian characters
                32,  # bulgarian characters
                6,  # serbian characters
                18,  # macedonian characters
                134,  # greek characters
                234,  # japanese characters
                256,  # korean characters
                7,  # german characters
                13,  # spanish characters
                42  # french characters
            ])

        hashes_per_second_millions = self.ProcPower_SpinBox.value()
        hashes_per_second = hashes_per_second_millions * 10**6

        time_seconds = self.calculate_bruteforce_time(password_length, charset_size, hashes_per_second)
        human_readable_time = self.seconds_to_human_readable(time_seconds)

        self.years_label.setText(str(human_readable_time.get('years', 0)))
        self.months_label.setText(str(human_readable_time.get('months', 0)))
        self.days_label.setText(str(human_readable_time.get('days', 0)))
        self.hours_label.setText(str(human_readable_time.get('hours', 0)))
        self.minutes_label.setText(str(human_readable_time.get('minutes', 0)))
        self.seconds_label.setText(str(human_readable_time.get('seconds', 0)))

        # Определение уровня безопасности только если пароль не пустой
        if password:
            security_level = self.calculate_security_level(time_seconds)
            self.prot_level_fchange.setText(security_level)

    # Вычисление уровня надёжности пароля
    def calculate_security_level(self, time_seconds):
        if time_seconds <= 60:
            return "Очень низкий"
        elif time_seconds <= 3600:
            return "Низкий"
        elif time_seconds <= 86400:
            return "Средний"
        elif time_seconds <= 2628000:
            return "Высокий"
        elif time_seconds <= 31536000:
            return "Очень высокий"
        else:
            return "Лучший"

    # Хэш пароля
    def hash_password_sha256(self, password):
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        return sha256.hexdigest()

    # Вычисление времени на перебор
    def calculate_bruteforce_time(self, password_length, charset_size, hashes_per_second):
        # Проверка, не превышает ли общее количество комбинаций максимально возможное значение типа float
        if charset_size ** password_length > sys.float_info.max:
            time_seconds = float('inf')  # Установка времени как бесконечность
        else:
            time_seconds = (charset_size ** password_length) / hashes_per_second
        return time_seconds

    # Вывод времени перебора
    def seconds_to_human_readable(self, seconds):
        intervals = {
            'years': seconds // 31536000,
            'months': seconds // 2628000 % 12,
            'days': seconds // 86400 % 30,
            'hours': seconds // 3600 % 24,
            'minutes': seconds // 60 % 60,
            'seconds': seconds % 60
        }
        
        return intervals

    # Знаки в словаре
    def determine_charset_size(self, password):
        charset_size = 0

        special_characters = string.punctuation
        chinese_characters = re.compile(r'[\u4e00-\u9fff]')
        russian_characters = re.compile(r'[\u0400-\u052F]')
        bulgarian_characters = re.compile(r'[\u0410-\u044F]')
        serbian_characters = re.compile(r'[\u040A-\u040F]')
        macedonian_characters = re.compile(r'[\u0400-\u040FЌќЅѕЏџ]')
        greek_characters = re.compile(r'[\u0370-\u03FF]')
        japanese_characters = re.compile(r'[\u3040-\u30FF]')
        korean_characters = re.compile(r'[\u1100-\u11FF]')
        german_characters = re.compile(r'[äöüßÄÖÜ]')
        spanish_characters = re.compile(r'[áéíóúüñ¿¡ÁÉÍÓÚÜÑ]')
        french_characters = re.compile(r'[àâæçéèêëîïôœùûüÿÀÂÆÇÉÈÊËÎÏÔŒÙÛÜŸ]')

        if any(char in special_characters for char in password):
            charset_size += 32
        if any(chinese_characters.match(char) for char in password):
            charset_size += 20902
        if any(russian_characters.match(char) for char in password):
            charset_size += 256
        if any(bulgarian_characters.match(char) for char in password):
            charset_size += 32
        if any(serbian_characters.match(char) for char in password):
            charset_size += 6
        if any(macedonian_characters.match(char) for char in password):
            charset_size += 18
        if any(greek_characters.match(char) for char in password):
            charset_size += 134
        if any(japanese_characters.match(char) for char in password):
            charset_size += 234
        if any(korean_characters.match(char) for char in password):
            charset_size += 256
        if any(german_characters.match(char) for char in password):
            charset_size += 7
        if any(spanish_characters.match(char) for char in password):
            charset_size += 13
        if any(french_characters.match(char) for char in password):
            charset_size += 42
        
        # Если размер набора символов равен нулю, установить его равным 1, чтобы избежать деления на ноль
        if charset_size == 0:
            charset_size = 1

        return charset_size

    # Функция генерации пароля
    def generate_password(self):
        password_length = self.length_spinBox.value()

        charset = ""

        if self.english_button.isChecked():
            charset += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self.numbers_button.isChecked():
            charset += "0123456789"
        if self.symbols_button.isChecked():
            charset += "!@#$%^&*()-_=+[]{}|;:,.<>?~/"
        if self.china_button.isChecked():
            charset += ''.join(chr(random.randint(0x4e00, 0x9fff)) for _ in range(100))

        if self.russian_button.isChecked():
            charset += ''.join(chr(code) for code in range(0x0400, 0x052F + 1))
        if self.bulgarian_button.isChecked():
            charset += ''.join(chr(code) for code in range(0x0410, 0x044F + 1))
        if self.serbian_button.isChecked():
            charset += ''.join(chr(code) for code in range(0x040A, 0x040F + 1))
        if self.macedonian_button.isChecked():
            charset += ''.join(chr(code) for code in range(0x0400, 0x040F + 1)) + "ЌќЅѕЏџ"
        if self.greek_button.isChecked():
            charset += ''.join(chr(code) for code in range(0x0370, 0x03FF + 1))
        if self.japanese_button.isChecked():
            charset += ''.join(chr(code) for code in range(0x3040, 0x30FF + 1))
        if self.korean_button.isChecked():
            charset += ''.join(chr(code) for code in range(0x1100, 0x11FF + 1))
        if self.german_button.isChecked():
            charset += 'äöüßÄÖÜ'
        if self.spanish_button.isChecked():
            charset += 'áéíóúüñ¿¡ÁÉÍÓÚÜÑ'
        if self.french_button.isChecked():
            charset += 'àâæçéèêëîïôœùûüÿÀÂÆÇÉÈÊËÎÏÔŒÙÛÜŸ'

        password = ''.join(random.choice(charset) for _ in range(password_length))
        self.main_lineEdit.setText(password)

    # Сохранение результатов
    def save_results(self):
        results_text = ""  # Объявление переменной и присвоение пустой строки
        
        # Открыть диалоговое окно выбора файла
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "Text Files (*.txt)", options=options)
        
        if not file_path:
            return  # Отменено пользователем или не выбран файл

        # Проверка, что все поля не пусты
        if (not self.years_label.text() or
            not self.months_label.text() or
            not self.days_label.text() or
            not self.hours_label.text() or
            not self.minutes_label.text() or
            not self.seconds_label.text()):
            self.output_label.setText("Заполните все поля перед сохранением!")
            return

        # Формирование текста для сохранения в файл
        results_text = f"Пароль: {self.pass_edit_prcheck.text()}\n"
        results_text += f"Хэшей в секунду (В миллионах): {self.ProcPower_SpinBox.value()}\n\n"
        results_text += f"Примерное время для подбора пароля:\n"
        results_text += f"Годы: {self.years_label.text()}\n"
        results_text += f"Месяцы: {self.months_label.text()}\n"
        results_text += f"Дни: {self.days_label.text()}\n"
        results_text += f"Часы: {self.hours_label.text()}\n"
        results_text += f"Минуты: {self.minutes_label.text()}\n"
        results_text += f"Секунды: {self.seconds_label.text()}\n"
        results_text += f'Данные расчёты не являются абсолютными и не могут служить точным индикатором надёжности пароля. Оценка времени подбора пароля основана на теоретической вычислительной мощности и не учитывает всех факторов, таких как специфические методы атак, оптимизация алгоритмов или аппаратное обеспечение злоумышленников. Предполагается, что для шифрования используется алгоритм "AES-256".'

        try:
            # Запись текста в файл
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(results_text)
            
            # Уведомление об успешном сохранении
            QMessageBox.information(self, "Успех", "Файл успешно сохранён!")

        except Exception as e:
            # Ошибка при сохранении файла
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл: {e}")

# Главный цикл программы
if __name__ == "__main__":
    initialize_password_manager_db()  # Создать таблицу, если её ещё нет
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())