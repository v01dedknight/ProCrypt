import sys
import os
import string
import re
import py7zr
import subprocess
import shutil
import sqlite3
import base64
import secrets
import webbrowser
import logging

from PIL import Image
from PIL.ExifTags import TAGS

from PyQt5.QtWidgets import QDialog, QHeaderView, QVBoxLayout, QAction, QWidget, QComboBox, QTextEdit, QCheckBox, QPushButton, QSpinBox, QLabel, QDoubleSpinBox, QFileDialog, QLineEdit, QMessageBox, QTableView, QInputDialog, QListView
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QStringListModel, Qt
from PyQt5 import QtCore, uic, QtWidgets
from PyQt5.QtSql import QSqlDatabase, QSqlTableModel

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle

from lzma import LZMAError

from path_utils import ensure_database_exists, ensure_salt_exists, get_working_db_path, get_salt_path, get_resource_path

import requests

# Логирование (по умолчанию отключено)
logging_enabled = False

# Настройки логирования
def setup_logging():
    global logging_enabled

    logging_enabled = True
    logging.basicConfig(
        filename='procrypt.log',
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

# Логи с пометкой warning
def log_warning(msg, exc=False):
    if logging_enabled:
        logging.warning(msg, exc_info=exc)

# Класс вкладки Менеджер паролей
class Manager(QtWidgets.QWidget):
    def __init__(self, tabWidget, parent=None):
        super().__init__(parent)
        self.tabWidget = tabWidget
        self.manager = self.tabWidget.findChild(QWidget, 'Manager')

        # Виджеты
        self.pass_fordb_lineEdit = self.manager.findChild(QLineEdit, "pass_fordb_lineEdit")
        self.pass_delete_pushButton = self.manager.findChild(QPushButton, "pass_delete_pushButton")
        self.pass_edit_pushButton = self.manager.findChild(QPushButton, "pass_edit_pushButton")
        self.open_arch_pushButton = self.manager.findChild(QPushButton, "open_arch_pushButton")
        self.iagree_checkBox = self.manager.findChild(QCheckBox, "iagree_checkBox")
        self.db_tableView = self.manager.findChild(QTableView, "db_tableView")
        self.update_pushButton = self.manager.findChild(QPushButton, "update_pushButton")
        self.encrypt_pushButton = self.manager.findChild(QPushButton, "encrypt_pushButton")
        self.decrypt_pushButton = self.manager.findChild(QPushButton, "decrypt_pushButton")
        self.pass_add_pushButton = self.manager.findChild(QPushButton, "pass_add_pushButton")
        self.source_fordb_lineEdit = self.manager.findChild(QLineEdit, "source_fordb_lineEdit")
        self.search_lineEdit = self.manager.findChild(QLineEdit, "search_lineEdit")
        self.search_pushButton = self.manager.findChild(QPushButton, "search_pushButton")

        # Подключение методов
        self.iagree_checkBox.stateChanged.connect(self.toggle_password_manager_buttons)
        self.pass_delete_pushButton.clicked.connect(self.delete_selected_password)
        self.pass_edit_pushButton.clicked.connect(self.edit_password_in_database)
        self.open_arch_pushButton.clicked.connect(self.open_selected_archive)
        self.update_pushButton.clicked.connect(self.refresh_password_manager_table)
        self.encrypt_pushButton.clicked.connect(self.encrypt_database)
        self.decrypt_pushButton.clicked.connect(self.decrypt_database)
        self.pass_add_pushButton.clicked.connect(self.add_password_in_database)
        self.search_pushButton.clicked.connect(self.search_password_table)

        # Начальное состояние
        self.toggle_password_manager_buttons()

        # Настройка отображения таблицы
        self.setup_password_manager_table()

    # Поиск в таблице
    def search_password_table(self):
        search_text = self.search_lineEdit.text().strip()

        if search_text:
            filter_str = (
                f"(password LIKE '%{search_text}%' OR "
                f"archive_name LIKE '%{search_text}%' OR "
                f"archive_folder LIKE '%{search_text}%')"
            )
        else:
            filter_str = "password IS NOT NULL AND archive_name IS NOT NULL AND archive_folder IS NOT NULL"

        self.passwords_model.setFilter(filter_str)
        self.passwords_model.select()

    # Добавить пароль в базу данных
    def add_password_in_database(self):
        new_password = self.pass_fordb_lineEdit.text().strip()
        archive_name = self.source_fordb_lineEdit.text().strip()

        if not new_password:
            QMessageBox.warning(self, "Ошибка", "Поле пароля не может быть пустым.")
            return

        db = QSqlDatabase.database()
        if not db.isOpen():
            QMessageBox.critical(self, "Ошибка", "Нет соединения с базой данных.")
            return

        query_str = f"INSERT INTO Passwords (password, archive_name, archive_folder) VALUES ('{new_password}', '{archive_name}', '')"
        query = db.exec(query_str)

        if query.lastError().isValid():
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить пароль: {query.lastError().text()}")
        else:
            self.refresh_password_manager_table()
            QMessageBox.information(self, "Успех", "Пароль успешно добавлен.")

    # Сгенерировать соль
    def generate_salt(self, size=16):
        return secrets.token_bytes(size)

    # Загрузить соль
    def load_salt(self):
        return open(ensure_salt_exists(), "rb").read()

    # Вывести ключ
    def derive_key(self, salt, password):
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())

    # Сгенерировать ключ
    def generate_key(self, password, salt_size=16, load_existing_salt=False, save_salt=True):
        if load_existing_salt:
            salt = self.load_salt()
        elif save_salt:
            salt = self.generate_salt(salt_size)
            with open(get_salt_path(), "wb") as salt_file:
                salt_file.write(salt)

        derived_key = self.derive_key(salt, password)
        return base64.urlsafe_b64encode(derived_key)

    # Шифрование
    def encrypt(self, filename, key):
        f = Fernet(key)

        with open(filename, "rb") as file:
            file_data = file.read()

        encrypted_data = f.encrypt(file_data)

        with open(filename, "wb") as file:
            file.write(encrypted_data)

    # Дешифрование
    def decrypt(self, filename, key):
        f = Fernet(key)
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        try:
            decrypted_data = f.decrypt(encrypted_data)
            with open(filename, "wb") as file:
                file.write(decrypted_data)
            QMessageBox.information(self, "Успех", "База данных успешно расшифрована.")
            self.setup_password_manager_table()
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод decrypt.", exc=True)
            QMessageBox.critical(self, "Ошибка", "Неверный пароль или поврежденный файл.")

    # Зашифровать базу данных
    def encrypt_database(self):
        password = self.pass_fordb_lineEdit.text().strip()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для шифрования базы данных.")
            return
        
        try:
            key = self.generate_key(password, load_existing_salt=True)
            db_path = get_working_db_path()
            self.encrypt(db_path, key)
            QMessageBox.information(self, "Успех", "База данных успешно зашифрована.")
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод encrypt_database.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать базу данных.")

    # Дешифровать базу данных
    def decrypt_database(self):
        password = self.pass_fordb_lineEdit.text().strip()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для расшифровки базы данных.")
            return
        try:
            key = self.generate_key(password, load_existing_salt=True)
            db_path = get_working_db_path()
            self.decrypt(db_path, key)
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод decrypt_database.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать базу данных.")

    # Обновление пароля в базе данных
    def edit_password_in_database(self):
        selection_model = self.db_tableView.selectionModel()
        if not selection_model.hasSelection():
            QMessageBox.warning(self, "Ошибка", "Выберите запись для редактирования.")
            return

        new_password = self.pass_fordb_lineEdit.text().strip()
        if not new_password:
            QMessageBox.warning(self, "Ошибка", "Поле пароля не может быть пустым.")
            return

        index = selection_model.currentIndex()
        row = index.row()
        record = self.passwords_model.record(row)
        record_id = record.value("id")

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
        self.pass_edit_pushButton.setEnabled(state)
        self.open_arch_pushButton.setEnabled(state)
        self.pass_add_pushButton.setEnabled(state)
        self.encrypt_pushButton.setEnabled(state)
        self.decrypt_pushButton.setEnabled(state)

    # Настройка отображения таблицы
    def setup_password_manager_table(self):
        db_path = ensure_database_exists()
        self.db = QSqlDatabase.addDatabase("QSQLITE")
        self.db.setDatabaseName(db_path)

        if not self.db.open():
            QMessageBox.critical(self, "Ошибка", "Не удалось подключиться к базе данных.")
            return

        # SQL запрос
        self.passwords_model = QSqlTableModel(self, self.db)
        self.passwords_model.setTable("Passwords")
        self.passwords_model.setFilter("password IS NOT NULL AND archive_name IS NOT NULL AND archive_folder IS NOT NULL")
        self.passwords_model.select()

        # Поля таблицы
        self.passwords_model.setHeaderData(1, Qt.Horizontal, "Пароль")
        self.passwords_model.setHeaderData(2, Qt.Horizontal, "От чего пароль")
        self.passwords_model.setHeaderData(3, Qt.Horizontal, "Путь к архиву")

        # Свойства таблицы
        self.db_tableView.setModel(self.passwords_model)
        self.db_tableView.setEditTriggers(QTableView.NoEditTriggers)
        self.db_tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.db_tableView.hideColumn(0)

    # Обновление данных с учётом фильтра
    def refresh_password_manager_table(self):
        self.passwords_model.setFilter("password IS NOT NULL AND archive_name IS NOT NULL AND archive_folder IS NOT NULL")
        self.passwords_model.select()

    # Открыть и распаковать архив с проверкой корректности пароля
    def open_selected_archive(self):
        selection_model = self.db_tableView.selectionModel()
        if not selection_model.hasSelection():
            QMessageBox.warning(self, "Ошибка", "Выберите запись, чтобы открыть архив.")
            return

        index = selection_model.currentIndex()
        row = index.row()
        record = self.passwords_model.record(row)

        archive_path = record.value("archive_folder")
        archive_password = record.value("password")

        if not archive_path:
            QMessageBox.warning(self, "Ошибка", "Путь к архиву отсутствует.")
            return

        archive_path = os.path.normpath(archive_path)

        if not os.path.exists(archive_path):
            QMessageBox.critical(self, "Ошибка", f"Файл {archive_path} не существует.")
            return

        options = QFileDialog.Options()
        extract_path = QFileDialog.getExistingDirectory(
            self, "Выберите папку для распаковки", "", options=options
        )

        if not extract_path:
            return

        # Попытка открыть архив
        def try_open_archive(path, password):
            try:
                with py7zr.SevenZipFile(path, mode='r', password=password) as archive:
                    archive.getnames()
                return True
            except (LZMAError, ValueError):
                return False
            except Exception as e:
                log_warning(f"Ошибка: {e}.\nМетод try_open_archive.", exc=True)
                print(f"Ошибка открытия архива.")
                return False

        if not try_open_archive(archive_path, archive_password):
            
            # Запрос на новый пароль
            dialog = QInputDialog(self)
            dialog.setWindowTitle("Неверный пароль")
            dialog.setLabelText(f"Введите пароль для архива:\n{archive_path}")
            dialog.setTextEchoMode(QLineEdit.Password)
            dialog.resize(400, 200)
            dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)

            if dialog.exec_() == QInputDialog.Accepted:
                new_password = dialog.textValue()
                if not new_password:
                    QMessageBox.warning(self, "Ошибка", "Распаковка отменена.")
                    return
                if not try_open_archive(archive_path, new_password):
                    QMessageBox.critical(self, "Ошибка", "Неверный пароль или ошибка архива.")
                    return
                archive_password = new_password
            else:
                QMessageBox.warning(self, "Ошибка", "Распаковка отменена.")
                return

        try:
            with py7zr.SevenZipFile(archive_path, mode='r', password=archive_password) as archive:
                archive.extractall(path=extract_path)
            QMessageBox.information(self, "Успех", f"Архив успешно распакован в: {extract_path}")
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод open_selected_archive.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось распаковать архив.")

    # Замена значений выбранной записи на NULL
    def delete_selected_password(self):
        selection_model = self.db_tableView.selectionModel()
        if not selection_model.hasSelection():
            QMessageBox.warning(self, "Ошибка", "Выберите запись для удаления.")
            return

        index = selection_model.currentIndex()
        row = index.row()
        record = self.passwords_model.record(row)
        record_id = record.value("id")

        if QMessageBox.question(self, "Подтверждение", "Вы уверены, что хотите обнулить запись?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            query = QSqlDatabase.database().exec(
                f"UPDATE Passwords SET password=NULL, archive_name=NULL, archive_folder=NULL WHERE id={record_id}"
            )
            if query.lastError().isValid():
                QMessageBox.critical(self, "Ошибка", f"Не удалось обнулить запись: {query.lastError().text()}")
            else:
                self.refresh_password_manager_table()
                QMessageBox.information(self, "Успех", "Запись успешно обнулена.")

# Класс вкладки Архивы
class Archives(QtWidgets.QWidget):
    def __init__(self, tabWidget, parent=None):
        super().__init__(parent)
        self.tabWidget = tabWidget
        self.archives = self.tabWidget.findChild(QWidget, 'Archives')

        # Виджеты
        self.method_comboBox = self.archives.findChild(QComboBox, 'method_comboBox')
        self.level_comboBox = self.archives.findChild(QComboBox, 'level_comboBox')
        self.enc_method_comboBox = self.archives.findChild(QComboBox, 'enc_method_comboBox')
        self.browse_button = self.archives.findChild(QPushButton, 'browse_button')
        self.create_arc_button = self.archives.findChild(QPushButton, 'create_arc_button')
        self.nopass_checkBox = self.archives.findChild(QCheckBox, 'nopass_checkBox')
        self.I_agree_checkBox = self.archives.findChild(QCheckBox, 'I_agree_checkBox')
        self.saveindb_checkBox = self.archives.findChild(QCheckBox, "saveindb_checkBox")
        self.password_arch_edit = self.archives.findChild(QLineEdit, 'password_arch_edit')
        self.filenames_checkBox = self.archives.findChild(QCheckBox, 'filenames_checkBox')
        self.folder_edit = self.archives.findChild(QLineEdit, 'folder_edit')
        self.sorting_checkBox = self.archives.findChild(QCheckBox, 'sorting_checkBox')

        # Параметры виджетов
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

        # Изначально выключить кнопку создания архива
        self.create_arc_button.setEnabled(False)

    # Открыть проводник для выбора папки
    def select_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Выберите папку для архивации")
        if folder_path:
            self.folder_edit.setText(folder_path)

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
            return  # Отмена выбора

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
                log_warning(f"Ошибка: {e}.\nМетод create_encrypted_archive.", exc=True)
                QMessageBox.critical(self, "Ошибка", f"Ошибка при сортировке файлов.")
                return

        try:
            # Команда для создания архива
            command = [
                rf"C:\Program Files\7-Zip\7z.exe", "a",  # Команда для создания архива
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
            log_warning(f"Ошибка: {e}.\nМетод create_encrypted_archive.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Ошибка при создании архива.")
        finally:
            # Удаление временной папки, если она была создана
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    # Вкл выкл элементы управления для шифрования
    def toggle_password_options(self):
        nopass_active = self.nopass_checkBox.isChecked()
        self.password_arch_edit.setEnabled(not nopass_active)
        self.filenames_checkBox.setEnabled(not nopass_active)
        self.enc_method_comboBox.setEnabled(not nopass_active)

    # Активировать или деактивировать кнопку создания архива в зависимости от чекбокса
    def toggle_create_button(self):
        self.create_arc_button.setEnabled(self.I_agree_checkBox.isChecked())

    # Добавить запись в таблицу
    def save_archive_to_database(self, password, archive_name, archive_folder):
        db_path = get_working_db_path()
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO Passwords (password, archive_name, archive_folder)
                VALUES (?, ?, ?)
            ''', (password, archive_name, archive_folder))

            conn.commit()
            conn.close()

        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод save_archive_to_database.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить запись в базу данных.")

# Класс вкладки Метаданные
class Metadata(QtWidgets.QWidget):
    def __init__(self, tabWidget, parent=None):
        super().__init__(parent)
        self.tabWidget = tabWidget
        self.metadata = self.tabWidget.findChild(QWidget, 'Metadata')

        # Виджеты
        self.I_agree_checkBox_2 = self.metadata.findChild(QCheckBox, 'I_agree_checkBox_2')
        self.picture_edit = self.metadata.findChild(QLineEdit, 'picture_edit')
        self.listView = self.metadata.findChild(QListView, 'listView')

        # Кнопки
        self.browse_button_2 = self.metadata.findChild(QPushButton, 'browse_button_2')
        self.watch_md_button = self.metadata.findChild(QPushButton, 'watch_md_button')
        self.clear_md_button = self.metadata.findChild(QPushButton, 'clear_md_button')

        # Подключение события внутри окна для работы с метаданными
        self.browse_button_2.clicked.connect(self.browse_image)
        self.watch_md_button.clicked.connect(self.display_metadata)
        self.I_agree_checkBox_2.stateChanged.connect(self.toggle_clear_button)
        self.clear_md_button.clicked.connect(self.clear_metadata)

        # Блокировка кнопки для очистки метаданных
        self.clear_md_button.setEnabled(False)

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
            # Открыть изображение и извлечь exif данные
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
            log_warning(f"Ошибка: {e}.\nМетод display_metadata.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать метаданные.")

    # Вкл выкл кнопки в зависимости от чекбокса
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
            log_warning(f"Ошибка: {e}.\nМетод clear_metadata.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить метаданные.")

# Класс вкладки Проверка паролей
class Protect(QtWidgets.QWidget):
    def __init__(self, tabWidget, parent=None):
        super().__init__(parent)
        self.tabWidget = tabWidget
        self.protect_tab = self.tabWidget.findChild(QWidget, 'Protect')

        # Виджеты внутри вкладки с проверкой защиты
        self.pass_edit_prcheck = self.protect_tab.findChild(QLineEdit, 'pass_edit_prcheck')
        self.ProcPower_SpinBox = self.protect_tab.findChild(QDoubleSpinBox, 'ProcPower_SpinBox')
        self.years_label = self.protect_tab.findChild(QLabel, 'years')
        self.months_label = self.protect_tab.findChild(QLabel, 'months')
        self.days_label = self.protect_tab.findChild(QLabel, 'days')
        self.hours_label = self.protect_tab.findChild(QLabel, 'hours')
        self.minutes_label = self.protect_tab.findChild(QLabel, 'minutes')
        self.seconds_label = self.protect_tab.findChild(QLabel, 'seconds')
        self.dictionaries_checkBox = self.protect_tab.findChild(QCheckBox, 'dictionaries_checkBox')
        self.prot_level_fchange = self.protect_tab.findChild(QLabel, 'prot_level_fchange')

        # Кнопки
        self.Test_button = self.protect_tab.findChild(QPushButton, 'Test_button')
        self.Save_button = self.protect_tab.findChild(QPushButton, 'Save_button')

        # Подключение события при нажатии кнопки к методу расчёта времени
        self.pass_edit_prcheck.textChanged.connect(self.toggle_test_button)
        self.pass_edit_prcheck.textChanged.connect(self.toggle_save_button)
        self.Test_button.clicked.connect(self.calculate_time)
        self.Save_button.clicked.connect(self.save_results)

        self.toggle_test_button()
        self.toggle_save_button()

    # Проверка кнопки теста
    def toggle_test_button(self):
        password = self.pass_edit_prcheck.text()
        if password:
            self.Test_button.setEnabled(True)
        else:
            self.Test_button.setEnabled(False)

    # Проверка кнопки сохранения
    def toggle_save_button(self):
        password = self.pass_edit_prcheck.text()
        if password:
            self.Save_button.setEnabled(True)
        else:
            self.Save_button.setEnabled(False)

    # Вычисление времени на перебор пароля
    def calculate_time(self):
        password = self.pass_edit_prcheck.text()
        if not password:
            self.output_label.setText("Введите пароль!")
            return

        password_length = len(password)
        if password_length > 30:
            password_length = 30  # Ограничение от слишком больших чисел

        if self.dictionaries_checkBox.isChecked():
            charset_size = self.determine_charset_size(password)
        else:
            charset_size = self.determine_charset_size_combined()

        hashes_per_second_millions = self.ProcPower_SpinBox.value()
        hashes_per_second = hashes_per_second_millions * 10**6

        time_seconds = self.calculate_bruteforce_time(password_length, charset_size, hashes_per_second)
        human_readable_time = self.seconds_to_human_readable(time_seconds)

        self.years_label.setText(f"{human_readable_time.get('years', 0):.2f}")
        self.months_label.setText(f"{human_readable_time.get('months', 0):.2f}")
        self.days_label.setText(f"{human_readable_time.get('days', 0):.2f}")
        self.hours_label.setText(f"{human_readable_time.get('hours', 0):.2f}")
        self.minutes_label.setText(f"{human_readable_time.get('minutes', 0):.2f}")
        self.seconds_label.setText(f"{human_readable_time.get('seconds', 0):.2f}")

        # Определение уровня безопасности только если пароль не пустой
        if password:
            security_level = self.calculate_security_level(time_seconds)
            self.prot_level_fchange.setText(security_level)

    # Размеры словарей
    def determine_charset_size_combined(self):
        # Латиница
        latin = 26 * 2

        # Спец символы
        special = len(string.punctuation)

        # Цифры
        digits = 10

        # Все словари + языковые
        return sum([
            latin + special + digits,
            20902,  # Китайский
            256,    # Русский
            32,     # Болгарский
            6,      # Сербский
            18,     # Македонский
            134,    # Греческий
            234,    # Японский
            256,    # Корейский
            7,      # Немецкий
            13,     # Испанский
            42      # Французский
        ])

    # Определение словарей для вычислений
    def determine_charset_size(self, password):
        charset_size = 0
        used_sets = set()

        # Стандартные наборы символов
        if any(c in string.ascii_lowercase for c in password):
            used_sets.update(string.ascii_lowercase)
        if any(c in string.ascii_uppercase for c in password):
            used_sets.update(string.ascii_uppercase)
        if any(c in string.digits for c in password):
            used_sets.update(string.digits)
        if any(c in string.punctuation for c in password):
            used_sets.update(string.punctuation)

        # Специальные языковые словари
        regex_sets = {
            'chinese': (20902, re.compile(r'[\u4e00-\u9fff]')),
            'russian': (256, re.compile(r'[\u0400-\u052F]')),
            'bulgarian': (32, re.compile(r'[\u0410-\u044F]')),
            'serbian': (6, re.compile(r'[\u040A-\u040F]')),
            'macedonian': (18, re.compile(r'[\u0400-\u040FЌќЅѕЏџ]')),
            'greek': (134, re.compile(r'[\u0370-\u03FF]')),
            'japanese': (234, re.compile(r'[\u3040-\u30FF]')),
            'korean': (256, re.compile(r'[\u1100-\u11FF]')),
            'german': (7, re.compile(r'[äöüßÄÖÜ]')),
            'spanish': (13, re.compile(r'[áéíóúüñ¿¡ÁÉÍÓÚÜÑ]')),
            'french': (42, re.compile(r'[àâæçéèêëîïôœùûüÿÀÂÆÇÉÈÊËÎÏÔŒÙÛÜŸ]'))
        }

        for _, (size, regex) in regex_sets.items():
            if any(regex.match(c) for c in password):
                charset_size += size

        # Количество уникальных символов из ascii наборов
        charset_size += len(used_sets)

        return max(charset_size, 1)

    # Сохранение результатов (для отчёта)
    def save_results(self):
        from PyQt5.QtWidgets import QFileDialog, QMessageBox

        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить результаты", "", "PDF Files (*.pdf)")
        if not file_path:
            return

        if not file_path.lower().endswith(".pdf"):
            file_path += ".pdf"

        if (not self.years_label.text() or
            not self.months_label.text() or
            not self.days_label.text() or
            not self.hours_label.text() or
            not self.minutes_label.text() or
            not self.seconds_label.text()):
            self.output_label.setText("Заполните все поля перед сохранением!")
            return

        try:
            # Путь к шрифту DejaVuSans
            font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
            if not os.path.exists(font_path):
                font_path = "C:/Windows/Fonts/arial.ttf"  # Windows Arial

            pdfmetrics.registerFont(TTFont("MainFont", font_path))

            style = ParagraphStyle(
                name='Main',
                fontName='MainFont',
                fontSize=11,
                leading=14,
            )

            doc = SimpleDocTemplate(file_path, pagesize=A4)
            elements = []

            elements.append(Paragraph("ProCrypt - Отчёт по проверке пароля", ParagraphStyle(name='Title', fontName='MainFont', fontSize=16, alignment=1)))
            elements.append(Spacer(1, 20))

            data = [
                ["Параметр", "Значение"],
                ["Пароль", self.pass_edit_prcheck.text()],
                ["Хэшей в секунду (млн)", str(self.ProcPower_SpinBox.value())],
                ["Годы", self.years_label.text()],
                ["Месяцы", self.months_label.text()],
                ["Дни", self.days_label.text()],
                ["Часы", self.hours_label.text()],
                ["Минуты", self.minutes_label.text()],
                ["Секунды", self.seconds_label.text()],
            ]

            table = Table(data, colWidths=[200, 250])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('FONTNAME', (0, 0), (-1, -1), 'MainFont'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 20))

            note = ('Расчёты являются оценочными и зависят от ряда допущений. Подробнее в пункте 7 Пользовательского соглашения.')

            elements.append(Paragraph("Примечание:", style))
            elements.append(Paragraph(note, style))

            doc.build(elements)

            QMessageBox.information(self, "Успех", "PDF-отчёт успешно сохранён!")

        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод save_results.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить PDF-файл.")

    # Расчёт времени подбора
    def calculate_bruteforce_time(self, password_length, charset_size, hashes_per_second):

        # Проверка, не превышает ли общее количество комбинаций максимально возможное значение вещественного типа
        if charset_size ** password_length > sys.float_info.max:
            time_seconds = float('inf')  # Установка бесконечного времени
        else:
            time_seconds = (charset_size ** password_length) / hashes_per_second
        return time_seconds

    # Читабельный вид значений времени
    def seconds_to_human_readable(self, seconds):
        max_seconds = 31536000 * 10000  # Ограничение времени до 10 тысяч лет
        seconds = min(seconds, max_seconds)

        intervals = {
            'years': round(seconds // 31536000, 2),
            'months': round((seconds % 31536000) // 2628000, 2),
            'days': round((seconds % 2628000) // 86400, 2),
            'hours': round((seconds % 86400) // 3600, 2),
            'minutes': round((seconds % 3600) // 60, 2),
            'seconds': round(seconds % 60, 2)
        }

        return intervals

    # Определение степени защиты
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

    # Вычисление размера словаря (Используется только при подборе по словарю)
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
        
        # Если размер набора символов равен нулю, он будет установлен на 1, чтобы избежать деления на ноль
        if charset_size == 0:
            charset_size = 1

        return charset_size

# Класс вкладки Генерация паролей
class Password(QtWidgets.QWidget):
    def __init__(self, tabWidget, parent=None):
        super().__init__(parent)
        self.tabWidget = tabWidget
        self.makepass_tab = self.tabWidget.findChild(QWidget, 'Password')

        # Виджеты
        self.symbols_button = self.makepass_tab.findChild(QCheckBox, 'spsymbols_button')
        self.Generate_button = self.makepass_tab.findChild(QPushButton, 'Generate_button')
        self.length_spinBox = self.makepass_tab.findChild(QSpinBox, 'length_spinBox')
        self.main_lineEdit = self.makepass_tab.findChild(QLineEdit, 'main_lineEdit')
        self.china_button = self.makepass_tab.findChild(QCheckBox, 'china_button')
        self.all_button = self.makepass_tab.findChild(QCheckBox, 'all_button')
        self.all_button.stateChanged.connect(self.toggle_all_checkboxes)

        # Флажки (словари)
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

        # Подключение кнопки к методу генерации
        self.Generate_button.clicked.connect(self.generate_password)

        # Проверка начального состояния флажков
        self.toggle_generate_button()

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
            china_massive = []
            for _ in range(0x4e00, 0x9fff + 1):
                china_massive.append(_)
            charset += ''.join(chr(secrets.choice(china_massive)) for _ in range(len(china_massive)))
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

        password = ''.join(secrets.choice(charset) for _ in range(password_length))
        self.main_lineEdit.setText(password)

    # Функция проверки флажков
    def toggle_generate_button(self):
        if (self.symbols_button.isChecked() or self.english_button.isChecked() or self.numbers_button.isChecked() or
            self.china_button.isChecked() or self.russian_button.isChecked() or self.bulgarian_button.isChecked() or
            self.serbian_button.isChecked() or self.macedonian_button.isChecked() or self.greek_button.isChecked() or
            self.japanese_button.isChecked() or self.korean_button.isChecked() or self.german_button.isChecked() or
            self.spanish_button.isChecked() or self.french_button.isChecked()):
            self.Generate_button.setEnabled(True)
        else:
            self.Generate_button.setEnabled(False)

    # Переключение флажков
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

# Главное окно приложения
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('data/main.ui', self)

        # Название, иконка, размер
        self.setWindowTitle('ProCrypt v2.7')
        self.setWindowIcon(QIcon(r'data\ProCrypt.ico'))
        self.setFixedSize(self.size())

        # Запрет на переход в полноэкранный режим
        self.setWindowFlags(Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)

        # Инициализация класса вкладки Генерация паролей
        self.workplace_tab = Password(self.tabWidget)
        # Инициализация класса вкладки Проверка паролей
        self.protect_tab = Protect(self.tabWidget)
        # Инициализация класса вкладки Метаданные
        self.metadata = Metadata(self.tabWidget)
        # Инициализация класса вкладки Архивы
        self.archives = Archives(self.tabWidget)
        # Инициализация класса вкладки Менеджер паролей
        self.manager = Manager(self.tabWidget)

        self.tabWidget.setCurrentIndex(0)

        # Ссылки на действия
        self.aboutapp_action = self.findChild(QAction, 'aboutapp')
        self.user_agreement_action = self.findChild(QAction, 'user_agreement')
        self.password_tab_action = self.findChild(QAction, 'password_tab')
        self.protect_tab_action = self.findChild(QAction, 'protect_tab')
        self.metadata_tab_action = self.findChild(QAction, 'metadata_tab')
        self.archives_tab_action = self.findChild(QAction, 'archives_tab')
        self.manager_tab_action = self.findChild(QAction, 'manager_tab')

        # Кнопка для сайта
        self.website_commandLinkButton = self.findChild(QtWidgets.QCommandLinkButton, 'website_commandLinkButton')

        # Подключение методов
        self.aboutapp_action.triggered.connect(lambda: self.show_aboutapp())
        self.user_agreement_action.triggered.connect(lambda: self.show_user_agreement())
        self.password_tab_action.triggered.connect(lambda: self.show_file_content(self.password_tab_action))
        self.protect_tab_action.triggered.connect(lambda: self.show_file_content(self.protect_tab_action))
        self.metadata_tab_action.triggered.connect(lambda: self.show_file_content(self.metadata_tab_action))
        self.archives_tab_action.triggered.connect(lambda: self.show_file_content(self.archives_tab_action))
        self.manager_tab_action.triggered.connect(lambda: self.show_file_content(self.manager_tab_action))
        self.website_commandLinkButton.clicked.connect(self.open_website)

        # Проверка обновлений
        self.new_release_search()

        # Запрос на логирование у пользователя
        self.ask_logging_permission()
        
        # Выбор темы
        self.radio_light = self.findChild(QtWidgets.QRadioButton, 'radioButton_light_theme')
        self.radio_dark = self.findChild(QtWidgets.QRadioButton, 'radioButton_dark_theme')
        
        # Тема по умолчанию - светлая
        self.radio_light.setChecked(True)
        self.apply_light_theme()

        # Подключение обработчиков
        self.radio_light.toggled.connect(self.on_theme_changed)
        self.radio_dark.toggled.connect(self.on_theme_changed)

    # Проверка обновлений
    def new_release_search(self):
        try:
            res = requests.get('https://api.github.com/repos/v01dedknight/ProCrypt/releases')
            data = res.json()

            if data[0]['tag_name'] != 'v2.7':
                QMessageBox.information(self, "Обновление", "Вышло обновление ProCrypt! Успейте установить новую версию в репозитории.")  
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод new_release_search.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка во время проверки обновлений.")           

    # Выбор темы
    def on_theme_changed(self):
        if self.radio_dark.isChecked():
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

    # Конфиг тёмной темы
    def apply_dark_theme(self):
        dark_stylesheet = """
            QWidget {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }

            QPushButton, QCommandLinkButton, QRadioButton {
                background-color: #3c3f41;
                color: white;
                border: 1px solid #5c5c5c;
                padding: 5px;
            }

            QLineEdit, QTextEdit, QPlainTextEdit {
                background-color: #3c3f41;
                color: white;
                border: 1px solid #5c5c5c;
            }

            QTabWidget::pane {
                border: 1px solid #444;
            }

            QTabBar::tab {
                background: #3c3f41;
                color: white;
                padding: 5px;
                margin: 1px;
            }

            QTabBar::tab:selected {
                background: #2e2e2e;
                font-weight: bold;
            }

            QMenuBar, QMenu {
                background-color: #2b2b2b;
                color: white;
            }

            QMenu::item:selected {
                background-color: #444;
            }

            QMessageBox {
                background-color: #2b2b2b;
                color: white;
            }
            
            QHeaderView::section {
                background-color: #3c3f41;
                color: white;
                padding: 4px;
                border: 1px solid #5c5c5c;
            }
        """
        self.setStyleSheet(dark_stylesheet)

    # Дефолтная тема
    def apply_light_theme(self):
        self.setStyleSheet("")

    # Запрос на логирование
    def ask_logging_permission(self):
        global logging_enabled

        log_file_path = os.path.join(os.getcwd(), "procrypt.log")

        # Если лог-файл уже существует, считаем, что пользователь уже дал согласие
        if os.path.exists(log_file_path):
            setup_logging()
            logging.info("Логирование уже разрешено ранее (обнаружен procrypt.log).")
            return

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Question)
        msg.setWindowTitle("Разрешить сохранение обезличенных технических данных (логов) для отладки?")
        msg.setText("В логах не хранится никакая личная информация или названия файлов.")
        msg.setInformativeText(
            "Все логи хранятся в файле procrypt.log в корневой папке приложения.\n"
            "Если хотите отказаться от логирования, удалите этот файл.\n"
            "Пример записи из лог файла:\n\n"
            "2025-06-22 12:00:00,000 - WARNING - Ошибка: 'код_ошибки'.\n"
            "Метод 'название_метода'.\n"
            "NoneType: 'вид_активного_исключения'\n\n"
            "Отправка этого файла разработчику производится исключительно вами вручную.\nНикакой автоматизации этого процесса нету."
        )

        enable_button = msg.addButton("Да, включить", QMessageBox.AcceptRole)
        disable_button = msg.addButton("Нет, не нужно", QMessageBox.RejectRole)

        msg.exec_()

        if msg.clickedButton() == enable_button:
            setup_logging()
            logging.info("Логирование разрешено пользователем.")
        else:
            logging_enabled = False  # Просто для ясности

    # Подключение к сайту
    def open_website(self):
        url = 'https://github.com/v01dedknight/ProCrypt'
        try:
            webbrowser.open(url)
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод open_website.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка во время открытия страницы.")

    # Общий метод для отображения содержимого файлов для вкладок
    def show_file_content(self, action):
        # Путь к файлам справок
        file_mapping = {
            'password_tab': 'data/userinfo/password.md',
            'protect_tab': 'data/userinfo/protect.md',
            'metadata_tab': 'data/userinfo/metadata.md',
            'archives_tab': 'data/userinfo/archives.md',
            'manager_tab': 'data/userinfo/manager.md'
        }

        # Определение пути к файлу по действию
        file_name = file_mapping.get(action.objectName())
        if file_name:
            self.open_file_dialog(file_name)

    # О приложении
    def show_aboutapp(self):
        self.open_file_dialog('data/userinfo/aboutapp.md')

    # Соглашение
    def show_user_agreement(self):
        url = 'https://github.com/v01dedknight/ProCrypt/blob/main/user_agreement.md'

        msg = QMessageBox(self)
        msg.setWindowTitle("Пользовательское соглашение")
        msg.setIcon(QMessageBox.Information)
        msg.setText("Будет открыта актуальная версия Пользовательского соглашения в официальном репозитории ProCrypt на GitHub.")
        msg.setInformativeText(
            "Рекомендуется ознакомиться с актуальной версией Пользовательского соглашения онлайн.\n\n"
            "При отсутствии подключения к интернету вы можете открыть локальную копию.\n"
            "Использование программы означает согласие с последней опубликованной версией соглашения."
        )

        github_button = msg.addButton("Открыть GitHub", QMessageBox.AcceptRole)
        local_button = msg.addButton("Локальная копия", QMessageBox.DestructiveRole)
        cancel_button = msg.addButton("Отмена", QMessageBox.RejectRole)

        msg.exec_()

        clicked_button = msg.clickedButton()

        try:
            if clicked_button == github_button:
                webbrowser.open(url)
            elif clicked_button == local_button:
                self.open_file_dialog('data/userinfo/user_agreement.md')
            elif clicked_button == cancel_button:
                # Отмена
                pass
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод show_user_agreement.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка во время открытия страницы.")


    # Отображение содержимого
    def open_file_dialog(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Создание диалога
            dialog = QDialog(self)
            dialog.setWindowTitle("Справочный материал")
            dialog.resize(700, 500)

            layout = QVBoxLayout(dialog)

            text_edit = QTextEdit(dialog)
            text_edit.setReadOnly(True)
            text_edit.setText(content)
            layout.addWidget(text_edit)

            dialog.setLayout(layout)
            dialog.exec_()

        except FileNotFoundError:
            QMessageBox.warning(self, "Ошибка", f"Файл {file_path} не найден!")
        except Exception as e:
            log_warning(f"Ошибка: {e}.\nМетод open_file_dialog.", exc=True)
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка.")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
