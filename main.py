import sys
import os
import random
import string
import re
import py7zr
import subprocess
import shutil
import sqlite3
import base64
import secrets
from PIL import Image
from PIL.ExifTags import TAGS
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QAction, QWidget, QComboBox, QCheckBox, QPushButton, QSpinBox, QLabel, QDoubleSpinBox, QFileDialog, QLineEdit, QMessageBox, QTableView, QInputDialog, QListView
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

# Класс вкладки Менеджер
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

        # Подключение методов
        self.iagree_checkBox.stateChanged.connect(self.toggle_password_manager_buttons)
        self.pass_delete_pushButton.clicked.connect(self.delete_selected_password)
        self.pass_edit_pushButton.clicked.connect(self.edit_password_in_database)
        self.open_arch_pushButton.clicked.connect(self.open_selected_archive)
        self.update_pushButton.clicked.connect(self.refresh_password_manager_table)
        self.encrypt_pushButton.clicked.connect(self.encrypt_database)
        self.decrypt_pushButton.clicked.connect(self.decrypt_database)
        self.pass_add_pushButton.clicked.connect(self.add_password_in_database)

        # Начальное состояние
        self.toggle_password_manager_buttons()

        # Настройка отображения таблицы
        self.setup_password_manager_table()

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
        return open("data/salt.salt", "rb").read()

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
            with open("data/salt.salt", "wb") as salt_file:
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
        except Exception:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль или поврежденный файл.")

    # Зашифровать базу данных
    def encrypt_database(self):
        password = self.pass_fordb_lineEdit.text().strip()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для шифрования базы данных.")
            return
        
        try:
            key = self.generate_key(password, load_existing_salt=True)
            db_path = os.path.join(os.path.dirname(__file__), 'data', 'PM.db')
            self.encrypt(db_path, key)
            QMessageBox.information(self, "Успех", "База данных успешно зашифрована.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать базу данных: {e}")

    # Дешифровать базу данных
    def decrypt_database(self):
        password = self.pass_fordb_lineEdit.text().strip()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для расшифровки базы данных.")
            return
        try:
            key = self.generate_key(password, load_existing_salt=True)
            db_path = os.path.join(os.path.dirname(__file__), 'data', 'PM.db')
            self.decrypt(db_path, key)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать базу данных: {e}")

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

    # Настройка отображения таблицы
    def setup_password_manager_table(self):
        db_path = os.path.join(os.path.dirname(__file__), 'data', 'PM.db')
        self.db = QSqlDatabase.addDatabase("QSQLITE")
        self.db.setDatabaseName(db_path)

        if not self.db.open():
            QMessageBox.critical(self, "Ошибка", "Не удалось подключиться к базе данных.")
            return

        self.passwords_model = QSqlTableModel(self, self.db)
        self.passwords_model.setTable("Passwords")
        self.passwords_model.setFilter("password IS NOT NULL AND archive_name IS NOT NULL AND archive_folder IS NOT NULL")
        self.passwords_model.select()

        self.passwords_model.setHeaderData(1, Qt.Horizontal, "Пароль")
        self.passwords_model.setHeaderData(2, Qt.Horizontal, "От чего пароль")
        self.passwords_model.setHeaderData(3, Qt.Horizontal, "Путь к архиву")

        self.db_tableView.setModel(self.passwords_model)
        self.db_tableView.setEditTriggers(QTableView.NoEditTriggers)
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

        def try_open_archive(path, password):
            try:
                with py7zr.SevenZipFile(path, mode='r', password=password) as archive:
                    archive.getnames()
                return True
            except (LZMAError, ValueError):
                return False
            except Exception as e:
                print(f"[Ошибка открытия архива] {e}")
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
            QMessageBox.critical(self, "Ошибка", f"Не удалось распаковать архив: {e}")

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
                QMessageBox.critical(self, "Ошибка", f"Ошибка при сортировке файлов: {e}")
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
            QMessageBox.critical(self, "Ошибка", f"Ошибка при создании архива: {e}")
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
        db_path = os.path.join(os.path.dirname(__file__), 'data', 'PM.db')
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Добавить запись в таблицу
            cursor.execute('''
                INSERT INTO Passwords (password, archive_name, archive_folder)
                VALUES (?, ?, ?)
            ''', (password, archive_name, archive_folder))

            conn.commit()
            conn.close()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить запись в базу данных: {e}")

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
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать метаданные: {e}")

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
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить метаданные: {e}")

# Класс вкладки Защита
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
        if self.dictionaries_checkBox.isChecked():
            charset_size = self.determine_charset_size(password)
        else:
            charset_size = sum([
                32,  # Спец символы
                20902,  # Китайский
                256,  # Русский
                32,  # Болгарский
                6,  # Сербский
                18,  # Македонский
                134,  # Греческий
                234,  # Японский
                256,  # Корейский
                7,  # Немецкий
                13,  # Испанский
                42  # Французский
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

            note = (
                'Данные расчёты не являются абсолютными и не могут служить точным индикатором надёжности пароля. '
                'Оценка времени подбора пароля основана на теоретической вычислительной мощности и не учитывает всех факторов, '
                'таких как специфические методы атак, оптимизация алгоритмов или аппаратное обеспечение злоумышленников. '
                'Предполагается, что для шифрования используется алгоритм "AES-256".'
            )

            elements.append(Paragraph("Примечание:", style))
            elements.append(Paragraph(note, style))

            doc.build(elements)

            QMessageBox.information(self, "Успех", "PDF-отчёт успешно сохранён!")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить PDF-файл: {e}")

    # Расчёт времени подбора
    def calculate_bruteforce_time(self, password_length, charset_size, hashes_per_second):

        # Проверка, не превышает ли общее количество комбинаций максимально возможное значение вещественного типа
        if charset_size ** password_length > sys.float_info.max:
            time_seconds = float('inf')  # Установка бесконечного времени
        else:
            time_seconds = (charset_size ** password_length) / hashes_per_second
        return time_seconds

    # Приведение времени подбора в читабельный вид
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

# Класс вкладки Пароль
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
        self.setWindowTitle('ProCrypt')
        self.setWindowIcon(QIcon(r'data\ProCrypt.ico'))
        self.setFixedSize(self.size())

        # Запрет на переход в полноэкранный режим
        self.setWindowFlags(Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)

        # Инициализация класса вкладки Пароль
        self.workplace_tab = Password(self.tabWidget)
        # Инициализация класса вкладки Защита
        self.protect_tab = Protect(self.tabWidget)
        # Инициализация класса вкладки Метаданные
        self.metadata = Metadata(self.tabWidget)
        # Инициализация класса вкладки Архивы
        self.archives = Archives(self.tabWidget)
        # Инициализация класса вкладки Менеджер
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

        # Кнопка для сайта (скоро)
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

    # Подключение к сайту
    def open_website(self):
        QMessageBox.information(self, "Скоро ...", "Сайт приложения находится в разработке. Спасибо что пользуетесь ProCrypt.")

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
            self._open_file_dialog(file_name)

    # О приложении
    def show_aboutapp(self):
        self._open_file_dialog('data/userinfo/aboutapp.md')

    # Соглашение
    def show_user_agreement(self):
        self._open_file_dialog('data/userinfo/user_agreement.md')

    # Отображение содержимого
    def _open_file_dialog(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Диалоговое окно для текста
            dialog = QDialog(self)
            dialog.setWindowTitle("Справочный материал")
            layout = QVBoxLayout(dialog)
            label = QLabel(content, dialog)
            layout.addWidget(label)
            dialog.setLayout(layout)
            dialog.exec_()

        except FileNotFoundError:
            QMessageBox.warning(self, "Ошибка", f"Файл {file_path} не найден!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка: {e}")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
