#!/usr/bin/env python3
# pyright: reportMissingImports=false
# ============================================================================
# СКРИПТ MEDIAPIPE_SIMPLE.PY - ОБРАБОТКА ЛИЦА С ПОМОЩЬЮ MEDIAPIPE
# ============================================================================
# Этот скрипт обрабатывает изображения лиц с использованием библиотеки MediaPipe
# для детекции и визуализации лицевых landmarks (ключевых точек лица).
# Работает в режиме постоянного чтения base64-изображений из stdin и вывода
# обработанных изображений в base64 через stdout.
#
# НАЗНАЧЕНИЕ:
# - Интеграция с Qt-приложением для третьего фактора аутентификации (распознавание лица)
# - Обработка кадров с камеры в реальном времени
# - Визуализация лицевых landmarks с эффектом сканирующей полосы
#
# АЛГОРИТМ РАБОТЫ:
# 1. Чтение base64-изображения из stdin
# 2. Декодирование изображения в numpy array
# 3. Обработка MediaPipe Face Mesh для детекции landmarks
# 4. Отрисовка треугольной сетки landmarks на изображении
# 5. Добавление анимированной сканирующей полосы
# 6. Кодирование обработанного изображения в base64 и вывод в stdout
# ============================================================================

import os
import sys

# Устанавливаем кодировку для правильной обработки путей с кириллицей
if sys.platform == 'win32':
    # На Windows устанавливаем UTF-8 для правильной обработки путей
    import locale
    if hasattr(locale, 'getpreferredencoding'):
        try:
            locale.setlocale(locale.LC_ALL, '')
        except:
            pass
    # Устанавливаем переменные окружения для правильной обработки путей
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    if hasattr(sys, 'setdefaultencoding'):
        sys.setdefaultencoding('utf-8')

# Отключаем предупреждения до импорта библиотек для уменьшения шума в консоли
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'        # Отключаем логи TensorFlow
os.environ['GLOG_minloglevel'] = '3'            # Отключаем логи Google/M trendyasset 
os.environ['MP_TASKS_MODEL_COMPLEXITY'] = '1'   # Используем среднюю сложность модели

import warnings
warnings.filterwarnings('ignore')  # Игнорируем все Python warnings

try:
    from absl import logging as absl_logging
    absl_logging.set_verbosity(absl_logging.ERROR)
    absl_logging.set_stderrthreshold('error')
except Exception:
    pass

import cv2                         # OpenCV для работы с изображениями
import mediapipe as mp             # MediaPipe для детекции лица и landmarks
import numpy as np                 # NumPy для работы с массивами
import sys                         # Системные функции (stdin, stdout, stderr)
import base64                      # Кодирование/декодирование base64
import time                        # Работа со временем для анимации
import math                        # Математические функции для рисования звезды

# ============================================================================
# КЛАСС MEDIAPIPEPROCESSOR - ОБРАБОТКА ИЗОБРАЖЕНИЙ С MEDIAPIPE
# ============================================================================
# Класс для обработки изображений лиц с использованием MediaPipe Face Mesh.
# Предоставляет методы для детекции лицевых landmarks и их визуализации
# с эффектом анимированной сканирующей полосы.
# ============================================================================

class MediaPipeProcessor:
    # ============================================================================
    # МЕТОД __init__ - ИНИЦИАЛИЗАЦИЯ ПРОЦЕССОРА
    # ============================================================================
    # Инициализирует MediaPipe Face Mesh с оптимальными параметрами для
    # обработки видеопотока в реальном времени. Настраивает визуализацию
    # landmarks и эффект сканирующей полосы.
    #
    # ПАРАМЕТРЫ:
    #   Нет (конструктор класса)
    #
    # ИНИЦИАЛИЗИРУЕТ:
    #   - self.mpDraw: утилиты для отрисовки MediaPipe
    #   - self.mpFaceMesh: модуль Face Mesh MediaPipe
    #   - self.faceMesh: экземпляр FaceMesh с настройками для видеопотока
    #   - self.drawSpec: стиль отрисовки точек landmarks (белый цвет)
    #   - self.connectionSpec: стиль отрисовки соединений между точками
    #   - self.scan_start_time: время начала для анимации сканирующей полосы
    # ============================================================================
    def __init__(self):
        # mpDraw - утилиты для отрисовки landmarks на изображении
        # Содержит функции для рисования точек, линий и соединений между landmarks
        self.mpDraw = mp.solutions.drawing_utils
        
        # mpFaceMesh - модуль MediaPipe для работы с Face Mesh
        # Предоставляет класс FaceMesh для детекции и обработки лицевых landmarks
        self.mpFaceMesh = mp.solutions.face_mesh
        
        # static_image_mode=False - режим для видео потока (не статичных изображений)
        #   При False модель оптимизирована для обработки последовательных кадров
        #   и использует отслеживание (tracking) для повышения производительности
        # max_num_faces=5 - максимальное количество лиц для одновременной детекции
        #   Поддерживает обработку до 5 лиц в одном кадре
        # refine_landmarks=False - отключение улучшенных landmarks для производительности
        #   Использует базовые 468 точек вместо расширенных, что значительно быстрее
        # min_detection_confidence=0.5 - минимальная уверенность для детекции лица
        #   Порог от 0.0 до 1.0. При значении 0.5 лицо считается обнаруженным,
        #   если модель уверена на 50% и более
        # min_tracking_confidence=0.5 - минимальная уверенность для отслеживания лица
        #   Порог для продолжения отслеживания уже обнаруженного лица между кадрами
        self.faceMesh = self.mpFaceMesh.FaceMesh(
            static_image_mode=False,        # Режим видеопотока (оптимизация для последовательных кадров)
            max_num_faces=5,                # Максимум 5 лиц одновременно
            refine_landmarks=False,         # Отключено для лучшей производительности
            min_detection_confidence=0.5,   # Порог уверенности детекции (50%)
            min_tracking_confidence=0.5     # Порог уверенности отслеживания (50%)
        )
        
        # drawSpec - стиль отрисовки точек landmarks
        #   thickness=1 - толщина линий (в пикселях)
        #   circle_radius=1 - радиус точек landmarks (в пикселях)
        #   color=(255, 255, 255) - белый цвет в RGB формате
        self.drawSpec = self.mpDraw.DrawingSpec(thickness=1, circle_radius=1, color=(255, 255, 255))
        
        # connectionSpec - стиль отрисовки соединений между landmarks
        #   thickness=1 - толщина линий соединений (в пикселях)
        #   color=(255, 255, 255) - белый цвет в RGB формате
        #   Используется для рисования треугольной сетки (tessellation) на лице
        self.connectionSpec = self.mpDraw.DrawingSpec(thickness=1, color=(255, 255, 255))
        
        # animation_start_time - время начала для расчета анимации маски
        #   Используется для синхронизации анимации цветов
        #   Значение в секундах с начала эпохи (time.time())
        self.animation_start_time = time.time()
        
        print("MediaPipe Face Mesh инициализирован", file=sys.stderr)
    
    
    # ============================================================================
    # МЕТОД draw_cool_mask - ОТРИСОВКА ПРИКОЛЬНОЙ ГРАДИЕНТНОЙ МАСКИ
    # ============================================================================
    # Рисует стильную градиентную маску с анимированными цветами на основе
    # треугольной сетки MediaPipe. Создает эффект неонового свечения с плавным
    # переходом цветов (радужный градиент).
    #
    # ПАРАМЕТРЫ:
    #   img - изображение в формате numpy array (RGB), на которое будет нарисована маска
    #   face_landmarks - объект MediaPipe с координатами landmarks лица
    #
    # АЛГОРИТМ:
    # 1. Получение размеров изображения
    # 2. Расчет времени для анимации цветов
    # 3. Преобразование нормализованных координат landmarks в пиксели
    # 4. Отрисовка треугольной сетки с градиентными цветами
    # 5. Добавление эффекта свечения вокруг маски
    #
    # ВОЗВРАЩАЕМОЕ ЗНАЧЕНИЕ:
    #   Нет (изображение модифицируется напрямую)
    # ============================================================================
    def draw_cool_mask(self, img, face_landmarks):
        try:
            height, width = img.shape[:2]
            
            # Преобразуем landmarks в пиксели
            landmarks_points = []
            for landmark in face_landmarks.landmark:
                x = int(landmark.x * width)
                y = int(landmark.y * height)
                landmarks_points.append([x, y])
            
            if not landmarks_points:
                return
            
            landmarks_points = np.array(landmarks_points, dtype=np.int32)
            
            # Изначальная маска: треугольная сетка MediaPipe Face Mesh
            # Используем стандартную визуализацию MediaPipe
            from mediapipe.python.solutions import face_mesh_connections
            
            # Цвет линий сетки (белый/светло-серый)
            line_color = (200, 200, 200)  # BGR: светло-серый
            thickness = 1
            
            # Рисуем треугольную сетку (tesselation) - изначальная маска
            # FACEMESH_TESSELATION содержит все треугольники для построения сетки
            tesselation = face_mesh_connections.FACEMESH_TESSELATION
            
            for connection in tesselation:
                start_idx = connection[0]
                end_idx = connection[1]
                
                if start_idx < len(landmarks_points) and end_idx < len(landmarks_points):
                    pt1 = tuple(landmarks_points[start_idx])
                    pt2 = tuple(landmarks_points[end_idx])
                    cv2.line(img, pt1, pt2, line_color, thickness)
            
            # === КЛОУНСКАЯ РАСКРАСКА ===
            thickness = 3  # Увеличиваем толщину для яркости
            
            # Левый глаз - СИНИЙ (только контур, без заливки)
            left_eye_color = (255, 100, 0)  # BGR: синий
            left_eye = face_mesh_connections.FACEMESH_LEFT_EYE
            for connection in left_eye:
                start_idx = connection[0]
                end_idx = connection[1]
                if start_idx < len(landmarks_points) and end_idx < len(landmarks_points):
                    pt1 = tuple(landmarks_points[start_idx])
                    pt2 = tuple(landmarks_points[end_idx])
                    cv2.line(img, pt1, pt2, left_eye_color, thickness)
            
            # Правый глаз - КРАСНЫЙ (только контур, без заливки)
            right_eye_color = (0, 0, 255)  # BGR: красный
            right_eye = face_mesh_connections.FACEMESH_RIGHT_EYE
            for connection in right_eye:
                start_idx = connection[0]
                end_idx = connection[1]
                if start_idx < len(landmarks_points) and end_idx < len(landmarks_points):
                    pt1 = tuple(landmarks_points[start_idx])
                    pt2 = tuple(landmarks_points[end_idx])
                    cv2.line(img, pt1, pt2, right_eye_color, thickness)
            
            # Левая бровь - ЖЕЛТАЯ
            left_eyebrow_color = (0, 255, 255)  # BGR: желтый
            left_eyebrow = face_mesh_connections.FACEMESH_LEFT_EYEBROW
            for connection in left_eyebrow:
                start_idx = connection[0]
                end_idx = connection[1]
                if start_idx < len(landmarks_points) and end_idx < len(landmarks_points):
                    pt1 = tuple(landmarks_points[start_idx])
                    pt2 = tuple(landmarks_points[end_idx])
                    cv2.line(img, pt1, pt2, left_eyebrow_color, thickness)
            
            # Правая бровь - ФИОЛЕТОВАЯ
            right_eyebrow_color = (255, 0, 255)  # BGR: фиолетовый
            right_eyebrow = face_mesh_connections.FACEMESH_RIGHT_EYEBROW
            for connection in right_eyebrow:
                start_idx = connection[0]
                end_idx = connection[1]
                if start_idx < len(landmarks_points) and end_idx < len(landmarks_points):
                    pt1 = tuple(landmarks_points[start_idx])
                    pt2 = tuple(landmarks_points[end_idx])
                    cv2.line(img, pt1, pt2, right_eyebrow_color, thickness)
            
            # Рот (губы) - ЯРКО-КРАСНЫЙ (только контур, без заливки)
            lips_color = (0, 0, 255)  # BGR: ярко-красный
            lips_thickness = 4  # Толще для рта
            lips = face_mesh_connections.FACEMESH_LIPS
            for connection in lips:
                start_idx = connection[0]
                end_idx = connection[1]
                if start_idx < len(landmarks_points) and end_idx < len(landmarks_points):
                    pt1 = tuple(landmarks_points[start_idx])
                    pt2 = tuple(landmarks_points[end_idx])
                    cv2.line(img, pt1, pt2, lips_color, lips_thickness)
            
            # Красный нос клоуна (используем точки носа)
            nose_color = (0, 0, 255)  # BGR: красный
            nose_tip_idx = 4  # Кончик носа (примерный индекс)
            if nose_tip_idx < len(landmarks_points):
                nose_tip = tuple(landmarks_points[nose_tip_idx])
                # Рисуем красный круг на кончике носа с заливкой
                cv2.circle(img, nose_tip, 15, nose_color, -1)  # -1 = заливка
                cv2.circle(img, nose_tip, 15, (255, 255, 255), 2)  # Белая обводка
                
        except Exception as e:
            print(f"Ошибка рисования маски: {e}", file=sys.stderr)
    
    
    # ============================================================================
    # МЕТОД process_base64_image - ОБРАБОТКА BASE64 ИЗОБРАЖЕНИЯ
    # ============================================================================
    # Обрабатывает base64-кодированное изображение: декодирует его, применяет
    # MediaPipe Face Mesh для детекции landmarks, рисует треугольную сетку
    # и сканирующую полосу, затем возвращает обработанное изображение.
    #
    # ПАРАМЕТРЫ:
    #   base64_data - строка с base64-кодированным изображением (JPEG/PNG)
    #
    # АЛГОРИТМ:
    # 1. Декодирование base64 в байты
    # 2. Преобразование байтов в numpy array через cv2.imdecode
    # 3. Конвертация BGR (OpenCV) в RGB (MediaPipe)
    # 4. Обработка изображения MediaPipe Face Mesh
    # 5. Отрисовка треугольной сетки MediaPipe с зеленой обводкой глаз, бровей и рта
    # 6. Конвертация обратно в BGR для OpenCV
    # 8. Кодирование обработанного изображения в base64
    #
    # ВОЗВРАЩАЕМОЕ ЗНАЧЕНИЕ:
    #   numpy.ndarray - обработанное изображение в формате BGR (OpenCV)
    #   None - если произошла ошибка при обработке
    # ============================================================================
    def process_base64_image(self, base64_data):
        try:
            # ========================================================================
            # ДЕЙСТВИЕ 1: ДЕКОДИРОВАНИЕ BASE64 В БАЙТЫ
            # ========================================================================
            # base64_data - строка с base64-кодированным изображением (JPEG/PNG)
            # base64.b64decode() декодирует строку в байты изображения
            # image_bytes - массив байтов, представляющий закодированное изображение
            image_bytes = base64.b64decode(base64_data)
            
            # ========================================================================
            # ДЕЙСТВИЕ 2: ПРЕОБРАЗОВАНИЕ БАЙТОВ В NUMPY ARRAY И ДЕКОДИРОВАНИЕ ИЗОБРАЖЕНИЯ
            # ========================================================================
            # np.frombuffer() создает numpy array из байтов
            #   image_bytes - исходные байты изображения
            #   np.uint8 - тип данных (беззнаковые 8-битные целые, 0-255)
            #   Результат: одномерный массив байтов
            nparr = np.frombuffer(image_bytes, np.uint8)
            
            # cv2.imdecode() декодирует массив байтов в изображение OpenCV
            #   nparr - массив байтов изображения
            #   cv2.IMREAD_COLOR - флаг для чтения цветного изображения (BGR формат)
            #   Результат: numpy array с изображением в формате BGR (Blue, Green, Red)
            #   frame - трехмерный массив (height, width, channels), где channels=3 (BGR)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            # Проверка успешности декодирования
            # Если изображение не удалось декодировать (неверный формат, поврежденные данные),
            # cv2.imdecode() возвращает None
            if frame is None:
                return None
            
            # ========================================================================
            # ДЕЙСТВИЕ 3: КОНВЕРТАЦИЯ BGR В RGB ДЛЯ MEDIAPIPE
            # ========================================================================
            # OpenCV использует формат BGR (Blue, Green, Red), а MediaPipe требует RGB
            # cv2.cvtColor() конвертирует цветовое пространство изображения
            #   frame - исходное изображение в формате BGR
            #   cv2.COLOR_BGR2RGB - флаг конвертации из BGR в RGB
            #   imgRGB - изображение в формате RGB для MediaPipe
            imgRGB = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # ========================================================================
            # ДЕЙСТВИЕ 4: ПОЛУЧЕНИЕ РАЗМЕРОВ ИЗОБРАЖЕНИЯ
            # ========================================================================
            # height, width - высота и ширина изображения в пикселях
            # imgRGB.shape[:2] возвращает первые два элемента формы массива (height, width)
            # Третий элемент (channels) не нужен, так как мы знаем, что это RGB (3 канала)
            # Размеры используются MediaPipe для правильной обработки изображения
            height, width = imgRGB.shape[:2]
            
            # ========================================================================
            # ДЕЙСТВИЕ 5: ОБРАБОТКА ИЗОБРАЖЕНИЯ MEDIAPIPE FACE MESH
            # ========================================================================
            # self.faceMesh.process() применяет Face Mesh модель к изображению
            #   imgRGB - изображение в формате RGB
            #   Результат: объект results с обнаруженными лицами и landmarks
            # results.multi_face_landmarks - список обнаруженных лиц (может быть несколько)
            #   Каждый элемент содержит landmarks для одного лица
            results = self.faceMesh.process(imgRGB)
            
            # ========================================================================
            # ДЕЙСТВИЕ 6: ОТРИСОВКА LANDMARKS И ЭФФЕКТА СКАНИРОВАНИЯ
            # ========================================================================
            # Проверяем, были ли обнаружены лица на изображении
            if results.multi_face_landmarks:
                # Проходим по всем обнаруженным лицам (поддержка нескольких лиц)
                for faceLms in results.multi_face_landmarks:
                    # faceLms - объект с landmarks одного лица
                    # Содержит координаты всех 468 точек лица в нормализованном формате
                    
                    # Добавляем треугольную сетку MediaPipe с зеленой обводкой
                    # self.draw_cool_mask() рисует треугольную сетку и обводит глаза, брови и рот зеленым
                    #   imgRGB - изображение для отрисовки (модифицируется напрямую)
                    #   faceLms - landmarks лица для расчета маски
                    self.draw_cool_mask(imgRGB, faceLms)
            
            # ========================================================================
            # ДЕЙСТВИЕ 7: КОНВЕРТАЦИЯ ОБРАТНО В BGR ДЛЯ OPENCV
            # ========================================================================
            # MediaPipe работает с RGB, но OpenCV использует BGR
            # Конвертируем обратно в BGR для совместимости с остальным кодом OpenCV
            # cv2.cvtColor() конвертирует цветовое пространство
            #   imgRGB - изображение в формате RGB (с нарисованными landmarks)
            #   cv2.COLOR_RGB2BGR - флаг конвертации из RGB в BGR
            #   imgBGR - изображение в формате BGR для возврата
            imgBGR = cv2.cvtColor(imgRGB, cv2.COLOR_RGB2BGR)
            
            # Возвращаем обработанное изображение в формате BGR
            # numpy.ndarray с формой (height, width, 3) - трехканальное цветное изображение
            return imgBGR
            
        except Exception as e:
            # Обработка ошибок: выводим сообщение в stderr для отладки
            # Возможные ошибки:
            #   - Неверный формат base64 строки
            #   - Поврежденные данные изображения
            #   - Ошибки MediaPipe при обработке
            #   - Ошибки OpenCV при конвертации цветов
            print(f"Ошибка обработки изображения: {e}", file=sys.stderr)
            return None


# ============================================================================
# ФУНКЦИЯ main - ГЛАВНАЯ ФУНКЦИЯ СКРИПТА
# ============================================================================
# Основная функция для постоянного чтения base64-изображений из stdin,
# их обработки через MediaPipe и вывода обработанных изображений в stdout.
# Работает в бесконечном цикле до получения сигнала прерывания (Ctrl+C).
#
# АЛГОРИТМ:
# 1. Инициализация MediaPipeProcessor
# 2. Бесконечный цикл чтения из stdin построчно
# 3. Для каждой строки (base64-изображение):
#    - Обработка через process_base64_image()
#    - Кодирование результата в base64
#    - Вывод в stdout
# 4. Обработка исключений (KeyboardInterrupt, общие ошибки)
#
# ПРОТОКОЛ ВЗАИМОДЕЙСТВИЯ:
# - Вход: base64-строка изображения через stdin (одна строка = одно изображение)
# - Выход: base64-строка обработанного изображения через stdout
# - Ошибки: сообщения об ошибках выводятся в stderr
# ============================================================================

def main():
    # ========================================================================
    # ДЕЙСТВИЕ 1: ИНИЦИАЛИЗАЦИЯ ПРОЦЕССОРА MEDIAPIPE
    # ========================================================================
    # Создаем экземпляр MediaPipeProcessor для обработки изображений
    # processor - объект класса MediaPipeProcessor, который содержит:
    #   - Настроенный Face Mesh модель MediaPipe
    #   - Утилиты для отрисовки landmarks
    #   - Параметры стиля отрисовки (drawSpec, connectionSpec)
    #   - Время начала для синхронизации анимации сканирующей полосы
    processor = MediaPipeProcessor()
    
    # Выводим сообщение о готовности в stderr (не мешает основному потоку данных)
    # stderr используется для служебных сообщений, stdout - для данных
    print("MediaPipe процессор готов к работе", file=sys.stderr)
    
    try:
        # ========================================================================
        # ДЕЙСТВИЕ 2: БЕСКОНЕЧНЫЙ ЦИКЛ ЧТЕНИЯ ИЗ STDIN
        # ========================================================================
        # sys.stdin - стандартный поток ввода (stdin)
        # Итерация по stdin построчно: каждая строка = одно base64-кодированное изображение
        # Цикл продолжается до получения EOF (End Of File) или прерывания (Ctrl+C)
        for line in sys.stdin:
            # ========================================================================
            # ДЕЙСТВИЕ 3: ПОДГОТОВКА ВХОДНЫХ ДАННЫХ
            # ========================================================================
            # line.strip() удаляет пробельные символы (пробелы, табуляции, переносы строк)
            # с начала и конца строки для корректной обработки base64 данных
            line = line.strip()
            
            # Пропускаем пустые строки (после strip() осталась пустая строка)
            # Пустые строки могут появляться из-за форматирования или ошибок передачи
            if not line:
                continue  # Переходим к следующей итерации цикла
            
            # ========================================================================
            # ДЕЙСТВИЕ 4: ОБРАБОТКА ИЗОБРАЖЕНИЯ ЧЕРЕЗ MEDIAPIPE
            # ========================================================================
            # processor.process_base64_image() обрабатывает base64-изображение:
            #   1. Декодирует base64 в байты
            #   2. Преобразует байты в numpy array (OpenCV формат)
            #   3. Конвертирует BGR в RGB для MediaPipe
            #   4. Применяет Face Mesh для детекции landmarks
            #   5. Рисует треугольную сетку landmarks
            #   6. Добавляет эффект сканирующей полосы
            #   7. Конвертирует обратно в BGR
            # line - строка с base64-кодированным изображением
            # processed_image - обработанное изображение в формате numpy.ndarray (BGR)
            #   или None, если обработка не удалась
            processed_image = processor.process_base64_image(line)
            
            # ========================================================================
            # ДЕЙСТВИЕ 5: КОДИРОВАНИЕ И ВЫВОД ОБРАБОТАННОГО ИЗОБРАЖЕНИЯ
            # ========================================================================
            # Проверяем успешность обработки
            if processed_image is not None:
                # Кодируем обработанное изображение в JPEG формат
                # cv2.imencode() кодирует изображение в указанный формат (JPEG)
                #   '.jpg' - формат выходного изображения (JPEG)
                #   processed_image - изображение в формате numpy.ndarray (BGR)
                #   Результат: (success_flag, buffer)
                #     success_flag - флаг успешности (True/False), игнорируем через _
                #     buffer - массив байтов закодированного JPEG изображения
                _, buffer = cv2.imencode('.jpg', processed_image)
                
                # Кодируем массив байтов JPEG в base64 строку
                # base64.b64encode() кодирует байты в base64
                #   buffer - массив байтов JPEG изображения
                #   .decode('utf-8') - преобразует байты в строку UTF-8
                #   image_base64 - строка с base64-кодированным JPEG изображением
                image_base64 = base64.b64encode(buffer).decode('utf-8')
                
                # Выводим base64 строку в stdout (стандартный поток вывода)
                # stdout используется для передачи данных обработанного изображения
                # C++ приложение читает из stdout и получает обработанное изображение
                print(image_base64)
                
                # Принудительно сбрасываем буфер stdout для немедленной отправки данных
                # sys.stdout.flush() гарантирует, что данные будут отправлены сразу,
                # без ожидания заполнения буфера. Это критично для реального времени,
                # так как C++ приложение ожидает немедленного ответа
                sys.stdout.flush()
            else:
                # Если обработка не удалась (неверный формат, ошибка декодирования и т.д.),
                # возвращаем пустую строку в stdout
                # Это сигнализирует C++ приложению об ошибке обработки
                print("")
                
                # Также сбрасываем буфер для немедленной отправки пустой строки
                sys.stdout.flush()
                
    except KeyboardInterrupt:
        # ========================================================================
        # ОБРАБОТКА ПРЕРЫВАНИЯ ПОЛЬЗОВАТЕЛЕМ (CTRL+C)
        # ========================================================================
        # KeyboardInterrupt возникает при нажатии Ctrl+C в терминале
        # Это нормальное завершение работы скрипта, не ошибка
        # Выводим сообщение в stderr и корректно завершаем работу
        print("MediaPipe процессор остановлен", file=sys.stderr)
        
    except Exception as e:
        # ========================================================================
        # ОБРАБОТКА ОБЩИХ ОШИБОК
        # ========================================================================
        # Перехватываем все остальные исключения (не KeyboardInterrupt)
        # Возможные ошибки:
        #   - Ошибки чтения из stdin (разрыв соединения)
        #   - Ошибки кодирования изображения
        #   - Ошибки MediaPipe при обработке
        #   - Ошибки OpenCV при работе с изображениями
        # Выводим сообщение об ошибке в stderr для отладки
        # e - объект исключения с информацией об ошибке
        print(f"Ошибка: {e}", file=sys.stderr)

# ============================================================================
# ТОЧКА ВХОДА СКРИПТА
# ============================================================================
# if __name__ == "__main__" проверяет, запущен ли скрипт напрямую
# (а не импортирован как модуль). Это стандартная практика в Python
# для создания исполняемых скриптов.
#
# Когда скрипт запускается напрямую (python mediapipe_simple.py),
# __name__ == "__main__" будет True, и функция main() будет вызвана.
#
# Когда скрипт импортируется как модуль (import mediapipe_simple),
# __name__ будет "mediapipe_simple", и main() не будет вызвана автоматически.
# ============================================================================
if __name__ == "__main__":
    main()
