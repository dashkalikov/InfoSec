# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build qt6-base-dev libopencv-dev \
    libssl-dev libsqlite3-dev libntl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt main.cpp ./
COPY src src/
COPY ca ca/
COPY widgets widgets/
COPY algorithms algorithms/
ARG BUILD_JOBS=2
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /build --parallel "$BUILD_JOBS"

FROM ubuntu:24.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl fonts-dejavu-core python3-venv \
    libqt6widgets6t64 libqt6concurrent6t64 libqt6printsupport6t64 libqt6network6t64 \
    libqt6sql6-sqlite qt6-qpa-plugins libssl3t64 libsqlite3-0 libntl44 \
    libopencv-core406t64 libopencv-dnn406t64 libopencv-imgproc406t64 libopencv-imgcodecs406t64 \
    libopencv-videoio406t64 libopencv-objdetect406t64 \
    libgl1 libglib2.0-0t64 libportaudio2 \
    xvfb x11-utils openbox x11vnc novnc websockify \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements-runtime.txt

ENV PATH="/opt/venv/bin:${PATH}" \
    DISPLAY=:99 \
    QT_QPA_PLATFORM=xcb \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    XDG_RUNTIME_DIR=/tmp/threefa-runtime

RUN useradd --create-home --uid 10001 --shell /bin/bash threefa \
    && install -d -m 1777 /tmp/.X11-unix \
    && install -d -o threefa -g threefa /opt/threefa /opt/threefa/databases \
       /opt/threefa/rsa_keys /opt/threefa/generated_primes /opt/threefa/config \
       /home/threefa/.config /home/threefa/exports

WORKDIR /opt/threefa
COPY --from=build /build/3FA /build/minica build/
COPY CMakeLists.txt ./
COPY resources/face build/resources/face/
COPY ca/sign_pdf.py ca/verify_pdf_signature.py ca/
COPY scripts/smart_server.py scripts/websocket_server.py scripts/mediapipe_simple.py scripts/send_email.py scripts/
COPY icons/app_icon.png icons/
COPY docker/start-desktop.sh /usr/local/bin/start-desktop

USER threefa
EXPOSE 6080 8765
ENTRYPOINT ["/bin/bash", "/usr/local/bin/start-desktop"]
