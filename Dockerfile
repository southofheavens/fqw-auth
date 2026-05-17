# syntax=docker/dockerfile:1.4
FROM alpine:3.23.3

RUN apk add --no-cache \
    openssl-dev \
    pkgconfig \
    git \
    build-base \
    meson \
    poco-dev \
    libsodium-dev \
    gtest-dev \
    cmake \ 
    boost-dev

RUN git clone --branch v0.15.0 --depth 1 https://github.com/alanxz/rabbitmq-c.git /tmp/rabbitmq-c && \
    cd /tmp/rabbitmq-c && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_LIBS=ON && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/rabbitmq-c

RUN git clone --depth 1 https://github.com/alanxz/SimpleAmqpClient.git /tmp/SimpleAmqpClient && \
    cd /tmp/SimpleAmqpClient && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_CXX_STANDARD=20 \
        -DBUILD_SHARED_LIBS=ON && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/SimpleAmqpClient

COPY . ./app

COPY ./startup.config /etc/rgt-auth.config

WORKDIR /app

RUN rm -rf subprojects/rgt-devkit
COPY --from=devkit . ./subprojects/rgt-devkit

RUN meson build
RUN meson compile -C build -j 1

CMD ["./build/rgt-auth"]
