FROM ubuntu:jammy
ARG DEBIAN_FRONTEND=noninteractive

RUN echo "Updating Ubuntu"
RUN apt-get update && apt-get upgrade -y

RUN echo "Installing dependencies..."
RUN apt install -y \
            ccache \
            clang \
            clang-format \
            clang-tidy \
            cppcheck \
            curl \
            doxygen \
            gcc \
            git \
            graphviz \
            make \
            ninja-build \
            python3 \
            python3-pip \
            tar \
            unzip \
            vim \
            ocaml \
            libelf-dev \
            sudo \
            gcc-10 \
            g++-10 \
            pkg-config \
            file

RUN echo "Installing dependencies not found in the package repos..."

RUN echo "Installing CMake 3.16+..." && \
    apt install -y --no-install-recommends wget software-properties-common && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | apt-key add - && \
    add-apt-repository -y 'deb https://apt.kitware.com/ubuntu/ jammy main' && \
    apt-get update && \
    apt install -y --no-install-recommends cmake && \
    cmake --version

RUN pip3 install conan

RUN git clone https://github.com/catchorg/Catch2.git && \
         cd Catch2 && \
         cmake -Bbuild -H. -DBUILD_TESTING=OFF && \
         cmake --build build/ --target install

# Disabled pthread support for GTest due to linking errors
RUN git clone https://github.com/google/googletest.git --branch release-1.11.0 && \
        cd googletest && \
        cmake -Bbuild -Dgtest_disable_pthreads=1 -DCMAKE_POLICY_VERSION_MINIMUM=3.5 && \
        cmake --build build --config Release && \
        cmake --build build --target install --config Release

RUN git clone https://github.com/microsoft/vcpkg -b 2020.06 && \
        cd vcpkg && \
        ./bootstrap-vcpkg.sh -disableMetrics -useSystemBinaries 
