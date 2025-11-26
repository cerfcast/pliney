FROM fedora:42


RUN sudo dnf -y install @development-tools libpcap-devel cmake

RUN mkdir /usr/local/packetline

WORKDIR /usr/local/packetline

COPY ./ ./

RUN sudo dnf -y install clang++

RUN rm -rf build && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=On && cmake --build build

CMD ["sudo", "./test/local_tests.sh"]

