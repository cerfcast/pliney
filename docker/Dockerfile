FROM fedora:42

RUN <<EOF
dnf update
dnf -y install @development-tools libpcap-devel cmake clang++ libxdp-devel
mkdir /usr/local/packetline
EOF

WORKDIR /usr/local/packetline

COPY ./ ./

RUN rm -rf build && cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=On && cmake --build build

CMD ["sudo", "./test/tests.sh"]

