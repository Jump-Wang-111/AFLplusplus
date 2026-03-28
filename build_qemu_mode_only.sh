if [ "$(id -u)" -eq 0 ]; then
    SUDO_CMD=""
else
    SUDO_CMD="sudo"
fi

$SUDO_CMD hwclock -s

cd qemu_mode/
CPU_TARGET=arm ./build_qemu_support.sh

if [ $? -eq 0 ]; then
    cd -
    $SUDO_CMD make install
fi