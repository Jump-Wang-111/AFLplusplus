cd qemu_mode/
CPU_TARGET=arm ./build_qemu_support.sh
if [ $? == 0 ]
then
    cd -
    sudo make install
fi