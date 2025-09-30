#!/bin/bash
# $1 -> file path
# $2 -> address

tee TempFlashScript.jlink > /dev/null << EOT
usb $JLINK_SN
device STM32H747XI_M7
SelectInterface swd
speed 10000
RSetType 0
LoadFile $1 $2 noreset
rx 100
g
exit
EOT

JLinkExe -nogui 1 -commanderscript TempFlashScript.jlink

rm TempFlashScript.jlink