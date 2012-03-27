#!/bin/sh

#export ALSADEV="plughw:0,2"
#./julius/julius -C ../dictation-kit-v4.1/fast.jconf -input alsa -charconv EUC-JP UTF-8

# alsa device setting
export ALSADEV="plughw:UA4FX"
# irmcd_notify setting
export IRMCD_NOTIFY_CONFIG_FILE="/root/download/julius/julius4/myplugins/irmcd_notify.conf"
# julius run with foreground
./julius/julius -plugindir ./myplugins -C ../grammar-kit-v4.1/hmm_mono.jconf -gram ../grammar/irmd -input alsa -48
