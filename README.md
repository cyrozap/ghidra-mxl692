# Loader for MxL692 Firmware for Ghidra

This plugin loads firmware images for the [MaxLinear MxL692][MxL692] into Ghidra.
An example firmware image can be found [here][fw].

> [!CAUTION]
> Until [NationalSecurityAgency/ghidra#8544][pr] is merged, many instructions will fail to disassemble correctly, and it will be very difficult to analyze the binary.


[fw]: https://github.com/LibreELEC/dvb-firmware/blob/90261ae2934329f6ca84dd6c72d10d0777bf4b0e/firmware/dvb-demod-mxl692.fw
[MxL692]: https://web.archive.org/web/20211206054829/https://www.maxlinear.com/product/connected-home/satellite-andamp;-terrestrial/fsc-andamp;-narrowband-tuners-demods/terrestrial/mxl692
[pr]: https://github.com/NationalSecurityAgency/ghidra/pull/8544
