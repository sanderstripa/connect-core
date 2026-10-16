# Pinned Xray BBR congestion controller

Source: XTLS/Xray-core v26.10.10,
transport/internet/hysteria/congestion/{bbr,common}.
Mozilla Public License 2.0 is retained in MPL-2.0.txt.
The only source edits are local package import paths. Original tests retained.
QUIC fork pinned to the exact apernet revision used by that Xray release.
No Xray handshake, proxy protocol, Sudoku mask or cipher is copied here.
BBR remains paced and bandwidth/RTT-controlled; Brutal and fixed unlimited
sending rates are not used. CONNECT mTLS and device/packet policy remain.
