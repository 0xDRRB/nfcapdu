# nfcapdu
A simple tool to exchange APDUs with an RFID/NFC tag

This program allows you to create an interactive session to send APDUs to a tag and receive responses.

- It supports the creation of aliases (defined in `~/.nfcapdurc`) to simplify the sending of common commands (Glib)
- APDU history is kept between sessions (in `~/.nfcapdu_history`) (readline)
- You can set default modulation and baud rate in config file (see `nfcapdurc_sample`)
- You can enable or disable colors in config file (see `nfcapdurc_sample`)


```
$ ./nfcapdu
NFC reader: ASK / LoGO (pn53x_usb:002:033) opened
ISO/IEC 14443A (106 kbps) tag found. UID: 02C4004E447224
4 aliases loaded
APDU> alias 
Defined aliases:
  selst25app = 00a4 0400 07 d2760000850101 00
  selstfile = 00a4 000c 02 e101
  selccfile = 00a4 000c 02 e103
  readstfile = 00b0 0000 12
APDU> selst25app
=> 00 a4 04 00 07 d2 76 00 00 85 01 01 00 
<= 90 00 
APDU> 00a4 000c 02 e101
=> 00 a4 00 0c 02 e1 01 
<= 90 00 
APDU> readstfile
=> 00 b0 00 00 12 
<= 00 12 01 00 11 00 81 02 02 c4 00 4e 44 72 24 1f ff c4 90 00 
APDU> 00b0 0000 aa
=> 00 b0 00 00 aa 
<= 62 82 
Error: End of file/record reached before reading Le bytes (0x6282)
cardtransmit error!
APDU> 
```
