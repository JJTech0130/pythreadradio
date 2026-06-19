# pythreadradio

> **⚠️ Experimental.** This project is experimental and not supported by Apple.

Python library and CLI for talking to the Thread radio on Apple Silicon
Macs.

Unlike my [threadctl](https://github.com/JJTech0130/threadctl), it talks directly to the RCP and bypasses Apple's userspace Thread stack. As such, it does not require any special entitlements, but may be more fragile.
## Supported hardware

Starting roughly in 2023, Apple began enabling the Thread RCP included in Broadcom's BCM4388 radio.
> Apple uses modules from [USI](https://www.usiglobal.com/) and [Amkor](https://amkor.com/) to package the BCM4388 radio.
> I have documented the module codename and underlying chipset used in each Mac, extracted from the devicetree: https://gist.github.com/JJTech0130/bf7dbc5b4ea1442a07bbd58bb1ae89c4

This has been tested on:
- 14" MacBook Pro with M4 Pro

It should be possible to make it work on most Macs with M3 and later, though this has not been tested.

This will NOT currently work on Macs with the new Apple N1 chipset, notably:
- MacBook Air with M5
- MacBook Pro with M5 Pro/M5 Max

## Installation

```bash
git clone https://github.com/JJTech0130/pythreadradio.git
cd pythreadradio
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

### Sniff to Wireshark

```bash
threadsniff -c 11 | wireshark -k -i -
```

Where `11` is the 802.15.4 channel to sniff.

## Notes

Apple's Thread RCP uses the [Spinel](https://tools.ietf.org/html/draft-rquattle-spinel-unified) protocol, it appears to be based on a modified version of OpenThread.

## Troubleshooting

If you encounter the following error:
> RuntimeError: [skywalk] os_channel_create failed for 'tsi' (is the owning daemon still running?)

This means that Apple's `threadradiod` is currently running. Use the included `daemonslayer` command to stop it.
```
sudo daemonslayer threadradio
```

Alternatively, if you have SIP disabled, you can unload it with `launchctl`.
