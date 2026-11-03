# WirelessHART-Parser

Wireshark Lua dissector for WirelessHART (IEC 62591), usable on live
over-the-air captures from any standard IEEE 802.15.4 sniffer.

Wireshark's built-in 802.15.4 dissector decodes the MAC header (sequence
number, network ID, addresses, FCS). This plugin decodes the WirelessHART
layer on top of it:

- DLPDU specifier (priority, network-key flag, packet type) and MIC
- Advertise (absolute slot number, join control, channel map, superframes and join links)
- Ack (response code, time adjustment)
- Data: network-layer (NPDU) header — TTL, ASN snippet, graph ID, addresses

## Installation

Copy `wirelesshart.lua` into your personal Wireshark plugins folder
(Help > About Wireshark > Folders > "Personal Lua Plugins"), for example:

- Linux/macOS: `~/.local/lib/wireshark/plugins/`
- Windows: `%APPDATA%\Wireshark\plugins\`

Restart Wireshark (or Analyze > Reload Lua Plugins).

## Live capture

Any sniffer that delivers raw 802.15.4 frames to Wireshark works, for example:

- **nRF52840 Dongle** with Nordic's
  [nRF Sniffer for 802.15.4](https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4)
  — appears directly as a capture interface in Wireshark (extcap).
- **KillerBee** (`zbdump -c <channel> -w out.pcap`) with a supported radio.
- **TI CC2531** with a pcap-producing tool such as `whsniff`.

Steps:

1. Pick a channel between 11 and 25 (WirelessHART does not use channel 26).
2. Start the capture. Frames from the network should show as `WiHART` in the
   Protocol column.
3. If they show as plain 802.15.4 data instead, use
   Analyze > Decode As… > "IEEE 802.15.4 PANID" = your network ID > `WIHART`.

### Channel hopping

WirelessHART hops channel every 10 ms timeslot across up to 15 channels, so a
single-channel sniffer only sees the slice of traffic that lands on its
channel (roughly 1/15, more if the network blacklists channels). Advertise
frames are broadcast regularly and hop across all channels, so they appear on
whichever channel you pick, which makes them a good first check. To see more traffic:

- Run several sniffers on different channels and capture all interfaces at
  once in Wireshark (Capture > Options, select multiple), or merge files with
  `mergecap`.
- Or use firmware that follows the hop sequence (as presented by Paternotte
  and van Ommeren, hardwear.io 2018).

## Limitations

- The NPDU payload (transport layer and HART commands) is encrypted with
  session keys and is not decoded.
- The MIC is shown but not verified.

## Sample capture

`hart-test.pcap` contains advertise frames from a Linear Technology
WirelessHART development kit's access point in default configuration
(network ID 1229). It uses the standard 802.15.4-with-FCS link type, so it
opens in stock Wireshark; with the plugin installed the WirelessHART layer is
decoded.
