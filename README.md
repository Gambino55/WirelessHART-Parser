# WirelessHART-Parser

A Wireshark Lua dissector for **WirelessHART (IEC 62591)**, usable on live
over-the-air captures from any standard IEEE 802.15.4 sniffer.

WirelessHART frames are IEEE 802.15.4 frames. Wireshark's built-in 802.15.4
("wpan") dissector decodes the MAC header and checks the FCS; this plugin
decodes the WirelessHART layer that sits on top:

- **DLPDU specifier** — priority, network-key flag, packet type, and MIC
- **Advertise** — absolute slot number, join control, channel map (shown as the
  list of active channels, e.g. `11-25` for a full network or `13-21` when some
  channels are blacklisted), superframes and join links
- **Ack** — response code, time adjustment
- **Data** — network-layer (NPDU) header: TTL, ASN snippet, graph ID, and
  addresses (0xF980 / 0xF981 labelled **Network Manager** / **Gateway**)

> **Scope.** This dissector decodes WirelessHART **framing** (link and
> network-layer structure). It does **not** decrypt the encrypted NPDU payload —
> that requires session keys obtained from a captured join handshake, which is
> outside what a passive dissector can do. See [Limitations](#limitations).

## Lineage & credits

This is a fork that refines earlier work. Credit where it's due:

- The core dissector originated in **Sam Roberts'** post to the wireshark-dev
  mailing list (July 2011):
  <https://www.wireshark.org/lists/wireshark-dev/201107/msg00040.html>
- **K. Reid Wightman** packaged it as the
  [WirelessHART-Parser](https://github.com/reidmefirst/WirelessHART-Parser)
  project and contributed the sample capture.
- This fork fixes the frame-parsing bug Reid's README anticipated, reworks the
  plugin to attach to Wireshark's standard 802.15.4 dissector so it works with
  modern sniffers, and validates it against live over-the-air captures (below).

## What's new in this fork

- **Fixes the "choke" on beacon/advertise frames** that Reid's README flagged as
  an unresolved parser bug. The cause was a message-integrity-code (MIC) offset
  error — the code read part of the 2-byte frame checksum (FCS) as MIC data.
- **Attaches to Wireshark's built-in IEEE 802.15.4 ("wpan") dissector** via a
  heuristic plus "Decode As" by PAN ID, instead of a bespoke link type that
  depended on a never-completed KillerBee change. This is what lets it work with
  any standard 802.15.4 sniffer today.
- **Portable across Lua 5.2 and 5.4** (Wireshark ≤ 4.2 and ≥ 4.4): no reliance
  on bitwise operators. Removed a crash-prone `assert` and a stray debug `print`.
- **Advertise channel map** rendered as the list of active channels, not raw hex
  (e.g. `ff7f (channels 11-25)` for a full network, or `fc07 (channels 13-21)`
  when some channels are blacklisted). The byte before the map is the number of
  active channels (field `wihart.advertise.chanmapsz`, now labelled "active
  channels"), not a length. The map is read as 2 bytes (falling back to the older
  ceil(count/8) bytes only if 2 doesn't fit the frame), so networks with 8 or
  fewer active channels now decode correctly.
- **Network-layer address nicknames**: 0xF980 → Network Manager, 0xF981 →
  Gateway.
- **Sample capture** (`hart-test.pcap`) converted from the old custom link type
  to the standard `DLT_IEEE802_15_4_WITHFCS`, so it opens in stock Wireshark.

## Installation

Copy `wirelesshart.lua` into your personal Wireshark plugins folder
(Help > About Wireshark > Folders > "Personal Lua Plugins"), e.g.:

- Wireshark ≥ 4.6, macOS/Linux: `~/.local/lib/wireshark/plugins/`
- Older Wireshark, Linux/macOS: `~/.config/wireshark/plugins/`
- Windows: `%APPDATA%\Wireshark\plugins\`

Then **Analyze > Reload Lua Plugins** (or restart Wireshark). Confirm it loaded
under Help > About Wireshark > Plugins.

## Live capture

Any sniffer that delivers raw 802.15.4 frames to Wireshark works. Tested paths:

- **Nordic nRF52840** (incl. nRF52840-MDK USB dongle) with Nordic's
  [nRF Sniffer for 802.15.4](https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4).
  Appears as a capture interface (extcap). Its **IEEE 802.15.4 TAP** output
  carries per-frame **RSSI, LQI, and channel** — recommended.
- **TI CC2531** with `whsniff` (`whsniff -c <channel> | wireshark -k -i -`) or
  KillerBee.

Steps:
1. Pick a channel in the network's active range (WirelessHART uses 11–25).
2. For the nRF sniffer, set **Out-Of-Band meta-data = IEEE 802.15.4 TAP** to
   record RSSI/LQI.
3. Start capturing. Frames from the network show as **WiHART** in the Protocol
   column.
4. If a frame shows as plain 802.15.4 data instead, use
   **Analyze > Decode As… > "IEEE 802.15.4 PANID" = your network ID > WIHART**.

### Useful display filters and columns

- Filter to WirelessHART: `wihart`
- Only data frames: `wihart.dlpduspec.pkttype == 7`
- RSSI / channel columns (from the 802.15.4 TAP layer, not this plugin):
  custom columns `wpan-tap.rss` (dBm) and `wpan-tap.ch_num`.

## Validation

This fork was verified against live over-the-air traffic, not just the sample:

- **Two independent sniffer hardware paths:** six TI CC2531 dongles (via the
  ZBOSS sniffer, channels 11–16) and a Nordic nRF52840-MDK dongle.
- **Live captures decoded cleanly** — every frame as WirelessHART, including
  advertise, data, ack, and keep-alive, with correct addresses, channel maps,
  and (on the nRF path) RSSI.
- **Automated tests:** the dissector was exercised against the sample capture and
  a set of synthetic frames (ack, keep-alive, disconnect, data with short and
  64-bit addresses) covering accept and reject paths.
- **Independent review** of the dissector changes caught and fixed an
  out-of-bounds read on data frames carrying 64-bit addresses.

## Limitations

- **No payload decryption.** The NPDU payload (transport layer and HART
  commands) is encrypted with session keys and is not decoded.
- **The MIC is displayed but not verified.**
- **Channel hopping.** WirelessHART hops across its active channels roughly every
  10 ms, so a single-channel sniffer sees only a fraction (~1/15) of traffic.
  Advertise frames are broadcast regularly and are a good first check. For
  broader coverage, run several sniffers on different channels and merge the
  captures (`mergecap`, or capture multiple interfaces at once).

## Sample capture

`hart-test.pcap` contains advertise frames from a Linear Technology WirelessHART
development kit's access point in default configuration. It uses the standard
802.15.4-with-FCS link type, so it opens in stock Wireshark; with the plugin
installed, the WirelessHART layer is decoded.

## License

The original code carries no explicit license (it derives from Sam Roberts'
public mailing-list post, as packaged by Reid Wightman). This fork preserves
that lineage and adds no license of its own. If you intend to redistribute,
please consult the original authors.
