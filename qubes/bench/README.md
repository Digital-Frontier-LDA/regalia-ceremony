# Bench power control on Qubes

The power-loss rigs cut VBUS to the staging Pico with `uhubctl`. On the Mac bench that ran next to
the workload. On Qubes it cannot: the hub belongs to the USB qube, and a power cut makes the Pico
re-enumerate, which on **R4.2 detaches it from the bench qube for good**. Re-attaching is a dom0
operation.

So one dom0 qrexec service does both halves: it switches the port through the USB qube, and on
power-on re-attaches whatever enumerates **at that port path** to the bench qube.

| file | installed in dom0 as |
|---|---|
| `dom0/regalia.PicoPower` | `/etc/qubes-rpc/regalia.PicoPower` (mode 755) |
| `dom0/30-regalia-pico-power.policy` | `/etc/qubes/policy.d/30-regalia-pico-power.policy` |
| `dom0/pico-power.conf.example` | `/etc/regalia/pico-power.conf`, filled in |

## What the bench qube can do with it

Exactly three verbs, `off`, `on` and `status`, on exactly one port. The hub, the port, the USB qube
and the qube the device returns to all come from the dom0 config file. The caller controls none of
them, and the service re-checks the caller against that file, on top of the policy.

It refuses to cut a port the Debug Probe is on. On 2026-08-09 that took a physical replug to recover.

## Install

Everything here is run **in dom0**. Moving a file into dom0 is a deliberate act on Qubes, so read
the service before installing it.

1. `uhubctl` must exist in the USB qube. If `sys-usb` is disposable, install it in the template
   that `sys-usb` is based on, then restart `sys-usb`.
2. Find the Pico's hub and port from the USB qube:

       qvm-run --pass-io -u root sys-usb uhubctl

   The hub must support per-port power switching (`ppps`). A hub that reports "off" while the
   device stays powered makes every result worthless, which is why the rig verifies the cut.
3. Copy the three files over from the bench qube (`dev-regalia`):

       qvm-run --pass-io dev-regalia 'cat ~/rc/qubes/bench/dom0/regalia.PicoPower' | sudo tee /etc/qubes-rpc/regalia.PicoPower >/dev/null
       sudo chmod 755 /etc/qubes-rpc/regalia.PicoPower
       qvm-run --pass-io dev-regalia 'cat ~/rc/qubes/bench/dom0/30-regalia-pico-power.policy' | sudo tee /etc/qubes/policy.d/30-regalia-pico-power.policy >/dev/null
       sudo mkdir -p /etc/regalia
       qvm-run --pass-io dev-regalia 'cat ~/rc/qubes/bench/dom0/pico-power.conf.example' | sudo tee /etc/regalia/pico-power.conf >/dev/null
       sudo nano /etc/regalia/pico-power.conf     # HUB_LOC, HUB_PORT

4. From the bench qube, check before the first cut:

       qrexec-client-vm dom0 regalia.PicoPower+status

   The last line must name the Pico as `sys-usb:<HUB_LOC>.<HUB_PORT>`. If it names nothing, the
   port path is wrong, and `on` would never re-attach.

## Removing it

Delete the three files from dom0. Nothing else is changed.
