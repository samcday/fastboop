# smoo-gadget-ublk

Think of this crate as an any% speedrun to a working ublk device, for smoo's porpoises. It uses the io-uring crate to
speak just enough ublk UAPI to create/start the device, process its I/O requests, and nothing more.
