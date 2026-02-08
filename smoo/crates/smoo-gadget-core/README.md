# smoo-gadget-core

Much of the "guts" of smoo's gadget daemon live here:

 * `IoPump` owns and drives the protocol interactions on the (USB) wire.
 * `ExportController` runs a reconciler that drives configured exports (from the host) into corresponding online ublk 
   targets.
 * `LinkController` is also a kinda-reconciler that handles the USB link (or the host side driving it) going away and/or
   coming online, and ensures in-flight I/O is parked and replayed (no timeouts).
 * `StateStore` handles (un)marshaling the runtime state we need to survive across daemon restarts/crashes.

Currently, we assume that we're dispatching i/o requests from ublk to USB via FunctionFS. In the future, if we were to
support other platforms/targets, we'd try to tease the ublk / FFS parts into separate crates. That's very much out of
scope for now, though.

The bits that drive the actual ublk (ctrl + i/o queues) rings live in smoo-gadget-ublk.
