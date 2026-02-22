# Device permissions

fastboop requires access to vendor USB boot mode interfaces so it can detect and boot a supported device.

## Safety and scope

- fastboop boot flow is non-mutating.
- No flash / erase / format / slot-toggle actions are part of the supported path.
- Boot is ephemeral and intended for live sessions.

## Host permission model (starter)

This page is a placeholder for a stable user-facing permission guide that will include:

- Linux `udev` rule setup.
- Group/ACL requirements for USB device access.
- Browser permission behavior for WebUSB frontends.

Until this page is expanded, use CLI/desktop paths where your user has explicit USB access rights.
