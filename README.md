# pkcs11-autopin

A PKCS#11 proxy for automatic authentication using stored PINs.

## Configuration

Configuration is read from `/etc/pkcs11-autopin.yaml`; see `example-config.yaml`.

PINs are read from `<pins_dir>/<token-label>`, with `/etc/pkcs11-autopin.pins` as the default directory. Leading and trailing whitespace is ignored.
