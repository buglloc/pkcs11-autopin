pkgname=pkcs11-autopin
pkgver=0.1.0
pkgrel=1
pkgdesc="PKCS#11 proxy library with automatic PIN entry"
arch=('x86_64')
url="https://github.com/buglloc/pkcs11-autopin"
license=('MIT')
depends=('glibc')
makedepends=('rust' 'cargo')
backup=('etc/pkcs11-autopin.yaml')
source=("$pkgname-$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$pkgname-$pkgver"
    cargo build --release --locked
}

check() {
    cd "$pkgname-$pkgver"
    cargo test --release --locked
}

package() {
    cd "$pkgname-$pkgver"

    install -Dm755 "target/release/libpkcs11_autopin.so" \
        "$pkgdir/usr/lib/pkcs11/libpkcs11_autopin.so"

    ln -s pkcs11/libpkcs11_autopin.so "$pkgdir/usr/lib/libpkcs11_autopin.so"

    install -dm700 "$pkgdir/etc/pkcs11-autopin.pins"
    install -Dm644 example-config.yaml "$pkgdir/etc/pkcs11-autopin.yaml"
}

