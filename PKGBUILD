pkgname=("lima-gold")
pkgver=1.1.4
pkgrel=1
pkgdesc="A terminal based Jabber MUC client with support for encrypted and invisible messages"
arch=("any")
url="https://github.com/hackyourlife/lima-gold"
license=("Custom")
depends=("python" "python-sleekxmpp" "python-crypto" "words")
source=(client.py encryptim.py main.py api.py rl.py rp.py rot.py setup.py)
md5sums=("225d06e97466329015814a9ee1c66db6"
         "851a9f27429ca1dd6792cde39b061d2d"
         "246c9ddbed29b1678c2f25358ae6db3e"
         "34d41be6e5bd7128a80163f869372b12"
         "5e1c0e2735ee8750ee2f29e1a4c3eefa"
         "34553800636e433a5a95aa69e64734be"
         "5d8924f45342614b8dcb418f0915cfd6"
         "be06c215cf34d5af64287366bcbc48de")


package() {
  cd "$srcdir"
  python setup.py install --root="$pkgdir/" --install-lib /usr/share/lima-gold --optimize=1
  mkdir -p "$pkgdir/usr/bin"
  ln -s /usr/share/lima-gold/main.py "$pkgdir/usr/bin/lima-gold"
  rm "$pkgdir/usr/share/lima-gold/lima_gold-1.0-py3.5.egg-info"
  chmod 0755 "$pkgdir/usr/share/lima-gold/main.py"
}

# vim:set ts=2 sw=2 et:
