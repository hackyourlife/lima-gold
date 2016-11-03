pkgname=("lima-gold")
pkgver=1.1.26
pkgrel=1
pkgdesc="A terminal based Jabber MUC client with support for encrypted and invisible messages"
arch=("any")
url="https://github.com/hackyourlife/lima-gold"
license=("Custom")
depends=("python" "python-sleekxmpp" "python-crypto" "words")
optdepends=("espeak" "python-pyaudio")
source=(client.py encryptim.py main.py api.py rl.py rp.py rot.py espeak.py setup.py morse.py random_quote.py bofh_excuses.txt)
md5sums=('d9e638aceae3e0724deb2691bd6f2847'
         '851a9f27429ca1dd6792cde39b061d2d'
         'cb11828825ca6df8ca105668bdde6cc6'
         '34d41be6e5bd7128a80163f869372b12'
         '5e1c0e2735ee8750ee2f29e1a4c3eefa'
         '34553800636e433a5a95aa69e64734be'
         '9335387c75f65281e7846f90053376fe'
         '7a073c923ef9760c52f05a134625fb0f'
         'be06c215cf34d5af64287366bcbc48de'
         'f36f709e90c40be0af00d97dbf983ed8'
         'b558b1d60d51dac18c2fab59b93d1844'
         'c31a633e277cc68c2c42884e50eb8f91')

package() {
  cd "$srcdir"
  python setup.py install --root="$pkgdir/" --install-lib /usr/share/lima-gold --optimize=1
  mkdir -p "$pkgdir/usr/bin"
  ln -s /usr/share/lima-gold/main.py "$pkgdir/usr/bin/lima-gold"
  rm "$pkgdir/usr/share/lima-gold/lima_gold-1.0-py3.5.egg-info"
  chmod 0755 "$pkgdir/usr/share/lima-gold/main.py"
  install -m644 bofh_excuses.txt "$pkgdir/usr/share/lima-gold/bofh_excuses.txt"
}

# vim:set ts=2 sw=2 et:
