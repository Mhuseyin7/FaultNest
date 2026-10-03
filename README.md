# FaultNest

## Capture. Isolate. Replay.

**FaultNest**, zor yeniden üretilen software failures için local-first bir reproducibility platformudur. Bir bug report içindeki technical context'i toplar, sensitive data'yı sanitize eder, portable bir bundle oluşturur ve failure'ı disposable bir environment içinde tekrar çalıştırmaya yardımcı olur.

> "It fails on the user's machine, but I cannot reproduce it."

```text
Bug report → Captured technical context → Sanitized bundle → Isolated environment → Replay
```

Bu proje open source olarak geliştirilmektedir ve **[muhammedkoca.com.tr](https://muhammedkoca.com.tr)** tarafından yapılmıştır.

## Neden FaultNest?

Production failure'larını paylaşmak çoğu zaman log, screenshot ve tahminlerden ibaret kalır. FaultNest, reproducibility için gerekli minimum technical state'i bundle haline getirir. Amaç telemetry toplamak veya data upload etmek değil; developer'ın kendi cihazında güvenli bir replay yapabilmesidir.

FaultNest şunlar değildir:

- crash telemetry SaaS veya Sentry clone
- raw log uploader ya da remote desktop tool
- Docker GUI
- `.env` kopyalama aracı
- automatic cloud upload service

## Özellikler

- Strict `faultnest.yml` configuration validation
- Git commit, branch, dirty-state ve sanitized patch metadata capture
- Dependency manifest / lockfile detection
- Configured log files için bounded capture
- Environment variable value yerine default olarak yalnızca isim capture etme
- JWT, bearer token, GitHub token, AWS key, private key, database credential, Authorization/Cookie header, e-mail ve IP redaction
- Aynı sensitive value için stable pseudonymization
- BLAKE3 checksum ile integrity verification
- Archive traversal, oversized entry ve corrupted bundle protection
- Execute etmeden safe bundle inspection
- Exact Git commit source reconstruction ve captured patch apply
- Local argv replay; shell string concatenation yok
- Optional constrained Docker replay: read-only workspace, dropped capabilities, `no-new-privileges`, CPU/RAM/PID limits ve restricted network
- Local-only Node.js ve Python capture SDK'ları

`minimize` ve `test` komutları, gerçek bir reproduction oracle / assertion engine olmadan success döndürmez. Bu özellikler hazır olmadığında tool güvenli biçimde error verir; fabricated derived bundle veya regression test üretmez.

## Quick Start

Rust stable kurulu olmalıdır.

```bash
git clone https://github.com/Mhuseyin7/FaultNest.git
cd FaultNest
cargo build --release
./target/release/faultnest init
```

Örnek `faultnest.yml`:

```yaml
version: 1
application:
  name: shop-api
capture:
  repository: true
  logs:
    - path: ./logs/app.log
      tail_lines: 5000
environment:
  allow_names: [NODE_ENV, APP_ENV]
redaction:
  emails: true
  ip_addresses: true
  paths: true
replay:
  command:
    name: regression-test
    executable: pnpm
    args: [test, payments]
  network: OFF
```

```bash
faultnest preview
faultnest capture --request failing-request.json --output issue.faultnest
faultnest verify issue.faultnest
faultnest inspect issue.faultnest
faultnest replay issue.faultnest --yes
faultnest down /path/to/faultnest-workspace
```

## Docker Replay

Container replay için `replay.container` tanımlanır:

```yaml
replay:
  command:
    name: reproduce
    executable: npm
    args: [test]
  network: OFF
  container:
    image: node:22-alpine
    cpus: "2"
    memory: 1g
    pids_limit: 256
```

FaultNest Docker socket mount etmez, privileged mode kullanmaz ve host workspace'i read-only mount eder.

## SDK'lar

Node.js ve Python SDK'ları network request göndermez. Local `.faultnest/requests.jsonl` dosyasına sanitized JSONL event yazarlar.

```js
import { captureError } from '@faultnest/sdk';
captureError(error, { request: { method: 'POST', route: '/payments' } });
```

```python
from faultnest import capture_error
capture_error(error, {"request": {"method": "POST", "route": "/payments"}})
```

Detaylar için [SDK documentation](sdks/README.md) belgesine bakın.

## Güvenlik ve Privacy

FaultNest local-first tasarlanmıştır: mandatory account, telemetry, automatic upload ve external AI service'e source/log gönderimi yoktur. `.env` dosyaları körlemesine capture edilmez. Environment value'ları capture edilmez; yalnızca explicitly allowlisted isimler kaydedilir.

Redaction bir security boundary değil, defense-in-depth katmanıdır. Bundle paylaşmadan önce `faultnest inspect` çalıştırın ve capture configuration'ını dar tutun.

- [Architecture](ARCHITECTURE.md)
- [Bundle Format](BUNDLE_FORMAT.md)
- [Security Policy](SECURITY.md)
- [Threat Model](THREAT_MODEL.md)
- [Privacy](PRIVACY.md)
- [Contributing](CONTRIBUTING.md)

## Development

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo build --release
```

## License

FaultNest, [Apache License 2.0](LICENSE) ile lisanslanmıştır.

---

Made with care by **[muhammedkoca.com.tr](https://muhammedkoca.com.tr)**. Open source software should make debugging safer, more reproducible and more respectful of privacy.
