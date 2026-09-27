# Third-party notices

This independent Linux implementation follows AltStore/AltSign's wire protocol,
Apple authentication flow, bootstrap metadata, and provisioning behavior. It is
not an official AltStore release and does not bundle an AltStore IPA.

| Project | Use | License / source |
| --- | --- | --- |
| AltStore, Riley Testut and contributors | Protocol and behavior reference; revision `74dc2d4c71e8a1d1abf91dcfc0cf3334f777f972` | AGPL-3.0, https://github.com/altstoreio/AltStore |
| AltSign, Riley Testut and contributors; authentication based on Kabir Oberai's work | Apple authentication/provisioning reference | https://github.com/rileytestut/AltSign |
| AltServer-Linux, NyaMisty and contributors | Linux integration reference, `new` branch inspected | https://github.com/NyaMisty/AltServer-Linux |
| go-ios, Daniel Paulus and contributors | Device transport, AFC, plist codec | MIT, https://github.com/danielpaulus/go-ios |
| zsign, zhlynn and contributors | Compiled native signing helper | MIT, `third_party/zsign/LICENSE`, https://github.com/zhlynn/zsign |
| zeroconf, grandcat and contributors | DNS-SD advertisement | MIT, https://github.com/grandcat/zeroconf |
| howett.net/plist, D. Howett and contributors | Property lists | BSD-3-Clause, https://github.com/DHowett/go-plist |
| Mozilla pkcs7 contributors | Provisioning profile CMS parsing | MIT, https://github.com/mozilla-services/pkcs7 |
| go-pkcs12, SSLMate and contributors | Certificate handoff | BSD-3-Clause, https://software.sslmate.com/src/go-pkcs12 |
| Go contributors | Standard library and golang.org/x packages | BSD-3-Clause, https://go.dev/LICENSE |
| anisette-v3-server, Dadoum and contributors | Separately distributed Compose companion | https://github.com/Dadoum/anisette-v3-server |

Go module versions and checksums are recorded in `go.mod` and `go.sum`; zsign's
exact source is a Git submodule. Debian library notices reside under
`/usr/share/doc` in the image. Runtime Go dependency license files are collected
into `/usr/share/doc/altserver/go-dependencies` during image construction.

The image's OCI source and revision labels identify corresponding source when
built by the publishing workflow. Distributors must retain this repository,
the recorded submodule revision, and applicable dependency source/license notices.
Anisette's first-run provisioning downloads are managed by that separate upstream
service; Apple libraries are not copied into this project's image.
