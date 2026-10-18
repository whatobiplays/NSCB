# NSTool v1.9.2 transitive source notices

The pinned NSTool source commit is
`e89ea84bd70c11b67ebec9153fb4a446f18a9d3d`. Its `.gitmodules` file records
five source dependencies. Their exact commits and licenses are:

| Dependency | Pinned commit | License |
| --- | --- | --- |
| `deps/libfmt` | `b03b081e026ceb1226b45de926babe629d6c0688` | MIT |
| `deps/liblz4` | `561775a11e00cbd21a45031c64068cb5e1242608` | BSD 2-Clause |
| `deps/libmbedtls` | `74346376dd035e9fbc161cdb80afc646b72fde86` | Apache-2.0 |
| `deps/libpietendo` | `5d50d02f8f3b8918bdfbbb599b8c4c1628660d89` | MIT |
| `deps/libtoolchain` | `578d170f5b294e4a9feb3cc2d504896e846f204e` | MIT |

License texts were read from each repository at the pinned commit. NSTool's
own MIT text is reproduced in `nstool-v1.9.2-MIT.txt`. NSCB does not
redistribute the NSTool executable or archive in this repository; managed
provisioning downloads the exact upstream release asset declared by the
provider manifest. Anyone redistributing NSTool or a derived binary must
retain the upstream notices and satisfy the applicable transitive license
requirements.

The provider operation does not bundle Nintendo keys, tickets, firmware,
certificates, or game content.
