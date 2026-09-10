# Bundled fonts

Inter and JetBrains Mono, vendored so the application renders in its own
typeface without contacting a CDN. Previously these were pulled from
`fonts.googleapis.com` at runtime, which made a tool that describes itself as
offline-capable and local-first announce every launch to a third party, and
left the interface unstyled on any network that could not reach Google.

| File | Family | Subset | Weights | Bytes |
|---|---|---|---|---|
| `inter-latin.woff2` | Inter | latin | 100–900 (variable) | 48,256 |
| `inter-latin-ext.woff2` | Inter | latin-ext | 100–900 (variable) | 85,068 |
| `jetbrains-mono-latin.woff2` | JetBrains Mono | latin | 400–700 (variable) | 31,432 |
| `jetbrains-mono-latin-ext.woff2` | JetBrains Mono | latin-ext | 400–700 (variable) | 11,624 |

Both are variable fonts, so one file per subset covers every weight the design
system uses instead of one file per weight. Only the Latin subsets are bundled;
each `@font-face` in `src/index.css` carries the `unicode-range` Google serves
it under, so the browser fetches `latin-ext` only when an accented character
actually appears.

## Licence

Both families are under the SIL Open Font License 1.1, which permits bundling
and redistribution in this form. The full text of each is beside the fonts:

* `Inter-LICENSE.txt` — Copyright (c) 2016 The Inter Project Authors
* `JetBrainsMono-LICENSE.txt` — Copyright 2020 The JetBrains Mono Project Authors

The OFL requires that the licence travel with the font, that the fonts are not
sold on their own, and that any modified version not use the reserved names.
None of those constrain use here: the files are unmodified, they are distributed
as part of the application, and both licences ship with them.
