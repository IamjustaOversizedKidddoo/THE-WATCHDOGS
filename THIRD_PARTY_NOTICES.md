# Third-Party Software, Tool, and Asset Notices

This project incorporates third-party open-source tools, software libraries, and digital assets under their respective licenses.

---

## 1. Third-Party Tools Used (Agent Desks)

The Watchdogs orchestrates the following independent open-source projects as agent "desks." I do not own or claim authorship of any of them — this project wraps and coordinates them, it does not replace or rebrand their underlying work.

| Desk Call Sign | Underlying Project | Primary Role | Source Repository | Confirmed Upstream License | Preserved Directory |
|---|---|---|---|---|---|
| **/jonathan** | **HackerGPT** | Reconnaissance & attack surface mapping | <https://github.com/stalane/HackerGPT> | **GNU General Public License v3.0 (GPL-3.0)** | [`jonathan/`](./jonathan) |
| **/chris** | **Strix** | Exploitation validation & PoC verification | <https://github.com/usestrix/strix> | **Apache License 2.0 (Apache-2.0)** | [`chris/`](./chris) |
| **/daniel** | **Shannon** | Code review & static analysis (SAST) | <https://github.com/KeygraphHQ/shannon> | **GNU Affero General Public License v3.0 (AGPL-3.0)** | [`daniel/`](./daniel) |
| **/david** | **HackBot** | Automation, CVE lookups & payload suggestions | <https://github.com/morpheuslord/HackBot> | **No license file upstream** (Public repo, © Chiranjeevi G. / morpheuslord) | [`david/`](./david) |
| **/wrench** / **/gabriel** | **HexStrike AI** | Tool floor & 150+ cybersecurity tool MCP server | <https://github.com/0x4m4/hexstrike-ai> | **MIT License** (© 2026 Muhammad Osama) | [`wrench/`](./wrench) |
| **/maverick** | **Anthropic Cybersecurity Skills** | 818 structured offensive security skills | <https://github.com/mukul975/Anthropic-Cybersecurity-Skills> | **Apache License 2.0 (Apache-2.0)** | [`skills-library/`](./skills-library) |

See each project's own `LICENSE` file (preserved in its folder under this repository) for full license terms.

---

## 2. Upstream Pixel-Art Asset Attribution — LimeZu

The bundled pixel-art tilesets and maps are from **Modern Interiors — RPG Tileset [16X16]** by **LimeZu**, used under the **Complete Version licence** purchased on 2026-08-20.

- **Asset Pack**: Modern Interiors — RPG Tileset [16X16]
- **Author**: LimeZu — <https://limezu.itch.io/moderninteriors>
- **Creator Website**: <https://limezu.itch.io/>
- **License Tier**: Complete Version (purchased 2026-08-20)
- **License Terms** (from `munder-difflin/src/renderer/src/assets/tilesets/LIMEZUASSETS-LICENSE.txt`):
  - **CAN**: Edit and use the assets in any commercial or non-commercial project.
  - **CANNOT**: Resell or distribute the assets to others; edit and resell the assets to others.
  - **CREDITS**: Credits are required with a link to <https://limezu.itch.io/>.

### Bundled Asset Locations
- `munder-difflin/src/renderer/src/assets/tilesets/interiors.png`
- `munder-difflin/src/renderer/src/assets/tilesets/office-tileset.png`
- `munder-difflin/src/renderer/src/assets/tilesets/a5-office-floors-walls.png`
- `munder-difflin/src/renderer/src/assets/maps/office.tmj`
- `munder-difflin/src/renderer/src/assets/maps/brooklyn99.tmj`

See [`munder-difflin/LICENSE-ASSETS`](./munder-difflin/LICENSE-ASSETS) and [`munder-difflin/src/renderer/src/assets/ATTRIBUTION.md`](./munder-difflin/src/renderer/src/assets/ATTRIBUTION.md) for further details.

### Procedural Cast Sprites
The character card portraits and walking sprites on the office floor are **not** LimeZu assets; they are drawn procedurally in [`munder-difflin/src/renderer/src/scene/office/portraitArt.ts`](./munder-difflin/src/renderer/src/scene/office/portraitArt.ts) from per-character recipes and are licensed under the MIT License along with the project source code.

---

## 3. Upstream Map / Tileset Vendoring — shahar061/the-office

- **Component**: Office tileset and Tiled map structure
- **Source**: [`shahar061/the-office`](https://github.com/shahar061/the-office)
- **License**: ISC License

---

## 4. Core Third-Party Open Source Libraries

The project relies on several key open-source libraries under permissive licenses (MIT / Apache-2.0 / BSD):
- **Pixi.js** (<https://pixijs.com/>) — MIT License
- **xterm.js** (<https://xtermjs.org/>) — MIT License
- **node-pty** (<https://github.com/microsoft/node-pty>) — MIT License
- **electron-vite** (<https://electron-vite.org/>) — MIT License
- **CodeMirror** (<https://codemirror.net/>) — MIT License
- **Remotion** (<https://www.remotion.dev/>) — Remotion License / Evaluation

---

## 5. Source Code License (MIT)

All original application harness source code in the `munder-difflin` repository is licensed under the **MIT License**.

See the [`munder-difflin/LICENSE`](./munder-difflin/LICENSE) file for the full text of the MIT License:
```
Copyright (c) 2026 Chaitanya Giri
```

The MIT grant applies strictly to the orchestration and application harness code. The bundled third-party art assets and external open-source engines referenced above remain subject to their respective licenses without conflict or contradiction.
