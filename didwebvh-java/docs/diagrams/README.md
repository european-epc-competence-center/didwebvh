# Architecture Diagrams

## architecture-overview.puml

A curated (hand-written, not auto-generated) package diagram showing the core
call path through the library: `api` &rarr; `operation`/`resolve` &rarr;
`model`/`log`/`witness` &rarr; `crypto`, with `Signer`/`Verifier` highlighted
as the extension points a host application implements.

### Regenerate after editing

`plantuml` is installed locally (Homebrew, pulls in `graphviz` as a
dependency). From `didwebvh-java/`:

```bash
plantuml -tpng docs/diagrams/architecture-overview.puml   # -> .png
plantuml -tsvg docs/diagrams/architecture-overview.puml   # -> .svg
plantuml -tpdf docs/diagrams/architecture-overview.puml   # -> .pdf (for thesis embedding)
```

Output is written next to the `.puml` source under the same filename.

### Live preview while editing

Install the **PlantUML** VS Code extension (`jebbs.plantuml`), open the
`.puml` file, and press `Alt+D` (`Option+D` on Mac) for a live-updating
preview. It uses the local `plantuml`/Java install automatically.

### Editing

Plain PlantUML syntax — packages are `package "name" { class Foo }` blocks,
relationships are `A --> B : label`. Prefer the `.svg` output for embedding
in the thesis (vector, scales without blur at any print size).
