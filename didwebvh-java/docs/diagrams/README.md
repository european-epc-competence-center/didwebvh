# Architecture Diagrams

## architecture-overview.puml

A curated (hand-written, not auto-generated) package-level view of the
principal packages and the direction of control through the library — the
same diagram (and abstraction level) as Figure 3.1 in the thesis, redrawn
here as PlantUML so it can be regenerated whenever the package structure
changes. It tracks control flow rather than every import and leaves out the
`util`/`exception` packages and the shared types in the root package.

Control runs from the `api` facade (and `didweb`, which sits outside the
core resolution path) down through `operation`/`resolve`, then `log`/
`witness`, onto the shared `model`/`crypto` base. `operation`, `log`, and
`witness` each use both `model` and `crypto` the same way, so each points at
that shared group with a single arrow instead of drawing all 6 individual
edges. `LogFetcher`, `Verifier`, and `Signer` are the host-provided
extension points (dashed boxes, dashed arrows) that cross the `library`/
`host` boundary — the same boundary Chapter 4 (Security Analysis) treats as
the trust boundary.

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

A PlantUML *component* diagram, not a class diagram: each package is a
single `component "name" as alias` box (no class members), grouped into
`package "library" { ... }` / `package "host" { ... }` boundaries, with
`A --> B` for "uses" and `A ..> B` for the dashed host-plugin edges. There
are deliberately no arrow labels or notes, matching the minimal style of the
thesis figure it substitutes — the prose/caption carries that context
instead. `skinparam linetype ortho` keeps every edge an axis-aligned bend
(no diagonals, no stray curves); the `-[hidden]->` edges exist purely to
pin node ranks/columns for a crossing-free layout and carry no semantic
meaning. Prefer the `.svg` (or `.pdf`) output for embedding in the thesis
(vector, scales without blur at any print size).
