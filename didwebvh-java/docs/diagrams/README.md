# Architecture Diagrams

## architecture-overview.puml

A curated (hand-written, not auto-generated) package-level view of the
principal packages and the direction of control through the library — the
same diagram (and abstraction level) as Figure 3.1 in the thesis, redrawn
here as PlantUML so it can be regenerated whenever the package structure
changes. It tracks control flow rather than every import and leaves out the
`util`/`exception` packages and the shared types in the root package.

Control runs from the `api` facade down through `operation`/`resolve`, then
`log`/`witness`, onto the shared `model`/`crypto` base. `operation`, `log`,
and `witness` each use both `model` and `crypto` the same way, so each
points at that shared group with a single arrow instead of drawing all 6
individual edges. `LogFetcher`, `Verifier`, and `Signer` are the
host-provided extension points (dashed boxes, dashed arrows) that cross the
`library`/`host` boundary — the same boundary Chapter 4 (Security Analysis)
treats as the trust boundary. Each interface box carries a small sub-label
stating whether it ships a built-in default: `LogFetcher` (an
`HttpClient`-backed fetcher) and `Verifier` (`DefaultVerifier`, for
`eddsa-jcs-2022`) both do; `Signer` does not, since a private key can only
come from the host.

`didweb` is intentionally left out. It only reaches into `resolve` for two
small string-utility helpers (`DidUrlTransformer`, `ImplicitServiceInjector`),
not the resolution machinery (`HttpResolver`/`LogBasedResolver`/`LogFetcher`)
that the `resolve` box actually represents in this diagram, so a
`didweb --> resolve` edge would overstate the coupling at this abstraction
level. (`DidWebImporter`, the other class in that package, doesn't touch
`resolve` at all.)

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
are deliberately no arrow labels, matching the minimal style of the thesis
figure it substitutes — the prose/caption carries that context instead. The
one exception is the small `<size:9>...</size>` sub-label baked into each
host interface's own name (not a separate note element), stating whether it
has a built-in default; keep that distinction in mind if you ever add more
annotations — a floating `note ... end note` attached to the whole `host`
package was tried first and rejected because it reordered the unrelated
`library` layout as a side effect (PlantUML/Graphviz add invisible
connector edges for notes, which perturb ranking elsewhere in the graph).
`skinparam linetype ortho` keeps every edge an axis-aligned bend (no
diagonals, no stray curves).

Two Graphviz quirks to know about if you touch the layout:

- The `resolve -[hidden]-> operation` edge exists purely to pull `operation`
  onto the same rank as `log`/`witness` (so its edge into `base` is a short
  vertical drop instead of a multi-rank-spanning line); it carries no
  semantic meaning.
- The declaration order of `witness --> base`, `log --> base`,
  `operation --> base` is significant: with 3 edges converging on the same
  cluster, Graphviz assigns boundary "ports" by declaration order, not by
  the source's actual on-screen position. The current order is the one that
  keeps every arrow a straight drop under its source — reordering those
  three lines (or adding more hidden edges anchored to `base`) can silently
  make one of them detour sideways before entering the box. Always eyeball
  the rendered output after editing anything near that block.

Prefer the `.svg` (or `.pdf`) output for embedding in the thesis (vector,
scales without blur at any print size).
