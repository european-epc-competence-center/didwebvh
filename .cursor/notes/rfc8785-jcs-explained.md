# RFC 8785 — JSON Canonicalization Scheme (JCS) Explained

---

## Part 1 — Why does JCS even exist?

Imagine you want to sign a JSON document with a private key so that anyone with
your public key can verify that you — and only you — produced it. The fundamental
rule of any signature scheme is:

> **The bytes you sign must be the exact same bytes the verifier reconstructs.**

JSON is a text format, and the same *logical* data can be written in infinitely
many byte sequences that all mean the same thing:

```json
{"b":2,"a":1}
{"a":1,"b":2}
{ "a" : 1, "b" : 2 }
{"a":1.0,"b":2.0}
```

All four mean "object with `a=1` and `b=2`". But if you hash the first one and
the verifier hashes the second one, the hashes are completely different and the
signature check fails — even though nothing was tampered with.

**JCS solves this.** It defines a single, deterministic transformation that turns
any valid JSON into a canonical byte sequence. Same logical data → always the
exact same bytes → always the same hash → signatures work reliably.

---

## Part 2 — What JCS does (the four rules)

RFC 8785 specifies exactly four transformations to apply in sequence:

### Rule 1: No whitespace

Remove all whitespace that is not inside a string value:

```
{ "a" : 1 }   →   {"a":1}
```

Trivial. Every JSON serializer can do this in compact mode.

### Rule 2: Serialize strings with specific escaping

This is where JSON parsers often differ subtly. JCS mandates ECMAScript's
`JSON.stringify()` escaping rules:

| Character | How to serialize |
|---|---|
| U+0000–U+001F (control chars) | `\uXXXX` (lowercase hex) |
| U+0008 (`\b`) | `\b` |
| U+0009 (`\t`) | `\t` |
| U+000A (`\n`) | `\n` |
| U+000C (`\f`) | `\f` |
| U+000D (`\r`) | `\r` |
| U+0022 (`"`) | `\"` |
| U+005C (`\`) | `\\` |
| Everything else | as-is (UTF-8 bytes) |

Example: the euro sign € (U+20AC) is output as-is: the 3 UTF-8 bytes `e2 82 ac`.
It is **not** escaped as `\u20ac`. You can confirm this in the RFC's hex dump.

Jackson's default serializer already follows these rules exactly. No special
configuration needed.

### Rule 3: Serialize numbers in ECMAScript format

This is the **hard part** and the reason JCS libraries exist.

JSON number data is parsed into IEEE 754 double-precision floating-point values
(64-bit doubles). When you serialize a double back to text, you need a rule for
how many decimal digits to use.

#### The naive approach fails

A naive implementation might use Java's `Double.toString()` or `String.format()`.
But these produce different output than ECMAScript in edge cases:

| Value | Java `Double.toString()` | ECMAScript / JCS |
|---|---|---|
| `1e30` | `1.0E30` | `1e+30` |
| `4.5` | `4.5` | `4.5` ✓ same |
| `0.002` | `0.002` | `0.002` ✓ same |
| `333333333.33333329` | `3.3333333333333328E8` | `333333333.3333333` |
| `1.0` | `1.0` | `1` (no `.0`) |
| `-0.0` | `-0.0` | `0` (minus zero becomes positive) |

The differences are subtle but they break signatures. ECMAScript uses the
**"shortest round-trip representation"** algorithm — the shortest decimal string
that uniquely identifies this specific IEEE 754 bit pattern. This algorithm is
called Grisu3/Ryu and is **non-trivial to implement correctly**.

The RFC explicitly references Google's V8 engine and the Ryu algorithm as
reference implementations for this part. That is why the erdtman Java library
exists and why it includes `NumberToJSON.java` — a full Java port of this
algorithm.

#### But for did:webvh, this does not matter

All numbers in a did:webvh log entry are small integers:
- `ttl: 3600` — the cache TTL
- Version numbers: `1`, `2`, `3`, …
- Witness threshold: `2` or similar
- `true`, `false`, `null` — not numbers

For integers in the range `-(2^53)` to `2^53`, Java and ECMAScript produce
identical output:
- `3600` → `"3600"` (Jackson calls `IntNode.numberValue()`, which outputs no
  decimal point)
- There is no rounding, no exponent, no edge case

Jackson's `IntNode` and `LongNode` serialize integers without a decimal point,
which is the correct ECMAScript behavior for integer values. The edge cases only
matter for values like `1e308`, `-0.0`, or `333333333.33333329` — none of which
appear in did:webvh.

**Conclusion:** Jackson's default number serialization is JCS-correct for all
values used by this spec. The ES2019 edge cases are a documented known limitation
of our `JcsCanonicalizer`, not a practical bug.

### Rule 4: Sort object keys by UTF-16 code unit order

Object keys (property names) must be sorted. But sorted *how*?

JCS mandates sorting by **UTF-16 code unit values**, not by UTF-8 byte values and
not by Unicode codepoint values (which are the same for BMP characters but
diverge for surrogate pairs).

Why UTF-16? Because JSON, ECMAScript, Java, and .NET all use UTF-16 internally
for strings. The sort order is defined as: compare strings character-by-character
where each `char` is treated as an unsigned 16-bit integer. This is exactly what
Java's `String.compareTo()` does.

Example from the RFC — this input:
```json
{
  "\u20ac": "Euro Sign",
  "\r":     "Carriage Return",
  "\ufb33": "Hebrew Dalet With Dagesh",
  "1":      "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}
```

Expected sort order of values after JCS:
```
"Carriage Return"        (key = U+000D = 13)
"One"                    (key = U+0031 = 49)
"Control"                (key = U+0080 = 128)
"Latin Small..."         (key = U+00F6 = 246)
"Euro Sign"              (key = U+20AC = 8364)
"Emoji: Grinning Face"   (key = U+D83D U+DE00 = surrogate pair, sorts by first unit 55357)
"Hebrew Dalet..."        (key = U+FB33 = 64307)
```

**`TreeMap<String, V>` in Java uses `String.compareTo()` which is UTF-16
code-unit comparison. This is exactly RFC 8785 §3.2.3.** No custom comparator
needed.

Note: for all-ASCII property names (which is 99.9% of real JSON), UTF-8, UTF-16,
and Unicode codepoint order are identical. The exotic sort order only matters for
Unicode property names.

---

## Part 3 — Sorting must be recursive

The sorting is applied at **every level** of nesting:
- Sort the top-level object's keys
- For each value that is itself an object → sort its keys too
- For each array element that is an object → sort its keys too
- Arrays themselves: do NOT change element order

```json
Input:
{"z": {"y": 2, "x": 1}, "a": [{"c": 3, "b": 2}]}

Output (sorted recursively):
{"a":[{"b":2,"c":3}],"z":{"x":1,"y":2}}
```

---

## Part 4 — Final output is UTF-8

After all transformations, the result is encoded in UTF-8. Since Java strings are
UTF-16 internally, `String.getBytes(StandardCharsets.UTF_8)` or Jackson's
`writeValueAsBytes()` with default settings handles this correctly.

---

## Part 5 — Our implementation: delegate to the RFC reference library

The implementation in `JcsCanonicalizer.java` is a thin delegation to the
erdtman library (`io.github.erdtman:java-json-canonicalization:1.1`), which is
the RFC's own reference Java implementation (listed in RFC Appendix G,
co-authored by RFC author Anders Rundgren):

```java
public static byte[] canonicalize(JsonNode node) {
    String json = MAPPER.writeValueAsString(node); // Jackson: JsonNode → JSON string
    return new JsonCanonicalizer(json).getEncodedUTF8(); // RFC reference impl: canonical bytes
}
```

Jackson handles the `JsonNode` → string step (it correctly escapes strings and
serializes numbers). The erdtman library then performs the full RFC 8785
canonicalization: key sorting, ES2019 number normalization, and UTF-8 output.

| What JCS needs | Who provides it |
|---|---|
| No whitespace | erdtman library |
| Correct string escaping | erdtman library (ECMAScript rules) |
| Integer serialization | erdtman library |
| Float serialization (ES2019, Ryu) | erdtman library (`NumberToJSON.java`) |
| UTF-16 key sorting | erdtman library (`TreeMap`) |
| UTF-8 output | erdtman library |
| `JsonNode` → string bridge | Jackson (`MAPPER.writeValueAsString`) |

---

---

## Summary

| Rule | Implementation | Complexity |
|---|---|---|
| No whitespace | erdtman library | Trivial |
| String escaping | erdtman library (ECMAScript rules) | Trivial |
| Number format — integers | erdtman library | Trivial |
| Number format — floats (ES2019) | erdtman `NumberToJSON.java` (Ryu port) | **Hard** |
| Key sorting (UTF-16) | erdtman library (`TreeMap`) | Easy |
| UTF-8 output | erdtman library | Trivial |
| `JsonNode` bridge | Jackson `writeValueAsString` | Trivial |

**JCS is not simple in the general case.** The number serialization rule alone
requires the Ryu algorithm. Using `io.github.erdtman:java-json-canonicalization:1.1`
(RFC Appendix G reference implementation, zero transitive deps) is the correct
choice — it handles all of this and is directly endorsed by the RFC.
