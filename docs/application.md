# Antrag für die Abschlussarbeit

**Geplantes Thema / Titel:**

> Eine Sicherheitsanalyse von did:webvh

---

## 1. Motivation

### 1.1 Einordnung

> _In welchem generellen Themenbereich befindet sich die Arbeit?_

Die Arbeit ist im Themenbereich der digitalen Identität angesiedelt, konkret im Umfeld des W3C-Standards für Decentralized Identifiers (DIDs). DIDs ermöglichen es, digitale Identitäten unabhängig von zentralen Autoritäten wie Zertifizierungsstellen oder Plattformbetreibern zu erstellen, zu verwalten und zu verifizieren. Dieses Konzept ist unter dem Begriff Self-sovereign Identity (SSI) bekannt. 

Innerhalb dieses Ökosystems befasst sich die Arbeit speziell mit der DID-Methode `did:webvh` (did:web + Verifiable History), die auf bestehender Web-Infrastruktur aufbaut und diese um kryptografisch gesichertes, manipulationsresistentes Log-Chaining erweitert. Damit verknüpft die Arbeit Konzepte aus dem Bereich angewandte Kryptografie (Hash-Verkettung, digitale Signaturen), Web-Technologien sowie der praktischen Implementierung sicherheitskritischer Protokolle.
&nbsp;

### 1.2 (Vorläufige) Forschungsfrage

> _Welche konkrete Fragestellung soll beantwortet werden? Was ist das Kernstück der Arbeit?_

Welche Sicherheitseigenschaften adressiert `did:webvh` gegenüber `did:web`, und welche Bedrohungsszenarien bleiben trotz der kryptografischen Schutzmechanismen bestehen?
&nbsp;


### 1.3 Problem und Zielsetzung

> _Welches Problem soll mit der Arbeit gelöst werden? Welches Ziel wird damit verfolgt?_

`did:web` ist heute Standard für DID-basierte Identitäten in der Praxis, obwohl die Methode fundamentale Sicherheitslücken aufweist: Es gibt keine Versionshistorie und keine kryptografische Bindung zwischen DID-Dokument-Versionen. Ein kompromittierter Server kann Identitäten unbemerkt manipulieren. `did:webvh` adressiert diese Schwächen durch Hash-Verkettung, bindende Update-Keys und Data Integrity Proofs.

Ziel dieser Arbeit ist eine systematische Sicherheitsanalyse von `did:webvh` anhand des STRIDE-Modells, einem etablierten Framework zur strukturierten Bedrohungsanalyse: Welche Bedrohungsklassen werden durch die von `did:webvh` eingeführten Mechanismen adressiert, welche verbleiben? Der Fokus liegt auf Key Rotation und Schlüsselkompromittierung, da diese Szenarien exemplarisch zeigen, wo die Sicherheitsgarantien des Standards enden und operative Verantwortung des Betreibers beginnt.
&nbsp;

---

## 2. (Wissenschaftliches) Vorgehen

### 2.1 Ansatz

> _Gibt es schon Lösungen zu dem Problem, die wiederverwendet werden sollen, oder ist die Fragestellung neu? Gibt es ähnliche Probleme, für die es bereits Lösungen gibt? Wie könnte ein möglicher Lösungsansatz aussehen? Gibt es Alternativen?_

Da `did:webvh` ein noch junger Standard ist, ist die wissenschaftliche Auseinandersetzung damit bisher begrenzt. Die Arbeit stützt sich daher primär auf die Spezifikation selbst sowie auf etablierte Literatur zu DID-Sicherheit und Bedrohungsmodellierung. Ergänzend werden die bestehenden Referenzimplementierungen in TypeScript und Python als inhaltliche Referenz herangezogen.

Als methodischer Ansatz für die Sicherheitsanalyse wird STRIDE eingesetzt, da dieses Framework einen strukturierten, kategorisierten Vergleich der Sicherheitseigenschaften von `did:web` und `did:webvh` ermöglicht. Alternative DID-Methoden, etwa blockchain-basierte oder zustandslose Ansätze, lösen das Problem der manipulationsresistenten DID grundlegend anders und werden im Rahmen der Einordnung vergleichend betrachtet, jedoch nicht implementiert.
&nbsp;

### 2.2 Praktische Umsetzung

> _Soll ein existierender Lösungsansatz genommen werden oder eine neue Lösung entwickelt werden? Worum handelt es sich bei der Lösung — ein Prototyp, ein neues Protokoll, eine Messung, eine Analyse, eine Simulation?_

Im Praxisprojekt wird eine Java-Bibliothek entwickelt, die die `did:webvh`-Spezifikation implementiert und als eigenständiges Package in Java-basierte SSI-Systeme integriert werden kann. Eine Java-Implementierung existiert bisher nicht; die Bibliothek soll wesentliche Aspekte des Standards abdecken, insbesondere Log-Chaining, Key Rotation und die Verifikation von Data Integrity Proofs.

Die daraus gewonnenen Erkenntnisse über das Protokoll fließen direkt in die Bachelorarbeit ein, deren Kern eine Sicherheitsanalyse anhand des STRIDE-Modells bildet. Das Ergebnis ist eine strukturierte Analyse, die aufzeigt, welche Bedrohungsklassen `did:webvh` gegenüber `did:web` adressiert und wo die Grenzen der technischen Sicherheitsgarantien liegen.
&nbsp;