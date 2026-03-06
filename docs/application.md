# Antrag für die Abschlussarbeit

**Geplantes Thema / Titel:**

> Eine Sicherheitsanalyse von did:webvh

---

## 1. Motivation

### 1.1 Einordnung

> _In welchem generellen Themenbereich befindet sich die Arbeit?_

Die Arbeit ist im Themenbereich der digitalen Identität angesiedelt, konkret im Umfeld des W3C-Standards für Decentralized Identifiers (DIDs). DIDs ermöglichen es, digitale Identitäten unabhängig von zentralen Autoritäten wie Zertifizierungsstellen oder Plattformbetreibern zu erstellen, zu verwalten und zu verifizieren. Dieses Konzept ist unter dem Begriff Self-sovereign Identity (SSI) bekannt. 

Innerhalb dieses Ökosystems befasst sich die Arbeit speziell mit der DID-Methode `did:webvh` (did:web + Verifiable History), die auf bestehender Web-Infrastruktur aufbaut und diese um kryptografisch gesichertes, manipulationsresistentes Log-Chaining erweitert. Damit verknüpft die Arbeit Konzepte aus dem Bereich angewandte Kryptografie (Hash-Verkettung, digitale Signaturen), Web-Technologien sowie der praktischen Implementierung sicherheitskritischer Protokolle.

`did:web` ist heute Standard für DID-basierte Identitäten in der Praxis, obwohl die Methode fundamentale Sicherheitslücken aufweist: Es gibt keine Versionshistorie und keine kryptografische Bindung zwischen DID-Dokument-Versionen. Ein kompromittierter Server kann Identitäten unbemerkt manipulieren. `did:webvh` adressiert diese Schwächen durch Hash-Verkettung, bindende Update-Keys und Data Integrity Proofs.

Der konzeptionelle Vorteil eines DID-Layers gegenüber konventioneller X.509-PKI liegt in der Entkopplung von Identifikator und kryptografischem Schlüsselmaterial. In der klassischen PKI ist ein Zertifikat direkt an einen öffentlichen Schlüssel gebunden; bei einer Schlüsselkompromittierung muss das gesamte Zertifikat widerrufen und neu ausgestellt werden, was eine vertrauenswürdige Zertifizierungsstelle (CA) als zentrale Instanz voraussetzt. DIDs hingegen führen eine Indirektionsschicht ein: Der DID als persistenter Identifikator verweist auf ein DID-Dokument, das den aktuell gültigen öffentlichen Schlüssel enthält. Schlüssel können damit rotiert werden, ohne den Identifikator selbst zu ändern oder eine CA einzubeziehen. Die Vertrauensverankerung erfolgt kryptografisch — etwa durch Hash-Verkettung wie bei `did:webvh` — statt durch hierarchische Delegation an eine zentrale Autorität. Dies beseitigt den Single Point of Trust der CA-Hierarchie und macht Identitäten robuster gegenüber CA-Kompromittierungen, Zertifikatsfälschungen und Missbrauch durch Intermediäre.

### 1.2 (Vorläufige) Forschungsfrage

> _Welche konkrete Fragestellung soll beantwortet werden? Was ist das Kernstück der Arbeit?_

Welche Sicherheitseigenschaften adressiert `did:webvh` gegenüber `did:web`, und welche Bedrohungsszenarien bleiben trotz der kryptografischen Schutzmechanismen bestehen?

Welche Sicherheitsgarantien bietet `did:webvh` im Fall einer Schlüsselkompromittierung, und unter welchen Bedingungen kann ein Angreifer trotz kryptografischer Schutzmechanismen die Identität dauerhaft übernehmen?

Welche Sicherheitseigenschaften von `did:webvh` sind in der Praxis schwer korrekt zu implementieren, und welche Implementierungsfehler führen zu welchen Bedrohungsszenarien?


### 1.3 Problem und Zielsetzung

> _Welches Problem soll mit der Arbeit gelöst werden? Welches Ziel wird damit verfolgt?_

Ziel dieser Arbeit ist eine systematische Sicherheitsanalyse von `did:webvh` anhand des STRIDE-Modells, einem etablierten Framework zur strukturierten Bedrohungsanalyse: Welche Bedrohungsklassen werden durch die von `did:webvh` eingeführten Mechanismen adressiert, welche verbleiben? Der Fokus liegt auf Key Rotation und Schlüsselkompromittierung, da diese Szenarien exemplarisch zeigen, wo die Sicherheitsgarantien des Standards enden und operative Verantwortung des Betreibers beginnt.

---

## 2. (Wissenschaftliches) Vorgehen

### 2.1 Ansatz

> _Gibt es schon Lösungen zu dem Problem, die wiederverwendet werden sollen, oder ist die Fragestellung neu? Gibt es ähnliche Probleme, für die es bereits Lösungen gibt? Wie könnte ein möglicher Lösungsansatz aussehen? Gibt es Alternativen?_

Da `did:webvh` ein noch junger Standard ist, ist die wissenschaftliche Auseinandersetzung damit bisher begrenzt. Die Arbeit stützt sich daher primär auf die Spezifikation selbst sowie auf etablierte Literatur zu DID-Sicherheit und Bedrohungsmodellierung. Ergänzend werden die bestehenden Referenzimplementierungen in TypeScript und Python als inhaltliche Referenz herangezogen.

Als methodischer Ansatz für die Sicherheitsanalyse wird STRIDE eingesetzt, da dieses Framework einen strukturierten, kategorisierten Vergleich der Sicherheitseigenschaften von `did:web` und `did:webvh` ermöglicht. Alternative DID-Methoden, etwa blockchain-basierte oder zustandslose Ansätze, lösen das Problem der manipulationsresistenten DID grundlegend anders und werden im Rahmen der Einordnung vergleichend betrachtet, jedoch nicht implementiert.

Ein besonders relevantes Vergleichsobjekt stellt **KERI (Key Event Receipt Infrastructure)** dar. KERI ist ein dezentrales Public-Key-Infrastruktur-Protokoll, das auf selbst-zertifizierenden Identifikatoren (Autonomic Identifiers, AIDs) und einem hash-verketteten Key Event Log (KEL) basiert. Die Sicherheitsmechanismen von `did:webvh` – insbesondere das Log-Chaining, die SCID-Ableitung und das Pre-Rotation-Schema (`nextKeyHashes`) – konvergieren unabhängig auf zentrale Designprinzipien von KERI. Ein Vergleich beider Ansätze ermöglicht es, die formalen Sicherheitsgarantien von `did:webvh` präziser einzuordnen: Wo übernimmt `did:webvh` KERI-äquivalente Garantien, und wo führt die Bindung an Web-Infrastruktur (DNS, HTTPS, Server-Trust) neue Angriffsflächen ein, die in KERI durch infrastrukturunabhängige Verifikation vermieden werden?

### 2.2 Praktische Umsetzung

> _Soll ein existierender Lösungsansatz genommen werden oder eine neue Lösung entwickelt werden? Worum handelt es sich bei der Lösung — ein Prototyp, ein neues Protokoll, eine Messung, eine Analyse, eine Simulation?_

Im Praxisprojekt wird eine Java-Bibliothek entwickelt, die die `did:webvh`-Spezifikation implementiert und als eigenständiges Package in Java-basierte SSI-Systeme integriert werden kann. Eine Java-Implementierung existiert bisher nicht; die Bibliothek soll wesentliche Aspekte des Standards abdecken, insbesondere Log-Chaining, Key Rotation und die Verifikation von Data Integrity Proofs.

Die daraus gewonnenen Erkenntnisse über das Protokoll fließen direkt in die Bachelorarbeit ein, deren Kern eine Sicherheitsanalyse anhand des STRIDE-Modells bildet. Das Ergebnis ist eine strukturierte Analyse, die aufzeigt, welche Bedrohungsklassen `did:webvh` gegenüber `did:web` adressiert und wo die Grenzen der technischen Sicherheitsgarantien liegen.