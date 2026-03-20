# Antrag für die Abschlussarbeit

**Titel (Deutsch):**
> Implementierung und Bedrohungsmodellierung der did:webvh-Method

**Title (English):**
> Implementation and Threat Modeling of the did:webvh-Method

---

## 1. Motivation

### 1.1 Einordnung

Die Arbeit ist im Themenbereich der digitalen Identität angesiedelt, konkret im Umfeld des W3C-Standards für Decentralized Identifiers (DIDs). DIDs ermöglichen es, digitale Identitäten unabhängig von zentralen Autoritäten wie Zertifizierungsstellen oder Plattformbetreibern zu erstellen, zu verwalten und zu verifizieren. Dieses Konzept ist unter dem Begriff Self-Sovereign Identity (SSI) bekannt.

Innerhalb dieses Ökosystems befasst sich die Arbeit speziell mit der DID-Methode `did:webvh` (did:web + Verifiable History), die auf bestehender Web-Infrastruktur aufbaut und diese um kryptografisch gesichertes, manipulationsresistentes Log-Chaining erweitert. Damit verknüpft die Arbeit Konzepte aus angewandter Kryptografie (Hash-Verkettung, digitale Signaturen), Web-Technologien sowie der praktischen Implementierung sicherheitskritischer Protokolle.

`did:web` ist heute Standard für DID-basierte Identitäten in der Praxis, obwohl die Methode fundamentale Sicherheitslücken aufweist: Es gibt keine Versionshistorie und keine kryptografische Bindung zwischen DID-Dokument-Versionen. Ein kompromittierter Server kann Identitäten unbemerkt manipulieren. `did:webvh` adressiert diese Schwächen durch Hash-Verkettung, bindende Update-Keys und Data Integrity Proofs.

Der konzeptionelle Vorteil eines DID-Layers gegenüber konventioneller X.509-PKI liegt in der Entkopplung von Identifikator und Schlüsselmaterial. In der klassischen PKI ist eine Identität direkt an einen öffentlichen Schlüssel gebunden; wechselt der Schlüssel, muss eine CA ein neues Zertifikat ausstellen. Ein DID hingegen ist ein persistenter Identifikator, der auf ein DID-Dokument mit dem aktuell gültigen Schlüssel verweist. Schlüssel können so rotiert werden, ohne die Identität zu ändern oder eine zentrale Instanz einzubeziehen. Vertrauen entsteht dabei nicht durch hierarchische Delegation an eine CA, sondern kryptografisch, etwa durch Hash-Verkettung wie bei `did:webvh`.

### 1.2 (Vorläufige) Forschungsfrage

Welche Bedrohungsklassen adressiert `did:webvh` gegenüber `did:web`, welche bleiben trotz kryptografischer Schutzmechanismen bestehen, und wo liegen die Grenzen dieser Garantien bei Schlüsselkompromittierung und fehlerhafter Implementierung?

### 1.3 Problem und Zielsetzung

Ziel dieser Arbeit ist eine systematische Sicherheitsanalyse von `did:webvh` anhand des STRIDE-Modells, einem etablierten Framework zur strukturierten Bedrohungsanalyse: Welche Bedrohungsklassen werden durch die von `did:webvh` eingeführten Mechanismen adressiert, welche verbleiben? Der Fokus liegt auf Key Rotation und Schlüsselkompromittierung, da diese Szenarien exemplarisch zeigen, wo die Sicherheitsgarantien des Standards enden und operative Verantwortung des Betreibers beginnt.

---

## 2. (Wissenschaftliches) Vorgehen

### 2.1 Ansatz

did:webvh ist ein junger Standard, der in der wissenschaftlichen Literatur bisher vor allem im Kontext von DID-Methodenvergleich als Randthema behandelt wird. Eine dedizierte Sicherheitsanalyse existiert nach aktuellem Kenntnisstand nicht. Diese Arbeit adressiert diese Lücke und stützt sich dabei auf die W3C/DIF-Spezifikation als primäre Quelle, ergänzt durch Literatur zu DID-Sicherheit, DID-Methodenvergleichen und Bedrohungsmodellierungen. Die bestehenden Referenzimplementierungen in TypeScript und Python dienen zusätzlich als inhaltliche Referenz für die praktische Umsetzung des Standards in Java.

Als methodischer Ansatz für die Sicherheitsanalyse wird STRIDE eingesetzt, da dieses Framework einen strukturierten, kategorisierten Vergleich der Sicherheitseigenschaften von `did:web` und `did:webvh` ermöglicht. Alternative DID-Methoden, etwa blockchain-basierte oder zustandslose Ansätze, lösen das Problem der manipulationsresistenten DID grundlegend anders und werden im Rahmen der Einordnung vergleichend betrachtet, jedoch nicht implementiert.

**KERI (Key Event Receipt Infrastructure)** ist ein besonders aufschlussreiches Vergleichsobjekt, weil es dasselbe Problem unabhängig und auf ähnliche Weise löst: selbst-zertifizierende Identifikatoren, ein hash-verkettetes Key Event Log und Pre-Rotation. Ein Vergleich beider Ansätze schärft den Blick dafür, wo did:webvh KERI-äquivalente Garantien bietet und wo die Bindung an Web-Infrastruktur möglicherweise weitere Angriffsflächen bietet.

### 2.2 Praktische Umsetzung

Im Praxisprojekt wird eine Java-Bibliothek entwickelt, die die did:webvh-Spezifikation implementiert und als eigenständiges Package in Java-basierte SSI-Systeme integriert werden kann. Eine Java-Implementierung existiert bisher nicht; die Bibliothek soll wesentliche Aspekte (CRUD) des Standards abdecken.

Die daraus gewonnenen Erkenntnisse über das Protokoll fließen direkt in die Bachelorarbeit ein, deren Kern eine Sicherheitsanalyse anhand des STRIDE-Modells bildet. Das Ergebnis ist eine strukturierte Analyse, die aufzeigt, welche Bedrohungsklassen `did:webvh` gegenüber `did:web` adressiert und wo die Grenzen der technischen Sicherheitsgarantien liegen, vor allem bei webbasierten DIDs.
