# c3p0 JavaBean deserialization composition boundary

Source: hourly offensive-security scan, [GHSA-w6w4-rjh9-9r58 / CVE-2026-55223](https://github.com/advisories/GHSA-w6w4-rjh9-9r58).

The operator lesson is a classpath-composition check, not a standalone c3p0 exploit: JavaBeans introspection can expose JDBC `getConnection()` and `getPooledConnection()` methods as apparently safe properties. A deserialization carrier that automatically reads bean properties can then invoke a c3p0 `DataSource`, which crosses into a JDBC driver and its connection-string behavior.

!!! warning "Authorized validation only"
    Use a disposable JVM, a marker-only `DataSource` or mock JDBC driver, and synthetic serialized objects. Do not connect to production databases, invoke JNDI/LDAP/RMI endpoints, load remote classes, execute commands, or deserialize a weaponized gadget stream in a deployed service.

## Preconditions

All parts of the composition must be present and reachable:

1. `com.mchange:c3p0 < 0.14.0` supplies an introspectable `DataSource` or `ConnectionPoolDataSource`;
2. a bean-property consumer or deserialization carrier automatically reads selected JavaBean properties;
3. untrusted serialized data reaches that carrier;
4. a compatible JDBC driver is on the effective runtime classpath; and
5. the carrier can select `connection` or `pooledConnection` on the supplied object.

The advisory calls out Apache Commons BeanUtils comparators combined with a sorting collection as a common carrier pattern, but package presence alone proves none of the required reachability. Java 16+ reflective-access restrictions may also break some compositions; record the actual runtime result.

## Recon workflow

### 1. Inventory the effective classpath

In an authorized source tree or application bundle:

```bash
mvn dependency:tree -Dincludes=com.mchange:c3p0,commons-beanutils:commons-beanutils
./gradlew dependencies --configuration runtimeClasspath
find . -type f \( -name 'c3p0-*.jar' -o -name 'commons-beanutils-*.jar' -o -name '*jdbc*.jar' \) -print
```

Record:

- exact c3p0 version and whether it is loaded at runtime;
- bean-property libraries and comparator implementations;
- JDBC drivers and versions;
- Java major version and module/reflective-access flags; and
- every application deserialization entry point.

Search only source or approved decompiled bundles for relevant sinks:

```text
ObjectInputStream.readObject
XMLDecoder.readObject
BeanComparator
PropertyUtils.getProperty
PropertyDescriptor.getReadMethod
DataSource.getConnection
ConnectionPoolDataSource.getPooledConnection
```

Do not conclude exploitability from a dependency scanner result. Show how attacker bytes reach object construction and how that object reaches property lookup.

### 2. Enumerate the bean surface without deserializing

Use `java.beans.Introspector` in a local harness to list property descriptors for the exact c3p0 classes loaded by the target. Compare an affected build with `0.14.0+`.

Candidate classes include:

```text
com.mchange.v2.c3p0.DriverManagerDataSource
com.mchange.v2.c3p0.PoolBackedDataSource
com.mchange.v2.c3p0.ComboPooledDataSource
com.mchange.v2.c3p0.WrapperConnectionPoolDataSource
com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource
com.mchange.v2.c3p0.JndiRefForwardingDataSource
```

Capture only descriptor names, property types, and read-method names. The expected affected signal is a descriptor named `connection` or `pooledConnection` whose read method maps to the JDBC acquisition method. The fixed release ships explicit `BeanInfo` classes that exclude those property names and the corresponding `Connection`/`PooledConnection` property types.

This test is safe because it proves the introspection boundary without constructing a serialized carrier or contacting a database.

## Marker-only composition replay

If the assessment requires dynamic proof, reproduce the application's exact property consumer in a disposable test JVM. Substitute a marker-only `DataSource` or mock JDBC driver whose connection method increments an in-memory counter and throws a synthetic exception. It must not open a socket, resolve a hostname, consult JNDI, read a file, or execute a process.

Use this decision table:

| Case | c3p0 / property input | Expected observation |
| --- | --- | --- |
| descriptor baseline | affected c3p0, ordinary safe property | selected getter only |
| risky property | affected c3p0, `connection` or `pooledConnection` | marker counter increments if the bean consumer invokes it |
| absent-carrier control | c3p0 present, no automatic property lookup | counter unchanged |
| absent-sink control | carrier present, no c3p0/JDBC object | counter unchanged |
| fixed control | c3p0 `0.14.0+`, same lookup | risky descriptor unavailable; counter unchanged |
| runtime control | target Java major/options | exact reflective-access success or failure recorded |

Only after this marker proof should an operator test the deserialization entry point, and only when explicitly authorized. Use a synthetic carrier containing the marker object and stop at the counter or synthetic exception. Do not substitute public weaponized gadget chains: they add uncontrolled JDBC/JNDI/network behavior and are unnecessary to establish composition reachability.

The proof chain should be explicit:

```text
attacker-controlled serialized bytes
  -> reachable deserializer
  -> carrier performs JavaBean property lookup
  -> c3p0 connection property selected
  -> marker DataSource getter invoked
```

If any edge is inferred rather than observed, label it as unconfirmed.

## Evidence and reporting

Capture:

- dependency tree and effective runtime JAR hashes;
- Java version and relevant runtime flags;
- deserialization source and carrier/property-selection path;
- affected `Introspector` descriptor output;
- marker counter or synthetic stack trace;
- absent-carrier and absent-sink controls; and
- c3p0 `0.14.0+` comparison.

Use bounded wording:

- "c3p0 exposes a connection getter as a JavaBean property to the reachable carrier," not "c3p0 alone is RCE";
- "synthetic deserialization invoked the marker getter," not "the production JDBC driver is exploitable"; and
- "the classpath contains the required components but deserialization reachability is unconfirmed" when only static evidence exists.

## Sources

- [GitHub Advisory Database: GHSA-w6w4-rjh9-9r58 / CVE-2026-55223](https://github.com/advisories/GHSA-w6w4-rjh9-9r58)
- [c3p0 explicit BeanInfo fix](https://github.com/swaldman/c3p0/commit/7b022c4b6694dabc6204254dc917af9c38f2cb27)
- [c3p0 0.14.0 release](https://github.com/swaldman/c3p0/releases/tag/v0.14.0)
