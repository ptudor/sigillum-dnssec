=== RUN   TestKeyGeneration
=== RUN   TestKeyGeneration/ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ED25519
=== RUN   TestKeyGeneration/ECDSAP256SHA256
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ECDSAP256SHA256
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ECDSAP256SHA256
=== RUN   TestKeyGeneration/ECDSAP384SHA384
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ECDSAP384SHA384
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ECDSAP384SHA384
--- PASS: TestKeyGeneration (0.01s)
    --- PASS: TestKeyGeneration/ED25519 (0.00s)
    --- PASS: TestKeyGeneration/ECDSAP256SHA256 (0.00s)
    --- PASS: TestKeyGeneration/ECDSAP384SHA384 (0.00s)
=== RUN   TestDSComputation
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
--- PASS: TestDSComputation (0.00s)
=== RUN   TestZoneValidation
=== RUN   TestZoneValidation/valid_zone
=== RUN   TestZoneValidation/missing_SOA
=== RUN   TestZoneValidation/missing_NS_at_apex
=== RUN   TestZoneValidation/multiple_SOA_records
--- PASS: TestZoneValidation (0.00s)
    --- PASS: TestZoneValidation/valid_zone (0.00s)
    --- PASS: TestZoneValidation/missing_SOA (0.00s)
    --- PASS: TestZoneValidation/missing_NS_at_apex (0.00s)
    --- PASS: TestZoneValidation/multiple_SOA_records (0.00s)
=== RUN   TestSigningRoundTrip
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ED25519
2026/01/19 11:45:43 INFO [SIGN] Signing zone domain=example.com path=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestSigningRoundTrip4031849818/001/example.com.zone
2026/01/19 11:45:43 INFO [SIGN] Zone signed successfully domain=example.com serial=2024011501 output=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestSigningRoundTrip4031849818/001/signed/example.com.zone.signed duration_ms=0
--- PASS: TestSigningRoundTrip (0.00s)
=== RUN   TestNSECChainGeneration
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ED25519
2026/01/19 11:45:43 INFO [SIGN] Signing zone domain=example.com path=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestNSECChainGeneration4250490331/001/example.com.zone
2026/01/19 11:45:43 INFO [SIGN] Zone signed successfully domain=example.com serial=2024011501 output=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestNSECChainGeneration4250490331/001/signed/example.com.zone.signed duration_ms=0
--- PASS: TestNSECChainGeneration (0.00s)
=== RUN   TestAlgorithmFromName
=== RUN   TestAlgorithmFromName/ED25519
=== RUN   TestAlgorithmFromName/ECDSAP256SHA256
=== RUN   TestAlgorithmFromName/ECDSAP384SHA384
=== RUN   TestAlgorithmFromName/RSASHA256
=== RUN   TestAlgorithmFromName/RSASHA512
=== RUN   TestAlgorithmFromName/INVALID
=== RUN   TestAlgorithmFromName/ed25519
--- PASS: TestAlgorithmFromName (0.00s)
    --- PASS: TestAlgorithmFromName/ED25519 (0.00s)
    --- PASS: TestAlgorithmFromName/ECDSAP256SHA256 (0.00s)
    --- PASS: TestAlgorithmFromName/ECDSAP384SHA384 (0.00s)
    --- PASS: TestAlgorithmFromName/RSASHA256 (0.00s)
    --- PASS: TestAlgorithmFromName/RSASHA512 (0.00s)
    --- PASS: TestAlgorithmFromName/INVALID (0.00s)
    --- PASS: TestAlgorithmFromName/ed25519 (0.00s)
=== RUN   TestAlgorithmName
=== RUN   TestAlgorithmName/ED25519
=== RUN   TestAlgorithmName/ECDSAP256SHA256
=== RUN   TestAlgorithmName/ECDSAP384SHA384
=== RUN   TestAlgorithmName/RSASHA256
=== RUN   TestAlgorithmName/Unknown(99)
--- PASS: TestAlgorithmName (0.00s)
    --- PASS: TestAlgorithmName/ED25519 (0.00s)
    --- PASS: TestAlgorithmName/ECDSAP256SHA256 (0.00s)
    --- PASS: TestAlgorithmName/ECDSAP384SHA384 (0.00s)
    --- PASS: TestAlgorithmName/RSASHA256 (0.00s)
    --- PASS: TestAlgorithmName/Unknown(99) (0.00s)
=== RUN   TestDurationParsing
=== RUN   TestDurationParsing/1y
=== RUN   TestDurationParsing/3y
=== RUN   TestDurationParsing/90d
=== RUN   TestDurationParsing/14d
=== RUN   TestDurationParsing/1M
=== RUN   TestDurationParsing/5m
=== RUN   TestDurationParsing/30s
=== RUN   TestDurationParsing/1h
--- PASS: TestDurationParsing (0.00s)
    --- PASS: TestDurationParsing/1y (0.00s)
    --- PASS: TestDurationParsing/3y (0.00s)
    --- PASS: TestDurationParsing/90d (0.00s)
    --- PASS: TestDurationParsing/14d (0.00s)
    --- PASS: TestDurationParsing/1M (0.00s)
    --- PASS: TestDurationParsing/5m (0.00s)
    --- PASS: TestDurationParsing/30s (0.00s)
    --- PASS: TestDurationParsing/1h (0.00s)
=== RUN   TestConfigValidation
=== RUN   TestConfigValidation/valid_config
=== RUN   TestConfigValidation/invalid_algorithm
=== RUN   TestConfigValidation/invalid_nsec_version
=== RUN   TestConfigValidation/refresh_>=_validity
=== RUN   TestConfigValidation/nsec3_iterations_too_high
=== RUN   TestConfigValidation/invalid_nsec3_salt
--- PASS: TestConfigValidation (0.00s)
    --- PASS: TestConfigValidation/valid_config (0.00s)
    --- PASS: TestConfigValidation/invalid_algorithm (0.00s)
    --- PASS: TestConfigValidation/invalid_nsec_version (0.00s)
    --- PASS: TestConfigValidation/refresh_>=_validity (0.00s)
    --- PASS: TestConfigValidation/nsec3_iterations_too_high (0.00s)
    --- PASS: TestConfigValidation/invalid_nsec3_salt (0.00s)
=== RUN   TestRolloverStateTransitions
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ED25519
2026/01/19 11:45:43 INFO [ROLLOVER] Starting KSK rollover domain=example.com old_key_id=58887
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
2026/01/19 11:45:43 INFO [ROLLOVER] Completing KSK rollover domain=example.com old_key_id=58887 new_key_id=29980
2026/01/19 11:45:43 INFO [ROLLOVER] KSK rollover completed domain=example.com note="Old key files remain on disk for safety. You may delete them after removing the old DS from your registrar."
--- PASS: TestRolloverStateTransitions (0.00s)
=== RUN   TestCanonicalOrdering
=== RUN   TestCanonicalOrdering/example._vs_a.example.
=== RUN   TestCanonicalOrdering/a.example._vs_yljkjljk.a.example.
=== RUN   TestCanonicalOrdering/yljkjljk.a.example._vs_Z.a.example.
=== RUN   TestCanonicalOrdering/Z.a.example._vs_zABC.a.EXAMPLE.
=== RUN   TestCanonicalOrdering/zABC.a.EXAMPLE._vs_z.example.
=== RUN   TestCanonicalOrdering/a.example._vs_b.example.
=== RUN   TestCanonicalOrdering/aa.example._vs_ab.example.
=== RUN   TestCanonicalOrdering/A.example._vs_b.example.
=== RUN   TestCanonicalOrdering/a.example._vs_B.example.
=== RUN   TestCanonicalOrdering/example._vs_sub.example.
=== RUN   TestCanonicalOrdering/sub.example._vs_a.sub.example.
--- PASS: TestCanonicalOrdering (0.00s)
    --- PASS: TestCanonicalOrdering/example._vs_a.example. (0.00s)
    --- PASS: TestCanonicalOrdering/a.example._vs_yljkjljk.a.example. (0.00s)
    --- PASS: TestCanonicalOrdering/yljkjljk.a.example._vs_Z.a.example. (0.00s)
    --- PASS: TestCanonicalOrdering/Z.a.example._vs_zABC.a.EXAMPLE. (0.00s)
    --- PASS: TestCanonicalOrdering/zABC.a.EXAMPLE._vs_z.example. (0.00s)
    --- PASS: TestCanonicalOrdering/a.example._vs_b.example. (0.00s)
    --- PASS: TestCanonicalOrdering/aa.example._vs_ab.example. (0.00s)
    --- PASS: TestCanonicalOrdering/A.example._vs_b.example. (0.00s)
    --- PASS: TestCanonicalOrdering/a.example._vs_B.example. (0.00s)
    --- PASS: TestCanonicalOrdering/example._vs_sub.example. (0.00s)
    --- PASS: TestCanonicalOrdering/sub.example._vs_a.sub.example. (0.00s)
=== RUN   TestStateFilePersistence
--- PASS: TestStateFilePersistence (0.00s)
=== RUN   TestSignatureVerification
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ED25519
2026/01/19 11:45:43 INFO [SIGN] Signing zone domain=example.com path=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestSignatureVerification1952968150/001/example.com.zone
2026/01/19 11:45:43 INFO [SIGN] Zone signed successfully domain=example.com serial=2024011501 output=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestSignatureVerification1952968150/001/signed/example.com.zone.signed duration_ms=0
--- PASS: TestSignatureVerification (0.00s)
=== RUN   TestMultipleAlgorithms
=== RUN   TestMultipleAlgorithms/ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ED25519
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ED25519
2026/01/19 11:45:43 INFO [SIGN] Signing zone domain=example.com path=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestMultipleAlgorithmsED255191020969037/001/example.com.zone
2026/01/19 11:45:43 INFO [SIGN] Zone signed successfully domain=example.com serial=2024011501 output=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestMultipleAlgorithmsED255191020969037/001/signed/example.com.zone.signed duration_ms=0
=== RUN   TestMultipleAlgorithms/ECDSAP256SHA256
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ECDSAP256SHA256
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ECDSAP256SHA256
2026/01/19 11:45:43 INFO [SIGN] Signing zone domain=example.com path=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestMultipleAlgorithmsECDSAP256SHA2563950154540/001/example.com.zone
2026/01/19 11:45:43 INFO [SIGN] Zone signed successfully domain=example.com serial=2024011501 output=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestMultipleAlgorithmsECDSAP256SHA2563950154540/001/signed/example.com.zone.signed duration_ms=0
=== RUN   TestMultipleAlgorithms/ECDSAP384SHA384
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=ksk algorithm=ECDSAP384SHA384
2026/01/19 11:45:43 INFO [KEY] Generating key domain=example.com type=zsk algorithm=ECDSAP384SHA384
2026/01/19 11:45:43 INFO [SIGN] Signing zone domain=example.com path=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestMultipleAlgorithmsECDSAP384SHA3844063557994/001/example.com.zone
2026/01/19 11:45:43 INFO [SIGN] Zone signed successfully domain=example.com serial=2024011501 output=/var/folders/mg/kg6dy2ks1ng57t5pgfghyh3h0000gn/T/TestMultipleAlgorithmsECDSAP384SHA3844063557994/001/signed/example.com.zone.signed duration_ms=2
--- PASS: TestMultipleAlgorithms (0.01s)
    --- PASS: TestMultipleAlgorithms/ED25519 (0.00s)
    --- PASS: TestMultipleAlgorithms/ECDSAP256SHA256 (0.00s)
    --- PASS: TestMultipleAlgorithms/ECDSAP384SHA384 (0.00s)
PASS
ok  	github.com/ptudor/sigillum-dnssec/signer	0.364s
