"""Tests for pki/ceremony/ceremony.py. No network; everything runs in tmp_path."""

import stat
from datetime import timedelta
from pathlib import Path
from typing import List

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pki.ceremony import ceremony

CDP = "https://labca.example.test/pki/root/crl.der"
PUBLIC_FILES = {
    "root-ca.pem",
    "root-crl.der",
    "root-crl.pem",
    "issuing-ca.pem",
    "chain.pem",
    "issuing-ca.key.pem",
    "fingerprints.txt",
}
SECRET_FILES = {"root-ca.key.enc", "root-passphrase.txt"}


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def run_init(out: Path, *extra: str, mode_: str = "test") -> int:
    return ceremony.main(["init", "--mode", mode_, "--out", str(out), "--issuing-cdp", CDP, *extra])


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def names(path: Path) -> set:
    return {p.name for p in path.iterdir()}


@pytest.fixture()
def out(tmp_path: Path) -> Path:
    target = tmp_path / "out"
    assert run_init(target) == 0
    return target


@pytest.fixture()
def root(out: Path) -> x509.Certificate:
    return load_cert(out / "root-ca.pem")


@pytest.fixture()
def issuing(out: Path) -> x509.Certificate:
    return load_cert(out / "issuing-ca.pem")


def test_init_test_mode_writes_expected_files(out: Path) -> None:
    assert names(out) == PUBLIC_FILES | SECRET_FILES
    for path in out.iterdir():
        assert mode(path) == 0o600, path.name
    assert mode(out) == 0o700


def test_chain_verifies(out: Path, root: x509.Certificate, issuing: x509.Certificate) -> None:
    issuing.verify_directly_issued_by(root)
    root.verify_directly_issued_by(root)
    chain = x509.load_pem_x509_certificates((out / "chain.pem").read_bytes())
    assert chain == [issuing, root]


def test_root_profile(root: x509.Certificate) -> None:
    cn = root.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    org = root.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
    assert (cn, org) == (ceremony.ROOT_CN, ceremony.ORG)
    assert root.issuer == root.subject
    pub = root.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert isinstance(pub.curve, ec.SECP384R1)
    assert isinstance(root.signature_hash_algorithm, hashes.SHA384)
    bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca is True and bc.value.path_length == 1
    ku = root.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical
    assert ku.value.key_cert_sign and ku.value.crl_sign
    for flag in (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
    ):
        assert getattr(ku.value, flag) is False
    assert root.not_valid_after_utc - root.not_valid_before_utc == timedelta(days=3650)
    ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = root.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert not aki.critical
    assert aki.value.key_identifier == ski.digest


def test_issuing_profile(tmp_path: Path, root: x509.Certificate, issuing: x509.Certificate) -> None:
    cn = issuing.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == ceremony.ISSUING_CN_DEFAULT
    assert issuing.issuer == root.subject
    pub = issuing.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert isinstance(pub.curve, ec.SECP256R1)
    bc = issuing.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca is True and bc.value.path_length == 0
    ku = issuing.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.key_cert_sign and ku.value.crl_sign
    assert not ku.value.digital_signature and not ku.value.key_agreement
    assert issuing.not_valid_after_utc - issuing.not_valid_before_utc == timedelta(days=1095)
    assert issuing.not_valid_after_utc <= root.not_valid_after_utc
    root_ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = issuing.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert not aki.critical and aki.value.key_identifier == root_ski.digest

    custom = tmp_path / "custom"
    assert run_init(custom, "--issuing-cn", "Other Issuing CA") == 0
    other = load_cert(custom / "issuing-ca.pem")
    assert other.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Other Issuing CA"


def test_issuing_has_cdp(issuing: x509.Certificate) -> None:
    ext = issuing.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    assert not ext.critical
    assert len(ext.value) == 1
    full_name = ext.value[0].full_name
    assert full_name is not None
    assert [n.value for n in full_name] == [CDP]


def test_root_crl_is_empty_signed_and_valid_for_365_days(out: Path, root: x509.Certificate) -> None:
    der = x509.load_der_x509_crl((out / "root-crl.der").read_bytes())
    pem = x509.load_pem_x509_crl((out / "root-crl.pem").read_bytes())
    assert der.public_bytes(serialization.Encoding.DER) == pem.public_bytes(serialization.Encoding.DER)
    assert len(list(der)) == 0
    assert der.issuer == root.subject
    assert der.is_signature_valid(root.public_key())
    assert der.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 1
    assert der.next_update_utc is not None
    assert der.next_update_utc - der.last_update_utc == timedelta(days=365)


def test_issuing_key_matches_and_is_plain_pkcs8(out: Path, issuing: x509.Certificate) -> None:
    data = (out / "issuing-ca.key.pem").read_bytes()
    assert data.startswith(b"-----BEGIN PRIVATE KEY-----")
    key = serialization.load_pem_private_key(data, password=None)
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    assert key.public_key().public_bytes(der, spki) == issuing.public_key().public_bytes(der, spki)


def test_root_key_decrypts_only_with_passphrase(out: Path, root: x509.Certificate) -> None:
    data = (out / "root-ca.key.enc").read_bytes()
    passphrase = (out / "root-passphrase.txt").read_text()
    assert passphrase.endswith("\n") and len(passphrase.strip()) == 43
    key = serialization.load_pem_private_key(data, password=passphrase.strip().encode())
    with pytest.raises(ValueError):
        serialization.load_pem_private_key(data, password=b"wrong-passphrase")
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(data, password=None)
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    assert key.public_key().public_bytes(der, spki) == root.public_key().public_bytes(der, spki)


def test_prod_mode_keeps_root_key_out_of_out_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    offline = tmp_path / "offline"
    assert run_init(out, "--root-key-dir", str(offline), mode_="prod") == 0
    assert names(out) == PUBLIC_FILES
    assert names(offline) == SECRET_FILES
    passphrase = (offline / "root-passphrase.txt").read_text().strip()
    for path in out.iterdir():
        content = path.read_bytes()
        assert b"ENCRYPTED PRIVATE KEY" not in content
        assert passphrase.encode() not in content
    for path in offline.iterdir():
        assert mode(path) == 0o600
    assert mode(offline) == 0o700


def test_prod_refuses_root_key_dir_inside_out_and_vice_versa(tmp_path: Path) -> None:
    base = tmp_path / "base"
    cases = [
        (base / "out", base / "out" / "keys"),
        (base / "out" / "sub", base / "out"),
        (base / "same", base / "same"),
    ]
    for out, keys in cases:
        assert run_init(out, "--root-key-dir", str(keys), mode_="prod") == 2
    assert not base.exists()


def test_prod_refuses_root_key_dir_in_git_tree(tmp_path: Path) -> None:
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    out = tmp_path / "out"
    keys = tmp_path / "repo" / "keys"
    assert run_init(out, "--root-key-dir", str(keys), mode_="prod") == 2
    assert not out.exists()
    assert not keys.exists()


def test_test_mode_rejects_root_key_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert run_init(out, "--root-key-dir", str(tmp_path / "keys")) == 2
    assert not out.exists()


def test_refuses_to_overwrite(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    out = tmp_path / "out"
    assert run_init(out) == 0
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    capsys.readouterr()
    assert run_init(out) == 1
    assert "error: " in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before


def test_stdout_has_no_secrets(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    offline = tmp_path / "offline"
    assert run_init(tmp_path / "out", "--root-key-dir", str(offline), mode_="prod") == 0
    passphrase = (offline / "root-passphrase.txt").read_text().strip()
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert passphrase not in text
    assert "PRIVATE KEY" not in text
    assert "BEGIN CERTIFICATE" not in text
    assert str(offline) in captured.out


def test_fingerprints_file(out: Path, root: x509.Certificate, issuing: x509.Certificate) -> None:
    def fp(cert: x509.Certificate) -> str:
        return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))

    lines = (out / "fingerprints.txt").read_text().splitlines()
    assert lines == [
        f"root-ca.pem sha256 Fingerprint={fp(root)}",
        f"issuing-ca.pem sha256 Fingerprint={fp(issuing)}",
    ]


@pytest.mark.parametrize("cdp", ["ftp://x/crl", "not-a-url", "https://"])
def test_invalid_cdp_rejected(tmp_path: Path, cdp: str) -> None:
    out = tmp_path / "out"
    assert ceremony.main(["init", "--mode", "test", "--out", str(out), "--issuing-cdp", cdp]) == 2
    assert not out.exists()


def renew_args(out: Path, previous: Path, dest: Path, *extra: str) -> List[str]:
    return [
        "renew-root-crl",
        "--root-cert",
        str(out / "root-ca.pem"),
        "--root-key",
        str(out / "root-ca.key.enc"),
        "--passphrase-file",
        str(out / "root-passphrase.txt"),
        "--previous-crl",
        str(previous),
        "--out",
        str(dest),
        *extra,
    ]


def test_renew_root_crl_increments_and_carries_entries(tmp_path: Path, out: Path, root: x509.Certificate) -> None:
    first = tmp_path / "crl2"
    assert ceremony.main(renew_args(out, out / "root-crl.der", first, "--revoke", "ABCDEF:superseded")) == 0
    crl2 = x509.load_der_x509_crl((first / "root-crl.der").read_bytes())
    assert crl2.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 2
    assert crl2.is_signature_valid(root.public_key())
    entries = list(crl2)
    assert [e.serial_number for e in entries] == [0xABCDEF]
    assert entries[0].extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.superseded
    assert mode(first / "root-crl.der") == 0o600 and mode(first / "root-crl.pem") == 0o600

    second = tmp_path / "crl3"
    assert ceremony.main(renew_args(out, first / "root-crl.pem", second, "--revoke", "1f:keyCompromise")) == 0
    crl3 = x509.load_der_x509_crl((second / "root-crl.der").read_bytes())
    assert crl3.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 3
    assert crl3.is_signature_valid(root.public_key())
    assert {e.serial_number for e in crl3} == {0xABCDEF, 0x1F}
    assert crl3.get_revoked_certificate_by_serial_number(0xABCDEF) is not None

    third = tmp_path / "crl4"
    assert ceremony.main(renew_args(out, second / "root-crl.der", third, "--revoke", "1F:superseded")) == 2
    assert not third.exists()


def test_renew_root_crl_rejects_foreign_crl(tmp_path: Path, out: Path) -> None:
    other_key, other_root = ceremony.build_root(ceremony._now())
    foreign = ceremony.build_crl(other_key, other_root, 1, ceremony._now(), timedelta(days=1), [])
    foreign_path = tmp_path / "foreign.der"
    foreign_path.write_bytes(foreign.public_bytes(serialization.Encoding.DER))
    dest = tmp_path / "new"
    assert ceremony.main(renew_args(out, foreign_path, dest)) == 1
    assert not dest.exists()


def test_renew_root_crl_wrong_passphrase(tmp_path: Path, out: Path, capsys: pytest.CaptureFixture) -> None:
    bad = tmp_path / "bad-pass.txt"
    bad.write_text("not-the-passphrase-xyz\n")
    args = renew_args(out, out / "root-crl.der", tmp_path / "new")
    args[args.index("--passphrase-file") + 1] = str(bad)
    real = (out / "root-passphrase.txt").read_text().strip()
    capsys.readouterr()
    assert ceremony.main(args) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ")
    assert real not in err and "not-the-passphrase-xyz" not in err


def test_new_issuing_ca_chains_to_root(
    tmp_path: Path, out: Path, root: x509.Certificate, issuing: x509.Certificate
) -> None:
    dest = tmp_path / "new-issuing"
    new_cdp = "http://labca.example.test/other.der"
    rc = ceremony.main(
        [
            "new-issuing-ca",
            "--root-cert",
            str(out / "root-ca.pem"),
            "--root-key",
            str(out / "root-ca.key.enc"),
            "--passphrase-file",
            str(out / "root-passphrase.txt"),
            "--out",
            str(dest),
            "--issuing-cdp",
            new_cdp,
            "--issuing-cn",
            "LabCA Workload Issuing CA 2",
        ]
    )
    assert rc == 0
    assert names(dest) == {"issuing-ca.pem", "issuing-ca.key.pem", "chain.pem", "fingerprints.txt"}
    for path in dest.iterdir():
        assert mode(path) == 0o600
    new = load_cert(dest / "issuing-ca.pem")
    new.verify_directly_issued_by(root)
    assert new.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "LabCA Workload Issuing CA 2"
    assert new.public_key() != issuing.public_key()
    cdp = new.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name
    assert cdp is not None and [n.value for n in cdp] == [new_cdp]
    old_lines = (out / "fingerprints.txt").read_text().splitlines()
    new_lines = (dest / "fingerprints.txt").read_text().splitlines()
    assert new_lines[0] == old_lines[0]
    assert new_lines[1] != old_lines[1]
    chain = x509.load_pem_x509_certificates((dest / "chain.pem").read_bytes())
    assert chain == [new, root]
