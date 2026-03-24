# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import platform
import ssl
import subprocess
import unicodedata
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from lib4sbom.data.cryptography import SBOMCryptography
from lib4sbom.data.package import SBOMPackage
from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.sbom import SBOM

from cbom4cert.version import VERSION

# Basic information

class CBOMGenerator:

    # Scans common filesystem paths for Linux (Debian/RPM) and BSD
    LINUX_PATHS = [
        '/etc/ssl/certs',            # Debian/Ubuntu/BSD
        '/etc/pki/tls/certs',        # RHEL/CentOS/Fedora
        '/usr/local/share/certs',    # FreeBSD
    ]

    def __init__(self):
        self.inventory = []

    # Detailed information

    def time_helper(self, cert_date):
        return cert_date.strftime("%Y-%m-%d")

    def get_cert_metadata(self, cert_bytes, fmt="DER", cert_file = None):
        if fmt == "PEM":
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        else:
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        # Get Public Key Details
        public_key = cert.public_key()
        # key_info = {"algorithm": type(public_key).__name__}
        key_info = {"type": type(public_key).__name__}

        if isinstance(public_key, rsa.RSAPublicKey):
            key_info["size"] = public_key.key_size
            numbers = public_key.public_numbers()
            key_info["modulus"] = numbers.n
            key_info["exponent"] = numbers.e
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_info["curve"] = public_key.curve.name
            key_info["size"] = public_key.key_size

        # Basic Constraints (Check if it's a CA)
        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
        except x509.ExtensionNotFound:
            pass

        issuer_dict = {attr.rfc4514_attribute_name: attr.value for attr in cert.issuer}

        # Access it like a normal dictionary
        supplier = issuer_dict.get("O")

        return {
            "subject": unicodedata.normalize('NFC',cert.subject.rfc4514_string()),
            "issuer": unicodedata.normalize('NFC',cert.issuer.rfc4514_string()),
            "organization": supplier,
            "serial": hex(cert.serial_number),
            "version": cert.version.name,
            "signature_hash_algo": cert.signature_hash_algorithm.name,
            "valid_from": self.time_helper(cert.not_valid_before_utc),
            "valid_to": self.time_helper(cert.not_valid_after_utc),
            'end_date': cert.not_valid_after_utc,
            "public_key": key_info,
            "is_ca": any(ext.value.ca for ext in cert.extensions if isinstance(ext.value, x509.BasicConstraints)),
            "format": fmt,
            "compliant": self.check_compliance(cert, key_info),
            "file" : cert_file,
            "oid": cert.public_key_algorithm_oid.dotted_string
        }

    def check_compliance(self, cert, key_info):
        """Simple auditor for CBOM compliance."""
        now = datetime.now(timezone.utc)

        # 1. Check Expiry
        if cert.not_valid_after_utc < now:
            return "NON-COMPLIANT: Expired"

        # 2. Check RSA Key Strength
        if key_info["type"] == "_RSAPublicKey" and key_info.get("bits", 0) < 2048:
            return "NON-COMPLIANT: Weak RSA Key (<2048)"

        # 3. Check for Deprecated Hashes
        if cert.signature_hash_algorithm and cert.signature_hash_algorithm.name in ['sha1', 'md5']:
            return "NON-COMPLIANT: Weak Hash (SHA1/MD5)"

        return "COMPLIANT"

    # OS Specificc
    def scan_linux(self, certificate_paths=""):
        certs = []
        paths = self.LINUX_PATHS if certificate_paths == "" else certificate_paths
        for path in paths:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        if file.endswith((".crt", ".pem")):
                            with open(os.path.join(root, file), 'rb') as f:
                                certs.append(self.get_cert_metadata(f.read(), "PEM", os.path.join(root, file)))
        return certs

    def scan_windows(self):
        # use ssl module to access Windows System Stores
        certs = []
        for store in ["ROOT", "CA", "MY"]:
            for cert_der, encoding, trust in ssl.enum_certificates(store):
                certs.append(self.get_cert_metadata(cert_der, "DER"))
        return certs

    def scan_macos(self):
        """Calls the macOS 'security' tool to find certificates."""
        certs = []
        try:
            # Find all certificates in the default keychains
            cmd = ["security", "find-certificate", "-a", "-p"]
            output = subprocess.check_output(cmd)
            # Split output into individual PEM blocks
            pem_certs = output.split(b"-----END CERTIFICATE-----")
            for pem in pem_certs:
                if b"-----BEGIN CERTIFICATE-----" in pem:
                    certs.append(self.get_cert_metadata(pem + b"-----END CERTIFICATE-----", "PEM"))
        except Exception as e:
            print(f"macOS scan error: {e}")
        return certs

    def process_certificate(self, filename):
        if platform.system() not in ["Windows", "Darwin"]:
            if filename.endswith((".crt", ".pem")):
                with open(filename, 'rb') as f:
                    self.inventory.append(self.get_cert_metadata(f.read(), "PEM", filename))

    def get_system_certificates(self, path=""):
        # Entry point for CBOM data collection fuor all certiciates in system
        os_type = platform.system()
        if os_type == "Windows":
            self.inventory = self.scan_windows()
        elif os_type == "Darwin":
            self.inventory = self.scan_macos()
        else: # Linux variants
            self.inventory = self.scan_linux(path)

    # def get_comprehensive_cert_data(self, cert_bytes, fmt="DER", cert_file = None):
    #     if fmt == "PEM":
    #         cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    #     else:
    #         cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

    #     # Get Public Key Details
    #     public_key = cert.public_key()
    #     key_info = {"algorithm": type(public_key).__name__}

    #     if isinstance(public_key, rsa.RSAPublicKey):
    #         key_info["size"] = public_key.key_size
    #     elif isinstance(public_key, ec.EllipticCurvePublicKey):
    #         key_info["curve"] = public_key.curve.name
    #         key_info["size"] = public_key.key_size

    #     return {
    #         "subject": cert.subject.rfc4514_string(),
    #         "issuer": cert.issuer.rfc4514_string(),
    #         "serial": hex(cert.serial_number),
    #         "version": cert.version.name,
    #         "signature_hash_algo": cert.signature_hash_algorithm.name,
    #         "valid_from": cert.not_valid_before_utc.isoformat(),
    #         "valid_to": cert.not_valid_after_utc.isoformat(),
    #         "public_key": key_info,
    #         "is_ca": any(ext.value.ca for ext in cert.extensions if isinstance(ext.value, x509.BasicConstraints)),
    #         "file": cert_file
    #     }

    def create_cbom(self, sbom_type="cyclonedx", sbom_format="json", outfile=""):
        now = datetime.now(timezone.utc)
        sbom_packages = {}
        my_package = SBOMPackage()
        my_crypto = SBOMCryptography()
        for entry in self.inventory:
            name = os.path.basename(entry['file'])
            my_package.initialise()
            my_package.set_evidence(entry['file'])
            my_crypto.initialise()
            my_package.set_type("cryptographic-asset")
            my_package.set_name(name)
            my_package.set_version(entry['version'])
            if entry.get('organization') is not None:
                my_package.set_supplier("organization", entry['organization'])
            my_crypto.set_type("certificate")
            my_crypto.set_certificate(subject = entry['subject'], issuer = entry['issuer'])
            # my_crypto.set_value("serialNumber", entry['serial'])
            if entry['end_date'] > now:
                my_crypto.set_state("active")
            else:
                my_crypto.set_state("deactivated")
            my_crypto.set_date("activate", entry['valid_from'])
            my_crypto.set_date("deactivate", entry['valid_to'])
            for key, value in entry['public_key'].items():
                my_crypto.set_asset(key,str(value))
            my_crypto.set_format(entry['format'])
            my_crypto.set_oid(entry['oid'])
            my_package.set_value("crypto", my_crypto.get_cryptography())
            sbom_packages[
                (my_package.get_name(), my_package.get_value("version"))
            ] = my_package.get_package()
            # if 'signature_hash_algo' in entry:
            #     # Algorithm
            #     my_package.initialise()
            #     my_crypto.initialise()
            #     my_package.set_type("cryptographic-asset")
            #     my_package.set_name(f"{name}_alg")
            #     my_package.set_version(entry['version'])
            #     my_crypto.set_type("algorithm","signature")
            #     my_crypto.set_algorithm(entry['signature_hash_algo'])
            #     my_package.set_value("crypto", my_crypto.get_cryptography())
            #     sbom_packages[
            #         (my_package.get_name(), my_package.get_value("version"))
            #     ] = my_package.get_package()
        # Generate SBOM
        my_sbom = SBOM()
        my_sbom.set_type(sbom_type=sbom_type)
        my_sbom.add_packages(sbom_packages)
        my_generator = SBOMGenerator(False, sbom_type=sbom_type, format=sbom_format, version=VERSION)
        # Will be displayed on console if no filename specified
        my_generator.generate("CryptoInfo", my_sbom.get_sbom(), filename=outfile)

    def show_certs(self):
        for cert in self.inventory:
            print (cert)


# Usage
if __name__ == "__main__":
    inventory = get_system_certificates()
    # for entry in inventory:
    #     print(entry)
    #     if "error" not in entry:
    #         status = "✅" if "COMPLIANT" in entry["compliant"] else "❌"
    #         print(f"{status} {entry['subject'][:50]}... | Expires: {entry['valid_to']} | {entry['compliant']}")
    create_cbom()
