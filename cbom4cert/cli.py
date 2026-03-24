# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import platform
import sys
import textwrap
from collections import ChainMap

from cbom4cert.generator import CBOMGenerator
from cbom4cert.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "cbom4cert"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            CBOM4cert generates a Cryptography Bill of Materials for one or more installed certificates.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    support_certfile = platform.system() not in ["Windows", "Darwin"]
    if support_certfile:
        input_group.add_argument(
            "-c",
            "--certificate",
            action="store",
            default="",
            help="filename of certificate",
        )
    input_group.add_argument(
        "--system",
        action="store_true",
        help="include all installed python modules within system",
    )
    input_group.add_argument(
        "--path",
        action="store",
        default="",
        help="path to directory of certificates",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="cyclonedx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: cyclonedx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="json",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) (default: json)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "certificate": "",
        "system": False,
        "path": "",
        "output_file": "",
        "sbom": "cyclonedx",
        "debug": False,
        "format": "json",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    certificate_name = args["certificate"]

    # Ensure format is aligned with type of SBOM
    bom_format = args["format"]
    if args["sbom"] == "cyclonedx":
        # Only JSON format valid for CycloneDX
        if bom_format != "json":
            bom_format = "json"

    # At least certificate or system shgould be specified
    if certificate_name == "" and not args['system']:
        print ("[ERROR] One of --certificate or --system must be specified")

    if args["debug"]:
        if support_certfile:
            print("Certificate", certificate_name)
        print("System", args["system"])
        print("Certificate path", args["path"])
        print("SBOM type:", args["sbom"])
        print("Format:", bom_format)
        print("Output file:", args["output_file"])

    cbom_generator = CBOMGenerator()

    if support_certfile and len(certificate_name) > 0:
        # Chcek file exists
        cbom_generator.process_certificate(certificate_name)
    elif args["system"]:
        cbom_generator.get_system_certificates(args["path"])
    else:
        print("[ERROR] Nothing to process")
        return -1

    cbom_generator.create_cbom(sbom_type = args["sbom"], sbom_format=args["format"], outfile = args["output_file"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
