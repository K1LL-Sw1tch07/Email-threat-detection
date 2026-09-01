import os
import tarfile
from pathlib import Path

import requests
from dotenv import load_dotenv


# ---------------------------------------------------------
# PATHS
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

ENV_FILE = BASE_DIR / ".env"

GEOIP_DIR = BASE_DIR / "backend" / "data" / "geoip"

GEOIP_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ---------------------------------------------------------
# LOAD ENVIRONMENT
# ---------------------------------------------------------

load_dotenv(ENV_FILE)

ACCOUNT_ID = os.getenv("MAXMIND_ACCOUNT_ID")
LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")


if not ACCOUNT_ID or not LICENSE_KEY:
    raise RuntimeError(
        "MAXMIND_ACCOUNT_ID or MAXMIND_LICENSE_KEY is missing."
    )


# ---------------------------------------------------------
# DOWNLOAD FUNCTION
# ---------------------------------------------------------

def download_database(database_name: str) -> None:

    url = (
        "https://download.maxmind.com/geoip/databases/"
        f"{database_name}/download?suffix=tar.gz"
    )

    print(f"Downloading {database_name}...")

    response = requests.get(
        url,
        auth=(ACCOUNT_ID, LICENSE_KEY),
        timeout=60
    )

    response.raise_for_status()

    archive_path = GEOIP_DIR / f"{database_name}.tar.gz"

    archive_path.write_bytes(
        response.content
    )

    print(f"Downloaded: {archive_path}")

    with tarfile.open(
        archive_path,
        "r:gz"
    ) as archive:

        members = archive.getmembers()

        mmdb_member = next(
            (
                member
                for member in members
                if member.name.endswith(".mmdb")
            ),
            None
        )

        if mmdb_member is None:
            raise RuntimeError(
                f"No .mmdb file found in {database_name} archive."
            )

        extracted_path = archive.extractfile(
            mmdb_member
        )

        if extracted_path is None:
            raise RuntimeError(
                f"Unable to extract {database_name}."
            )

        output_path = (
            GEOIP_DIR /
            Path(mmdb_member.name).name
        )

        output_path.write_bytes(
            extracted_path.read()
        )

        print(f"Installed: {output_path}")

    archive_path.unlink()

    print(f"Finished {database_name}")
    print()


# ---------------------------------------------------------
# DOWNLOAD DATABASES
# ---------------------------------------------------------

download_database("GeoLite2-City")

download_database("GeoLite2-ASN")

print("GeoIP databases installed successfully.")