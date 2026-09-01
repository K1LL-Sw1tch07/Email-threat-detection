from pathlib import Path

import geoip2.database
import geoip2.errors


BASE_DIR = Path(__file__).resolve().parents[3]

GEOIP_DIR = BASE_DIR / "data" / "geoip"

CITY_DATABASE = GEOIP_DIR / "GeoLite2-City.mmdb"
ASN_DATABASE = GEOIP_DIR / "GeoLite2-ASN.mmdb"


def lookup_city(ip: str) -> dict:
    """
    Look up geographic information for an IP address.
    """

    result = {
        "available": False,
        "country": None,
        "country_code": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "source": "MaxMind GeoLite2",
        "error": None,
    }

    if not CITY_DATABASE.exists():
        result["error"] = "GeoIP City database not installed."
        return result

    try:

        with geoip2.database.Reader(str(CITY_DATABASE)) as reader:

            response = reader.city(ip)

            result["country"] = (
                response.country.name
            )

            result["country_code"] = (
                response.country.iso_code
            )

            result["city"] = (
                response.city.name
            )

            result["latitude"] = (
                response.location.latitude
            )

            result["longitude"] = (
                response.location.longitude
            )

            result["available"] = True

    except geoip2.errors.AddressNotFoundError:

        result["error"] = (
            "IP address not found in GeoIP database."
        )

    except ValueError:

        result["error"] = "Invalid IP address."

    except Exception as error:

        result["error"] = str(error)

    return result


def lookup_asn(ip: str) -> dict:
    """
    Look up ASN and network information for an IP address.
    """

    result = {
        "available": False,
        "asn": None,
        "organization": None,
        "network": None,
        "source": "MaxMind GeoLite2",
        "error": None,
    }

    if not ASN_DATABASE.exists():
        result["error"] = "GeoIP ASN database not installed."
        return result

    try:

        with geoip2.database.Reader(str(ASN_DATABASE)) as reader:

            response = reader.asn(ip)

            result["asn"] = (
                response.autonomous_system_number
            )

            result["organization"] = (
                response.autonomous_system_organization
            )

            result["network"] = str(
                response.network
            )

            result["available"] = True

    except geoip2.errors.AddressNotFoundError:

        result["error"] = (
            "IP address not found in ASN database."
        )

    except ValueError:

        result["error"] = "Invalid IP address."

    except Exception as error:

        result["error"] = str(error)

    return result


def enrich_ip_with_maxmind(ip: str) -> dict:
    """
    Combine GeoIP and ASN intelligence.
    """

    city = lookup_city(ip)
    asn = lookup_asn(ip)

    available = (
        city["available"]
        or asn["available"]
    )

    return {
        "ip": ip,
        "available": available,
        "country": city["country"],
        "country_code": city["country_code"],
        "city": city["city"],
        "latitude": city["latitude"],
        "longitude": city["longitude"],
        "asn": asn["asn"],
        "organization": asn["organization"],
        "network": asn["network"],
        "provider": asn["organization"],
        "source": "MaxMind GeoLite2",
        "geoip": city,
        "asn_intelligence": asn,
    }