import base64
import gzip
import io
import random
import unittest
from contextlib import redirect_stderr, redirect_stdout
from urllib.parse import parse_qs, urlsplit

from open_in_advanced_hunting import MAX_URL_LENGTH, QueryTooLongError, build_url, main

QUERY = """DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine // naïve ✓
| take 10"""


def decode_url(url: str) -> tuple[str, dict[str, list[str]]]:
    parts = urlsplit(url)
    params = parse_qs(parts.query)
    kql = gzip.decompress(base64.b64decode(params["query"][0])).decode("utf-16-le")
    return kql, params


def incompressible_query() -> str:
    # Random text barely compresses, so its link outgrows the limit.
    noise = base64.b64encode(random.Random(0).randbytes(6000)).decode()
    return f"print x = '{noise}'"


class BuildUrlTest(unittest.TestCase):
    def test_the_query_round_trips_through_the_link(self):
        url = build_url(QUERY)

        kql, params = decode_url(url)

        self.assertTrue(url.startswith("https://security.microsoft.com/v2/advanced-hunting?query="))
        self.assertEqual(kql, QUERY)
        self.assertEqual(params["timeRangeId"], ["day"])
        self.assertNotIn("tid", params)

    def test_the_payload_is_percent_encoded(self):
        url = build_url(QUERY)

        raw_query = urlsplit(url).query.split("&")[0].removeprefix("query=")

        self.assertFalse(set(raw_query) & set("+/="), raw_query)

    def test_the_same_query_builds_the_same_link(self):
        self.assertEqual(build_url(QUERY), build_url(QUERY))

    def test_time_range_and_tenant_are_passed_through(self):
        url = build_url(QUERY, time_range="week", tenant_id="00000000-0000-0000-0000-000000000000")

        _, params = decode_url(url)

        self.assertEqual(params["timeRangeId"], ["week"])
        self.assertEqual(params["tid"], ["00000000-0000-0000-0000-000000000000"])

    def test_a_link_over_the_limit_is_refused(self):
        with self.assertRaises(QueryTooLongError):
            build_url(incompressible_query())

    def test_an_empty_query_is_refused(self):
        with self.assertRaises(ValueError):
            build_url("  \n")


class MainTest(unittest.TestCase):
    def test_prints_the_link_for_a_query_argument(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--query", QUERY])

        self.assertEqual(code, 0)
        self.assertEqual(decode_url(out.getvalue().strip())[0], QUERY)

    def test_exits_2_without_a_link_when_too_long(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--query", incompressible_query()])

        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn(str(MAX_URL_LENGTH), err.getvalue())


if __name__ == "__main__":
    unittest.main()
