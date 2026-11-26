"""Print a Splunk search that checks the dashboard's series grouping."""

from pathlib import Path
from xml.etree import ElementTree

from kerberos_bruteforce_search import CLIENT, fixture_events, make_results


PRIMARY = "fixture-dc-01"
SECONDARY = "fixture-dc-02"
OTHER_CLIENT = "192.0.2.11"


def additional_events(host, address, offsets):
    return [
        {
            "offset": offset,
            "host": host,
            "Account_Name": "boundary",
            "Client_Address": address,
            "Failure_Code": "0x18",
        }
        for offset in offsets
    ]


def main():
    root = Path(__file__).resolve().parents[1]
    rule = (root / "detections" / "kerberos-bruteforce.spl").read_text(encoding="utf-8")
    _, separator, detection = rule.partition("\n| ")
    if not separator:
        raise SystemExit("Expected a pipeline in the detection SPL file.")

    dashboard = ElementTree.parse(root / "dashboard" / "kerberos-series.xml")
    summary = dashboard.findtext("row/panel/table/search/query")
    if not summary:
        raise SystemExit("Expected a post-process search in the dashboard XML.")

    events = [
        event
        for event in fixture_events()
        if event.get("Account_Name") == "boundary" or "payload" in event
    ]
    events.extend(additional_events(PRIMARY, CLIENT, (130, 135, 300, 310, 320, 330, 340)))
    events.extend(additional_events(SECONDARY, CLIENT, (112, 117, 122, 127, 132)))
    events.extend(additional_events(PRIMARY, OTHER_CLIENT, (112, 117, 122, 127, 132)))

    expected = [
        {
            "host": host,
            "Account_Name": "boundary",
            "Client_Address": address,
            "first_offset": start,
            "expected_last": end,
            "expected_peak": peak,
            "expected_windows": windows,
        }
        for host, address, start, end, peak, windows in (
            (PRIMARY, CLIENT, 105, 135, 7, 3),
            (PRIMARY, CLIENT, 300, 340, 5, 1),
            (SECONDARY, CLIENT, 112, 132, 5, 1),
            (PRIMARY, OTHER_CLIENT, 112, 132, 5, 1),
        )
    ]

    print(f"""{make_results(events)}
| eval _time=relative_time(now(), "-1h@h")+offset, _raw=payload
| {detection.rstrip()}
| {summary.strip()}
| eval first_offset=first_failure-relative_time(now(), "-1h@h"),
       last_offset=last_failure-relative_time(now(), "-1h@h")
| append [ {make_results(expected)} ]
| stats count(peak_2m) AS matching_rows max(last_offset) AS actual_last max(peak_2m) AS actual_peak max(matching_windows) AS actual_windows max(expected_last) AS expected_last max(expected_peak) AS expected_peak max(expected_windows) AS expected_windows by host Account_Name Client_Address first_offset
| eval status=if(matching_rows=1 AND isnotnull(expected_peak) AND actual_peak=expected_peak AND actual_last=expected_last AND actual_windows=expected_windows, "PASS", "FAIL")
| table host Client_Address first_offset actual_last expected_peak actual_peak actual_windows status
| sort host Client_Address first_offset""")


if __name__ == "__main__":
    main()
