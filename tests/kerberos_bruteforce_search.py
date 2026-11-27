"""Print a search that checks Kerberos detection with synthetic events."""

import json
from pathlib import Path


OFFSETS = (105, 110, 115, 120, 125)
CLIENT = "192.0.2.10"
EXPECTED = (
    {"Account_Name": "boundary", "expected": 1},
    {"Account_Name": "too-slow", "expected": 0},
    {"Account_Name": "wrong-status", "expected": 0},
    {"Account_Name": "split-dc", "expected": 0},
    {"Account_Name": "split-address", "expected": 0},
)


def fixture_events():
    for scenario in EXPECTED:
        account = scenario["Account_Name"]
        offsets = (0, 30, 60, 90, 125) if account == "too-slow" else OFFSETS
        for index, offset in enumerate(offsets):
            event = {
                "offset": offset,
                "host": "fixture-dc-02" if account == "split-dc" and index >= 3 else "fixture-dc-01",
                "Account_Name": account,
                "Client_Address": "192.0.2.11" if account == "split-address" and index >= 3 else CLIENT,
                "Failure_Code": "0x17" if account == "wrong-status" and index == 4 else "0x18",
            }
            if account == "boundary" and index == 1:
                event["Client_Address"] = f"::ffff:{CLIENT}"
            if account == "boundary" and index == 2:
                event["Failure_Code"] = "24"
            if account == "boundary" and index == 4:
                event = {
                    "offset": offset,
                    "host": event["host"],
                    "payload": (
                        "<Event><EventData>"
                        "<Data Name='TargetUserName'>BOUNDARY</Data>"
                        f"<Data Name='IpAddress'>::ffff:{CLIENT}</Data>"
                        "<Data Name='Status'>0x00000018</Data>"
                        "</EventData></Event>"
                    ),
                }
            yield event


def make_results(rows):
    data = json.dumps(list(rows), separators=(",", ":"))
    return f"| makeresults format=json data={json.dumps(data)}"


def main():
    path = Path(__file__).resolve().parents[1] / "detections" / "kerberos-bruteforce.spl"
    _, separator, pipeline = path.read_text(encoding="utf-8").partition("\n| ")
    if not separator:
        raise SystemExit("Expected a pipeline in the detection SPL file.")

    print(f"""{make_results(fixture_events())}
| eval _time=relative_time(now(), "-1h@h")+offset, _raw=payload
| {pipeline.rstrip()}
| eval hit=1
| append [ {make_results(EXPECTED)} ]
| stats max(expected) AS expected sum(hit) AS actual max(count) AS window_count by Account_Name
| eval actual=coalesce(actual, 0)
| eval status=if(actual=expected AND (expected=0 OR window_count=5), "PASS", "FAIL")
| rename Account_Name AS scenario
| table scenario expected actual window_count status
| sort scenario""")


if __name__ == "__main__":
    main()
