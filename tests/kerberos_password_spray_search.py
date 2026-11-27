"""Print a Splunk search that tests Kerberos spray detection."""

import json
from pathlib import Path


SCENARIOS = {
    "many-accounts": 1,
    "one-account": 0,
    "split-address": 0,
    "split-dc": 0,
    "outside-window": 0,
    "wrong-code": 0,
}


def fixture_events():
    for number, scenario in enumerate(SCENARIOS, start=1):
        for index in range(6 if scenario == "many-accounts" else 5):
            address = f"192.0.2.{number}"
            if scenario == "split-address" and index >= 3:
                address = "192.0.2.99"
            if scenario == "many-accounts" and index == 2:
                address = f"::ffff:{address}"
            yield {
                "offset": index * (80 if scenario == "outside-window" else 10),
                "host": "fixture-dc-02" if scenario == "split-dc" and index >= 3 else "fixture-dc-01",
                "Client_Address": address,
                "Account_Name": f"user-{index if scenario != 'one-account' else 0}",
                "Failure_Code": "0x17" if scenario == "wrong-code" and index == 4 else "0x18",
            }


def make_results(rows):
    data = json.dumps(list(rows), separators=(",", ":"))
    return f"| makeresults format=json data={json.dumps(data)}"


def main():
    path = Path(__file__).resolve().parents[1] / "detections" / "kerberos-password-spray.spl"
    _, sep, pipeline = path.read_text(encoding="utf-8").partition("\n| ")
    if not sep:
        raise SystemExit("Expected a pipeline in the detection SPL file.")

    expected = [
        {"scenario": scenario, "Client_Address": f"192.0.2.{number}", "expected": matches}
        for number, (scenario, matches) in enumerate(SCENARIOS.items(), start=1)
    ]

    print(f"""{make_results(fixture_events())}
| eval _time=relative_time(now(), "-1h@h")+offset
| {pipeline.rstrip()}
| eval hit=1
| append [ {make_results(expected)} ]
| stats values(scenario) AS scenario max(expected) AS expected sum(hit) AS actual max(distinct_accounts) AS distinct_accounts by Client_Address
| eval actual=coalesce(actual, 0), scenario=coalesce(scenario, "unexpected-address")
| eval status=if(isnotnull(expected) AND actual=expected AND (expected=0 OR distinct_accounts=5), "PASS", "FAIL")
| table scenario expected actual distinct_accounts status
| sort scenario""")


if __name__ == "__main__":
    main()
