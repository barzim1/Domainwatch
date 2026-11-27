"""Print a Splunk search that tests the privileged-group detection pipeline."""

import json
from pathlib import Path
from xml.sax.saxutils import escape


MEMBER_SID = "S-1-5-21-100-200-300-1100"
ACTOR = "fixture-operator"
CASES = (
    ("4733-local-removal", 4733, "Administrators", "S-1-5-32-544", "USUNIĘTO / SID"),
    ("4756-universal-add", 4756, "Enterprise Admins", "S-1-5-21-100-200-300-519", "DODANO / SID"),
    ("4757-universal-removal", 4757, "Enterprise Admins", "S-1-5-21-100-200-300-519", "USUNIĘTO / SID"),
    ("4732-name-fallback", 4732, "Administrators", None, "DODANO / NAME"),
    ("4732-unlisted-sid", 4732, "Administrators", "S-1-5-21-100-200-300-2500", "BRAK"),
)


def event_xml(group_name, group_sid):
    fields = {
        "TargetUserName": group_name,
        "TargetSid": group_sid,
        "SubjectUserName": ACTOR,
        "MemberSid": MEMBER_SID,
    }
    data = "".join(
        f"<Data Name='{name}'>{escape(value)}</Data>"
        for name, value in fields.items()
        if value is not None
    )
    return f"<Event><EventData>{data}</EventData></Event>"


def spl_cases(values):
    branches = ", ".join(
        f"fixture={index}, {json.dumps(value, ensure_ascii=False)}"
        for index, value in enumerate(values, start=1)
    )
    return f"case({branches})"


def main():
    path = Path(__file__).resolve().parents[1] / "detections" / "privilege-escalation.spl"
    _, sep, pipeline = path.read_text(encoding="utf-8").partition("\n| ")
    if not sep:
        raise SystemExit("Expected a pipeline in the detection SPL file.")

    generate = f"| makeresults count={len(CASES)}\n| streamstats count AS fixture"
    names = spl_cases(case[0] for case in CASES)
    event_ids = spl_cases(case[1] for case in CASES)
    raw = spl_cases(event_xml(case[2], case[3]) for case in CASES)
    expected = spl_cases(case[4] for case in CASES)

    print(f"""{generate}
| eval host={names},
       EventCode={event_ids},
       _raw={raw}
| {pipeline.rstrip()}
| eval actual=action." / ".group_match, seen=1,
       identity_ok=if(actor="{ACTOR}" AND member_identity="{MEMBER_SID}", 1, 0)
| append [
    {generate}
    | eval host={names},
           expected={expected}
    | fields host expected
  ]
| stats values(expected) AS expected values(actual) AS actual sum(seen) AS matches sum(identity_ok) AS correct_identities by host
| eval actual=coalesce(actual, "BRAK"), matches=coalesce(matches, 0), correct_identities=coalesce(correct_identities, 0)
| eval status=if(isnotnull(expected) AND actual=expected AND matches=if(expected="BRAK", 0, 1) AND matches=correct_identities, "PASS", "FAIL")
| rename host AS scenario
| table scenario expected actual matches status
| sort scenario""")


if __name__ == "__main__":
    main()
