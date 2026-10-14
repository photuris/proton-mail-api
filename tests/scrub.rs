//! Offline tests for the fixture scrubber in `support/scrub.rs`.

#[path = "support/scrub.rs"]
mod scrub;

use scrub::Scrubber;
use serde_json::{Map, Value, json};

/// A fresh scrubber's output for `value`.
fn scrubbed(value: Value) -> Value {
    Scrubber::new().scrub(&value)
}

/// A unique marker string; remembered so the test can search for it.
fn mark(markers: &mut Vec<String>, name: &str) -> String {
    let m = format!("Marker{name}7q");

    markers.push(m.clone());
    m
}

#[test]
fn ids_map_consistently_and_only_system_ids_pass_through() {
    let mut s = Scrubber::new();

    let out = s.scrub(&json!({
        "ID": "abc",
        "AddressID": "abc",
        "LabelIDs": ["abc", "0", "6"],
    }));

    assert_eq!(out["ID"], "id-1");
    assert_eq!(out["AddressID"], "id-1");
    assert_eq!(out["LabelIDs"], json!(["id-1", "0", "6"]));

    let out = s.scrub(&json!({ "LabelIDs": ["16", "", "x"] }));

    assert_eq!(out["LabelIDs"], json!(["16", "", "id-2"]));

    let label = s.scrub(&json!({ "ID": "6", "Name": "n", "Color": "#7272a7" }));

    assert_eq!(label["ID"], "6");

    let out = s.scrub(&json!({ "ExternalID": "6", "AddressID": "6" }));

    assert_ne!(out["ExternalID"], "6");
    assert!(out["ExternalID"].as_str().unwrap().starts_with("id-"));
    assert_eq!(out["ExternalID"], out["AddressID"]);

    let plain = s.scrub(&json!({ "ID": "0" }));

    assert!(plain["ID"].as_str().unwrap().starts_with("id-"));

    let plain = s.scrub(&json!({ "ID": "11", "ParentID": "123", "LabelID": "11" }));

    assert!(plain["ID"].as_str().unwrap().starts_with("id-"));
    assert!(plain["ParentID"].as_str().unwrap().starts_with("id-"));
    assert_eq!(plain["ID"], plain["LabelID"]);

    let out = s.scrub(&json!({ "LabelIDs": ["11", "123"] }));

    assert_eq!(out["LabelIDs"][0], plain["ID"]);
    assert_eq!(out["LabelIDs"][1], plain["ParentID"]);
    assert_eq!(s.scrub(&json!({ "ID": "" }))["ID"], "");
    assert_eq!(scrubbed(json!({ "ID": "zzz" }))["ID"], "id-1");
}

#[test]
fn id_arrays_truncate_before_mapping() {
    let mut s = Scrubber::new();

    let out = s.scrub(&json!({ "LabelIDs": ["a", "b", "c", "d", "e"] }));

    assert_eq!(out["LabelIDs"], json!(["id-1", "id-2", "id-3"]));
    assert_eq!(s.scrub(&json!({ "ID": "zzz" }))["ID"], "id-4");
}

#[test]
fn emails_map_consistently_and_hide_local_part() {
    let mut s = Scrubber::new();

    let out = s.scrub(&json!({
        "Email": "Alice.Smith@Corp.example",
        "Address": "Alice.Smith@Corp.example",
        "Other": { "Email": "bob@x.test", "Address": "" },
    }));

    assert_eq!(out["Email"], "user1@example.invalid");
    assert_eq!(out["Address"], "user1@example.invalid");
    assert_eq!(out["Other"]["Email"], "user2@example.invalid");
    assert_eq!(out["Other"]["Address"], "");

    let text = out.to_string();

    for hidden in ["Alice", "Smith", "Corp", "bob", "x.test"] {
        assert!(!text.contains(hidden), "{hidden} survived");
    }
}

#[test]
fn secret_strings_never_survive() {
    let mut markers: Vec<String> = Vec::new();

    let mut root = Map::new();

    for key in [
        "PrivateKey",
        "Token",
        "Signature",
        "Body",
        "KeySalt",
        "Subject",
        "Name",
        "Header",
        "Path",
    ] {
        root.insert(key.to_string(), json!(mark(&mut markers, key)));
    }

    // Keys are alphanumeric so only the wholesale replacement removes them.
    for key in ["Headers", "Details"] {
        let mut inner = Map::new();

        inner.insert(
            mark(&mut markers, &format!("{key}Key")),
            json!(mark(&mut markers, &format!("{key}Val"))),
        );
        root.insert(key.to_string(), Value::Object(inner));
    }

    root.insert(
        "List".to_string(),
        json!([mark(&mut markers, "l1"), mark(&mut markers, "l2")]),
    );
    root.insert(
        "A".to_string(),
        json!({ "MIMEType": format!("text/plain; name={}", mark(&mut markers, "mime")) }),
    );
    root.insert(
        "B".to_string(),
        json!({ "MIMEType": "application/marker-alice123" }),
    );
    markers.push("marker-alice123".to_string());
    root.insert("Disposition".to_string(), json!(mark(&mut markers, "disp")));
    root.insert("Color".to_string(), json!(mark(&mut markers, "color")));

    let out = scrubbed(Value::Object(root));

    assert_eq!(out["B"]["MIMEType"], "application/octet-stream");

    let text = out.to_string();

    for m in &markers {
        assert!(!text.contains(m.as_str()), "{m} survived");
    }

    let root_marker = mark(&mut markers, "root");

    assert!(
        !scrubbed(json!(root_marker))
            .to_string()
            .contains("Markerroot")
    );
}

#[test]
fn numbers_default_to_zero_except_listed_keys() {
    let out = scrubbed(json!({
        "Size": 123,
        "Total": 5,
        "UsedSpace": 9,
        "Credit": 7,
        "List": [1, 2],
        "Code": 1000,
        "Flags": 13,
        "Unread": 1,
        "Order": 4,
        "Time": 99,
        "ValidUntil": 5,
    }));

    for key in ["Size", "Total", "UsedSpace", "Credit"] {
        assert_eq!(out[key], 0, "{key}");
    }

    assert_eq!(out["List"], json!([0, 0]));
    assert_eq!(out["Code"], 1000);
    assert_eq!(out["Flags"], 13);
    assert_eq!(out["Unread"], 1);
    assert_eq!(out["Order"], 4);
    assert_eq!(out["Time"], 1_700_000_000);
    assert_eq!(out["ValidUntil"], 1_700_000_000);

    let out =
        scrubbed(json!({ "Big": { "Order": 5_802_348_887_479_i64 }, "Small": { "Order": 3 } }));

    assert_eq!(out["Big"]["Order"], 0);
    assert_eq!(out["Small"]["Order"], 3);
}

#[test]
fn allowlisted_values_keep_only_valid_forms() {
    let out = scrubbed(json!({
        "MIMEType": "text/html",
        "Disposition": "inline",
        "Color": "#7272a7",
        "t": true,
        "f": false,
        "n": null,
        "e": "",
    }));

    assert_eq!(out["MIMEType"], "text/html");
    assert_eq!(out["Disposition"], "inline");
    assert_eq!(out["Color"], "#7272a7");
    assert_eq!(out["t"], true);
    assert_eq!(out["f"], false);
    assert_eq!(out["n"], Value::Null);
    assert_eq!(out["e"], "");

    let out = scrubbed(json!({
        "MIMEType": "application/x-custom",
        "Disposition": "attachment",
    }));

    assert_eq!(out["MIMEType"], "application/octet-stream");
    assert_eq!(out["Disposition"], "attachment");

    for bad in ["#7272a", "#gggggg", "7272a7", "#7272a7f"] {
        assert_eq!(
            scrubbed(json!({ "Color": bad }))["Color"],
            "<scrubbed>",
            "{bad}"
        );
    }

    assert_eq!(
        scrubbed(json!({ "Disposition": "weird" }))["Disposition"],
        "<scrubbed>"
    );
}

#[test]
fn arrays_truncate_to_three() {
    let out = scrubbed(json!([{"a": 1}, {"a": 2}, {"a": 3}, {"a": 4}, {"a": 5}]));

    assert_eq!(out.as_array().unwrap().len(), 3);
}

#[test]
fn unusual_object_keys_are_replaced() {
    let out = scrubbed(json!({
        "a@b.c": 1,
        "X-Alice-123": 2,
        "LabelIDs": [],
        "Snake_case1": "",
        "2FA": true,
    }));
    let keys: Vec<&str> = out
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();

    assert_eq!(keys.len(), 5);

    for kept in ["LabelIDs", "Snake_case1", "2FA"] {
        assert!(keys.contains(&kept), "{kept} was renamed");
    }

    assert_eq!(keys.iter().filter(|k| k.starts_with('k')).count(), 2);
    assert!(!out.to_string().contains("Alice"));

    let out = scrubbed(json!({ "k1": true, "x-y": false }));

    assert_eq!(out, json!({ "k1": true, "k2": false }));
}
