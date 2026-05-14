use crate::util;

pub fn fixtures() {
    util::run("tools/channels/generate-fixtures.sh", &[]);
}

pub fn test() {
    fixtures();
    util::run(
        "cargo",
        &[
            "test",
            "-p",
            "fastboop-core",
            "channel_stream::",
            "--",
            "--nocapture",
        ],
    );
    util::run(
        "cargo",
        &[
            "test",
            "-p",
            "fastboop-core",
            "generated_fixtures_match_expected_stream_kinds",
            "--",
            "--nocapture",
        ],
    );
}
