extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use crate::DeviceProfile;
use crate::device::DeviceHandle;
use crate::fastboot::{
    FastbootProtocolError, FastbootSession, FastbootWire, ProbeError, profile_matches_vid_pid,
};

pub trait FastbootCandidate {
    type Wire: FastbootWire;
    type Error;

    type OpenFuture<'a>: Future<Output = Result<Self::Wire, Self::Error>> + 'a
    where
        Self: 'a;

    fn vid(&self) -> u16;
    fn pid(&self) -> u16;
    fn open<'a>(&'a self) -> Self::OpenFuture<'a>;
}

impl<D> FastbootCandidate for D
where
    D: DeviceHandle,
{
    type Wire = D::FastbootWire;
    type Error = D::OpenFastbootError;
    type OpenFuture<'a>
        = D::OpenFastbootFuture<'a>
    where
        Self: 'a;

    fn vid(&self) -> u16 {
        DeviceHandle::vid(self)
    }

    fn pid(&self) -> u16 {
        DeviceHandle::pid(self)
    }

    fn open<'a>(&'a self) -> Self::OpenFuture<'a> {
        DeviceHandle::open_fastboot(self)
    }
}

#[derive(Debug)]
pub struct ProbeAttempt<WErr> {
    pub profile_id: String,
    pub result: Result<(), ProbeError<FastbootProtocolError<WErr>>>,
}

#[derive(Debug)]
pub struct ProbeCandidateReport<OErr, WErr> {
    pub candidate_index: usize,
    pub vid: u16,
    pub pid: u16,
    pub open_error: Option<OErr>,
    pub attempts: Vec<ProbeAttempt<WErr>>,
}

pub async fn probe_candidates<C>(
    profiles: &[DeviceProfile],
    candidates: &[C],
) -> Vec<ProbeCandidateReport<C::Error, <C::Wire as FastbootWire>::Error>>
where
    C: FastbootCandidate,
{
    let mut reports = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let vid = candidate.vid();
        let pid = candidate.pid();
        let matching: Vec<&DeviceProfile> = profiles
            .iter()
            .filter(|profile| profile_matches_vid_pid(profile, vid, pid))
            .collect();
        if matching.is_empty() {
            continue;
        }

        match candidate.open().await {
            Ok(mut fastboot) => {
                let mut session = FastbootSession::new(&mut fastboot);
                let mut attempts = Vec::new();
                for profile in matching {
                    let result = session.probe_profile(profile).await;
                    attempts.push(ProbeAttempt {
                        profile_id: profile.id.clone(),
                        result,
                    });
                }
                reports.push(ProbeCandidateReport {
                    candidate_index: index,
                    vid,
                    pid,
                    open_error: None,
                    attempts,
                });
            }
            Err(err) => {
                reports.push(ProbeCandidateReport {
                    candidate_index: index,
                    vid,
                    pid,
                    open_error: Some(err),
                    attempts: Vec::new(),
                });
            }
        }
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devpro::{
        AndroidBootImage, AndroidInitrd, AndroidKernel, Boot, BootLimits, BootPayload,
        DeviceProfile, FastbootGetvarEq, FastbootMatch, KernelEncoding, MatchRule, ProbeStep,
        Stage0,
    };
    use crate::fastboot::{FastbootWire, Response};
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockError;

    struct MockWire {
        responses: BTreeMap<String, String>,
        send_calls: usize,
    }

    impl MockWire {
        fn new(responses: BTreeMap<String, String>) -> Self {
            Self {
                responses,
                send_calls: 0,
            }
        }
    }

    impl FastbootWire for MockWire {
        type Error = MockError;
        type SendCommandFuture<'a>
            = core::future::Ready<Result<Response, Self::Error>>
        where
            Self: 'a;
        type SendDataFuture<'a>
            = core::future::Ready<Result<(), Self::Error>>
        where
            Self: 'a;
        type ReadResponseFuture<'a>
            = core::future::Ready<Result<Response, Self::Error>>
        where
            Self: 'a;

        fn send_command<'a>(&'a mut self, cmd: &'a str) -> Self::SendCommandFuture<'a> {
            self.send_calls += 1;
            let payload = if let Some(name) = cmd.strip_prefix("getvar:") {
                self.responses.get(name).cloned().unwrap_or_default()
            } else {
                String::new()
            };
            core::future::ready(Ok(Response {
                status: "OKAY".to_string(),
                payload,
            }))
        }

        fn send_data<'a>(&'a mut self, _data: &'a [u8]) -> Self::SendDataFuture<'a> {
            core::future::ready(Ok(()))
        }

        fn read_response<'a>(&'a mut self) -> Self::ReadResponseFuture<'a> {
            core::future::ready(Ok(Response {
                status: "OKAY".to_string(),
                payload: String::new(),
            }))
        }
    }

    struct MockCandidate {
        vid: u16,
        pid: u16,
        responses: BTreeMap<String, String>,
    }

    impl MockCandidate {
        fn new(vid: u16, pid: u16, responses: BTreeMap<String, String>) -> Self {
            Self {
                vid,
                pid,
                responses,
            }
        }
    }

    impl FastbootCandidate for MockCandidate {
        type Wire = MockWire;
        type Error = MockError;
        type OpenFuture<'a>
            = core::future::Ready<Result<Self::Wire, Self::Error>>
        where
            Self: 'a;

        fn vid(&self) -> u16 {
            self.vid
        }

        fn pid(&self) -> u16 {
            self.pid
        }

        fn open<'a>(&'a self) -> Self::OpenFuture<'a> {
            core::future::ready(Ok(MockWire::new(self.responses.clone())))
        }
    }

    fn dummy_profile(id: &str, vid: u16, pid: u16, probe: Vec<ProbeStep>) -> DeviceProfile {
        DeviceProfile {
            id: id.to_string(),
            display_name: None,
            devicetree_name: "dummy".to_string(),
            r#match: vec![MatchRule {
                fastboot: FastbootMatch { vid, pid },
            }],
            probe,
            boot: Boot {
                fastboot_boot: BootPayload {
                    android_bootimg: AndroidBootImage {
                        header_version: 0,
                        page_size: 4096,
                        base: None,
                        kernel_offset: None,
                        dtb_offset: None,
                        limits: Some(BootLimits {
                            max_kernel_bytes: None,
                            max_initrd_bytes: None,
                            max_total_bytes: None,
                        }),
                        kernel: AndroidKernel {
                            encoding: KernelEncoding::Image,
                        },
                        initrd: Some(AndroidInitrd { compress: None }),
                        cmdline_append: None,
                    },
                },
            },
            stage0: Stage0 {
                kernel_modules: Vec::new(),
                inject_mac: None,
            },
        }
    }

    fn block_on<F: Future>(mut fut: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn no_op(_: *const ()) {}
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(val) => return val,
                Poll::Pending => continue,
            }
        }
    }

    #[test]
    fn session_caches_getvar() {
        let mut responses = BTreeMap::new();
        responses.insert("product".to_string(), "pinephone".to_string());
        let mut wire = MockWire::new(responses);
        let mut session = FastbootSession::new(&mut wire);

        let first = block_on(session.getvar_cached("product")).unwrap();
        let second = block_on(session.getvar_cached("product")).unwrap();

        assert_eq!(first, "pinephone");
        assert_eq!(second, "pinephone");
        assert_eq!(wire.send_calls, 1);
    }

    #[test]
    fn probe_candidates_reports_matches() {
        let mut responses = BTreeMap::new();
        responses.insert("product".to_string(), "pinephone".to_string());
        let candidates = vec![MockCandidate::new(0x1234, 0x5678, responses)];

        let profile_ok = dummy_profile(
            "ok",
            0x1234,
            0x5678,
            vec![ProbeStep::FastbootGetvarEq(FastbootGetvarEq {
                name: "product".to_string(),
                equals: "pinephone".to_string(),
            })],
        );
        let profile_mismatch = dummy_profile(
            "nope",
            0x1234,
            0x5678,
            vec![ProbeStep::FastbootGetvarEq(FastbootGetvarEq {
                name: "product".to_string(),
                equals: "other".to_string(),
            })],
        );
        let profiles = vec![profile_ok, profile_mismatch];

        let reports = block_on(probe_candidates(&profiles, &candidates));
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.attempts.len(), 2);
        let ok = report
            .attempts
            .iter()
            .find(|attempt| attempt.profile_id == "ok")
            .unwrap();
        assert!(ok.result.is_ok());
        let mismatch = report
            .attempts
            .iter()
            .find(|attempt| attempt.profile_id == "nope")
            .unwrap();
        assert!(mismatch.result.is_err());
    }

    #[test]
    fn probe_not_equals_succeeds_when_different() {
        use crate::FastbootGetvarNotEq;
        let mut responses = BTreeMap::new();
        responses.insert("product".to_string(), "pinephone".to_string());
        let candidates = vec![MockCandidate::new(0x1234, 0x5678, responses)];

        let profile = dummy_profile(
            "test",
            0x1234,
            0x5678,
            vec![ProbeStep::FastbootGetvarNotEq(FastbootGetvarNotEq {
                name: "product".to_string(),
                not_equals: "fajita".to_string(),
            })],
        );

        let reports = block_on(probe_candidates(&[profile], &candidates));
        assert_eq!(reports.len(), 1);
        assert!(reports[0].attempts[0].result.is_ok());
    }

    #[test]
    fn probe_not_equals_fails_when_same() {
        use crate::FastbootGetvarNotEq;
        let mut responses = BTreeMap::new();
        responses.insert("product".to_string(), "pinephone".to_string());
        let candidates = vec![MockCandidate::new(0x1234, 0x5678, responses)];

        let profile = dummy_profile(
            "test",
            0x1234,
            0x5678,
            vec![ProbeStep::FastbootGetvarNotEq(FastbootGetvarNotEq {
                name: "product".to_string(),
                not_equals: "pinephone".to_string(),
            })],
        );

        let reports = block_on(probe_candidates(&[profile], &candidates));
        assert_eq!(reports.len(), 1);
        assert!(reports[0].attempts[0].result.is_err());
    }

    #[test]
    fn probe_not_exists_succeeds_when_missing() {
        use crate::{FastbootGetvarNotExists, NotExistsFlag};
        let mut responses = BTreeMap::new();
        responses.insert("product".to_string(), "pinephone".to_string());
        let candidates = vec![MockCandidate::new(0x1234, 0x5678, responses)];

        let profile = dummy_profile(
            "test",
            0x1234,
            0x5678,
            vec![ProbeStep::FastbootGetvarNotExists(
                FastbootGetvarNotExists {
                    name: "parallel-download-flash".to_string(),
                    not_exists: Some(NotExistsFlag),
                },
            )],
        );

        let reports = block_on(probe_candidates(&[profile], &candidates));
        assert_eq!(reports.len(), 1);
        assert!(reports[0].attempts[0].result.is_ok());
    }

    #[test]
    fn probe_not_exists_fails_when_present() {
        use crate::{FastbootGetvarNotExists, NotExistsFlag};
        let mut responses = BTreeMap::new();
        responses.insert("product".to_string(), "pinephone".to_string());
        let candidates = vec![MockCandidate::new(0x1234, 0x5678, responses)];

        let profile = dummy_profile(
            "test",
            0x1234,
            0x5678,
            vec![ProbeStep::FastbootGetvarNotExists(
                FastbootGetvarNotExists {
                    name: "product".to_string(),
                    not_exists: Some(NotExistsFlag),
                },
            )],
        );

        let reports = block_on(probe_candidates(&[profile], &candidates));
        assert_eq!(reports.len(), 1);
        assert!(reports[0].attempts[0].result.is_err());
    }
}
