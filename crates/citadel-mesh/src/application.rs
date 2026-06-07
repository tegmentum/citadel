//! Application-level appraisal — report-only (design `application-appraisal.md`,
//! Phase 1).
//!
//! A registered **application** is appraised independently of the platform: its
//! measurement is judged against an [`AppPolicy`] (accepted states per app, the
//! same `FleetArtifactPolicy` vocabulary used for measured-state) and produces a
//! signed [`AppAttestationResult`]. P1 is *report-only*: the result is recorded
//! and gossiped so an external control plane can remediate; it does **not**
//! touch node trust (graded enforcement + escalation are P2/P3).

use serde::{Deserialize, Serialize};

use crate::crypto::{MeshKeypair, MeshPublicKey, Signature};
use crate::id::NodeId;
use crate::reference::{ArtifactIdentity, FleetArtifactPolicy};

/// Identity of a registered application instance.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppId {
    pub name: String,
    /// Optional instance discriminator (e.g. a pod uid); `None` = the app class.
    pub instance: Option<String>,
}

impl AppId {
    pub fn new(name: impl Into<String>) -> Self {
        AppId { name: name.into(), instance: None }
    }
    pub fn instance(name: impl Into<String>, instance: impl Into<String>) -> Self {
        AppId { name: name.into(), instance: Some(instance.into()) }
    }
}

/// A measurement of a registered application presented for appraisal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMeasurement {
    pub app: AppId,
    pub digest: Vec<u8>,
    pub version: Vec<u64>,
    pub role: String,
    /// `true` if this measurement is bound to the platform quote (e.g. IMA into
    /// PCR 10, replay==quote); `false` for a self-reported claim, which is
    /// accepted only as **advisory** (lower confidence).
    pub pcr_bound: bool,
    pub timestamp_tick: u64,
}

/// App-scoped verdict (mirrors the platform [`crate::types::Verdict`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppVerdict {
    Healthy,
    Degraded,
    Failed,
    /// No policy covers this app — cannot judge.
    Unknown,
}

/// Why an app appraisal reached its verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppReasonCode {
    /// Below the version baseline — running but stale (soft).
    AppVersionDeprecated,
    /// The app's role is not authorized for it.
    AppRoleNotAuthorized,
    /// The measured state matches no accepted app state — likely tamper.
    AppMeasurementUnknown,
    /// The measured state matches a revoked/denylisted app state.
    AppMeasurementRevoked,
}

/// One accepted measured state for an app, with its provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEntry {
    pub digest: Vec<u8>,
    pub artifact: ArtifactIdentity,
}

/// The verifier-side policy for registered applications.
#[derive(Clone, Debug, Default)]
pub struct AppPolicy {
    /// Accepted states per app name.
    accepted: std::collections::BTreeMap<String, Vec<AppEntry>>,
    /// Roles each app name may run as (absent = any role allowed).
    allowed_roles: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    /// Channel / version-baseline / denylist gating (shared vocabulary).
    artifact_policy: FleetArtifactPolicy,
    /// Apps whose failure escalates straight to *node* distrust (§5.3).
    critical: std::collections::BTreeSet<String>,
}

impl AppPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a measured state for an app.
    pub fn accept(&mut self, app: impl Into<String>, digest: Vec<u8>, artifact: ArtifactIdentity) {
        self.accepted.entry(app.into()).or_default().push(AppEntry { digest, artifact });
    }

    /// Authorize a role for an app (restricts to the named roles once any set).
    pub fn allow_role(&mut self, app: impl Into<String>, role: impl Into<String>) {
        self.allowed_roles.entry(app.into()).or_default().insert(role.into());
    }

    /// Install the artifact gating policy (channel / baseline / denylist).
    pub fn set_artifact_policy(&mut self, policy: FleetArtifactPolicy) {
        self.artifact_policy = policy;
    }

    /// Mark an app **critical**: its failure escalates straight to node distrust
    /// (§5.3), bypassing the count threshold.
    pub fn mark_critical(&mut self, app: impl Into<String>) {
        self.critical.insert(app.into());
    }

    /// Is `app` marked critical?
    pub fn is_critical(&self, app: &str) -> bool {
        self.critical.contains(app)
    }

    fn role_ok(&self, app: &str, role: &str) -> bool {
        self.allowed_roles.get(app).is_none_or(|roles| roles.contains(role))
    }

    /// Appraise a measurement → (verdict, reasons, confidence). Pure; the node
    /// wraps this into a signed [`AppAttestationResult`].
    pub fn appraise(&self, m: &AppMeasurement) -> (AppVerdict, Vec<AppReasonCode>, f32) {
        let mut reasons = Vec::new();
        if !self.role_ok(&m.app.name, &m.role) {
            reasons.push(AppReasonCode::AppRoleNotAuthorized);
        }

        let known_app = self.accepted.contains_key(&m.app.name);
        let entry = self
            .accepted
            .get(&m.app.name)
            .and_then(|es| es.iter().find(|e| e.digest == m.digest));

        match entry {
            None if !known_app && self.role_ok(&m.app.name, &m.role) => {
                // No policy at all for this app → cannot judge.
                return (AppVerdict::Unknown, reasons, 0.0);
            }
            None => {
                // Policy exists but the measured state matches nothing.
                reasons.push(AppReasonCode::AppMeasurementUnknown);
            }
            Some(e) => {
                if self.artifact_policy.is_denied(&e.artifact) {
                    reasons.push(AppReasonCode::AppMeasurementRevoked);
                } else if self.artifact_policy.below_baseline(&e.artifact) {
                    reasons.push(AppReasonCode::AppVersionDeprecated);
                }
            }
        }

        // A self-reported (non-PCR-bound) measurement is advisory: it can't
        // assert full health.
        let base = if m.pcr_bound { 1.0 } else { 0.5 };
        let hard = reasons.iter().any(|r| {
            matches!(
                r,
                AppReasonCode::AppRoleNotAuthorized
                    | AppReasonCode::AppMeasurementUnknown
                    | AppReasonCode::AppMeasurementRevoked
            )
        });
        let verdict = if hard {
            AppVerdict::Failed
        } else if reasons.contains(&AppReasonCode::AppVersionDeprecated) {
            AppVerdict::Degraded
        } else {
            AppVerdict::Healthy
        };
        let confidence = match verdict {
            AppVerdict::Healthy => base,
            AppVerdict::Degraded => base * 0.5,
            _ => 0.0,
        };
        (verdict, reasons, confidence)
    }
}

/// A verifier's signed appraisal of an application running on `subject`
/// (design §5.1). Recorded in the evidence chain and gossiped — the
/// report-always artifact a control plane consumes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppAttestationResult {
    pub subject: NodeId,
    pub app: AppId,
    pub verdict: AppVerdict,
    pub reason_codes: Vec<AppReasonCode>,
    pub confidence: f32,
    pub verifier: NodeId,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl AppAttestationResult {
    fn signing_bytes(
        subject: &NodeId,
        app: &AppId,
        verdict: AppVerdict,
        reasons: &[AppReasonCode],
        confidence: f32,
        verifier: &NodeId,
        tick: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&(
            "app-attestation-result",
            subject,
            app,
            verdict,
            reasons,
            confidence.to_bits(),
            verifier,
            tick,
        ))
        .expect("serializable")
    }

    /// Appraise `m` (for `subject`) under `policy` and sign the result as
    /// `verifier`.
    pub fn create(
        kp: &MeshKeypair,
        verifier: NodeId,
        subject: NodeId,
        m: &AppMeasurement,
        policy: &AppPolicy,
        tick: u64,
    ) -> Self {
        let (verdict, reason_codes, confidence) = policy.appraise(m);
        let signature = kp.sign(&Self::signing_bytes(
            &subject,
            &m.app,
            verdict,
            &reason_codes,
            confidence,
            &verifier,
            tick,
        ));
        AppAttestationResult {
            subject,
            app: m.app.clone(),
            verdict,
            reason_codes,
            confidence,
            verifier,
            timestamp_tick: tick,
            signature,
        }
    }

    pub fn verify(&self, verifier_pub: &MeshPublicKey) -> bool {
        verifier_pub.verify(
            &Self::signing_bytes(
                &self.subject,
                &self.app,
                self.verdict,
                &self.reason_codes,
                self.confidence,
                &self.verifier,
                self.timestamp_tick,
            ),
            &self.signature,
        )
    }

    /// Content id (for the evidence-chain record).
    pub fn content_id(&self) -> [u8; 32] {
        *blake3::hash(&serde_json::to_vec(self).expect("serializable")).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(version: Vec<u64>) -> ArtifactIdentity {
        ArtifactIdentity {
            component: "billing-api".into(),
            publisher: "acme".into(),
            channel: "prod".into(),
            version,
            build_id: None,
        }
    }

    fn measurement(digest: &[u8], version: Vec<u64>, role: &str) -> AppMeasurement {
        AppMeasurement {
            app: AppId::new("billing-api"),
            digest: digest.to_vec(),
            version,
            role: role.into(),
            pcr_bound: true,
            timestamp_tick: 1,
        }
    }

    #[test]
    fn healthy_when_state_accepted() {
        let mut p = AppPolicy::new();
        p.accept("billing-api", b"v2".to_vec(), artifact(vec![2, 0]));
        let (v, r, c) = p.appraise(&measurement(b"v2", vec![2, 0], "worker"));
        assert_eq!(v, AppVerdict::Healthy);
        assert!(r.is_empty());
        assert_eq!(c, 1.0);
    }

    #[test]
    fn unknown_app_cannot_be_judged() {
        let p = AppPolicy::new();
        let (v, _r, c) = p.appraise(&measurement(b"x", vec![1], "worker"));
        assert_eq!(v, AppVerdict::Unknown);
        assert_eq!(c, 0.0);
    }

    #[test]
    fn unrecognized_state_for_known_app_fails() {
        let mut p = AppPolicy::new();
        p.accept("billing-api", b"v2".to_vec(), artifact(vec![2, 0]));
        let (v, r, _c) = p.appraise(&measurement(b"tampered", vec![2, 0], "worker"));
        assert_eq!(v, AppVerdict::Failed);
        assert!(r.contains(&AppReasonCode::AppMeasurementUnknown));
    }

    #[test]
    fn revoked_state_fails_and_deprecated_degrades() {
        let mut p = AppPolicy::new();
        p.accept("billing-api", b"v1".to_vec(), artifact(vec![1, 0]));
        p.accept("billing-api", b"v2".to_vec(), artifact(vec![2, 0]));
        // Revoke v1, require >= 2.0.
        p.set_artifact_policy(
            FleetArtifactPolicy::new()
                .deny_version("billing-api", vec![1, 0])
                .min_version("billing-api", vec![2, 0]),
        );
        let (v, r, _) = p.appraise(&measurement(b"v1", vec![1, 0], "worker"));
        assert_eq!(v, AppVerdict::Failed);
        assert!(r.contains(&AppReasonCode::AppMeasurementRevoked));

        // A below-baseline-but-not-denied state degrades (deprecated).
        let mut p2 = AppPolicy::new();
        p2.accept("billing-api", b"v1".to_vec(), artifact(vec![1, 0]));
        p2.set_artifact_policy(FleetArtifactPolicy::new().min_version("billing-api", vec![2, 0]));
        let (v2, r2, _) = p2.appraise(&measurement(b"v1", vec![1, 0], "worker"));
        assert_eq!(v2, AppVerdict::Degraded);
        assert!(r2.contains(&AppReasonCode::AppVersionDeprecated));
    }

    #[test]
    fn unauthorized_role_fails() {
        let mut p = AppPolicy::new();
        p.accept("billing-api", b"v2".to_vec(), artifact(vec![2, 0]));
        p.allow_role("billing-api", "worker");
        let (v, r, _) = p.appraise(&measurement(b"v2", vec![2, 0], "edge"));
        assert_eq!(v, AppVerdict::Failed);
        assert!(r.contains(&AppReasonCode::AppRoleNotAuthorized));
    }

    #[test]
    fn self_reported_is_advisory() {
        let mut p = AppPolicy::new();
        p.accept("billing-api", b"v2".to_vec(), artifact(vec![2, 0]));
        let mut m = measurement(b"v2", vec![2, 0], "worker");
        m.pcr_bound = false;
        let (v, _r, c) = p.appraise(&m);
        assert_eq!(v, AppVerdict::Healthy);
        assert_eq!(c, 0.5, "self-reported health is advisory");
    }

    #[test]
    fn result_signs_and_verifies() {
        let mut p = AppPolicy::new();
        p.accept("billing-api", b"v2".to_vec(), artifact(vec![2, 0]));
        let kp = MeshKeypair::from_seed([5u8; 32]);
        let res = AppAttestationResult::create(
            &kp,
            NodeId([2; 32]),
            NodeId([1; 32]),
            &measurement(b"v2", vec![2, 0], "worker"),
            &p,
            7,
        );
        assert_eq!(res.verdict, AppVerdict::Healthy);
        assert!(res.verify(&kp.public()));
        assert!(!res.verify(&MeshKeypair::from_seed([6u8; 32]).public()));
    }
}
