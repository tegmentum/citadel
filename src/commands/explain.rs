/// Built-in TPM concept explanations.
pub fn run(concept: &str) -> anyhow::Result<()> {
    let text = match concept.to_lowercase().as_str() {
        "pcr" | "pcrs" => PCR_EXPLANATION,
        "policy" | "policies" => POLICY_EXPLANATION,
        "hierarchy" | "hierarchies" => HIERARCHY_EXPLANATION,
        "key" | "keys" => KEY_EXPLANATION,
        "seal" | "sealed" | "sealing" => SEAL_EXPLANATION,
        "attestation" | "attest" | "quote" => ATTESTATION_EXPLANATION,
        "nv" | "nvram" | "nv-index" => NV_EXPLANATION,
        "ek" | "endorsement-key" => EK_EXPLANATION,
        "ak" | "attestation-key" => AK_EXPLANATION,
        "handle" | "handles" => HANDLE_EXPLANATION,
        "session" | "sessions" => SESSION_EXPLANATION,
        "dictionary-attack" | "da" | "lockout" => DA_EXPLANATION,
        _ => {
            eprintln!("unknown concept: '{}'\n", concept);
            eprintln!("available topics:");
            eprintln!("  pcr, policy, hierarchy, key, seal, attestation,");
            eprintln!("  nv, ek, ak, handle, session, dictionary-attack");
            return Ok(());
        }
    };

    println!("{}", text);
    Ok(())
}

const PCR_EXPLANATION: &str = "\
Platform Configuration Registers (PCRs)

PCRs are a set of registers in the TPM that record measurements of the
system's boot and runtime state. Each PCR holds a hash that is extended
(not overwritten) as the system boots, creating a chain of measurements.

Key properties:
  - PCRs can only be extended, never directly written (except by reset)
  - Each PCR bank uses a specific hash algorithm (sha256, sha384, etc.)
  - Typical PCR indices 0-7 measure firmware and boot components
  - PCR 7 commonly reflects Secure Boot state
  - PCRs 8-15 are often used by the OS and applications

Common uses:
  - Seal secrets to specific boot states (disk encryption keys)
  - Attest machine state to remote verifiers
  - Detect unauthorized boot changes

Commands:
  tpm pcr show                    Show current PCR values
  tpm pcr baseline save <name>    Save current state as baseline
  tpm pcr baseline diff <name>    Compare current state to baseline
";

const POLICY_EXPLANATION: &str = "\
TPM Policies

Policies define conditions that must be satisfied before the TPM will
perform an operation (sign, unseal, etc.). They are attached to objects
at creation time and enforced by the TPM hardware.

Policy types:
  - PCR policy: requires specific PCR values (ties operation to boot state)
  - Password/auth: requires a knowledge factor
  - Locality: requires specific TPM command locality
  - Compound: multiple conditions combined (AND logic)

Key properties:
  - Policies are compiled into a digest that is stored with the object
  - The TPM evaluates policies in a session, not the software
  - Policy changes require recreating the object
  - Policy satisfaction is checked at operation time, not creation time

Commands:
  tpm policy create <name> --pcr sha256:7,11
  tpm policy show <name>
  tpm policy explain <name>
";

const HIERARCHY_EXPLANATION: &str = "\
TPM Hierarchies

The TPM organizes objects into four hierarchies, each with its own
authorization and purpose:

  owner       The primary hierarchy for general-purpose keys and objects.
              Most user keys live here. Controlled by the owner auth.

  endorsement Contains the Endorsement Key (EK), which is a unique
              manufacturer-provisioned identity. Used for attestation
              and privacy-sensitive operations.

  platform    Controlled by the platform firmware (BIOS/UEFI).
              Typically not accessible to the OS directly.

  null        A transient hierarchy cleared on every reboot.
              Objects here do not persist across power cycles.

Most operations use the owner hierarchy. The endorsement hierarchy
is important for attestation workflows.
";

const KEY_EXPLANATION: &str = "\
TPM Keys

Keys are the primary objects in a TPM. They are generated inside the
TPM and their private material never leaves the hardware.

Key types:
  - Signing keys: create digital signatures (code signing, attestation)
  - Storage keys: wrap/protect other keys and data
  - Attestation keys (AK): used specifically for TPM quotes

Key properties:
  - Keys exist in a parent-child hierarchy under a primary key
  - Primary keys are derived deterministically from a seed
  - Child keys can be made persistent (survive reboot) or transient
  - Key attributes (fixed-tpm, sign, decrypt) are set at creation

Commands:
  tpm key create <path> --algorithm ecc-p256
  tpm key list
  tpm key show <path>
  tpm key sign <path> --input file.bin
  tpm key export-pub <path>
";

const SEAL_EXPLANATION: &str = "\
Sealing and Unsealing

Sealing encrypts data so it can only be decrypted (unsealed) when
specific conditions are met, typically matching PCR values.

How it works:
  1. Data is sealed with a policy (e.g., PCR 7 and 11 must match)
  2. The TPM encrypts the data and stores it as a sealed blob
  3. To unseal, the current system state must satisfy the policy
  4. If PCRs have changed (different boot), unseal fails

Common uses:
  - Disk encryption keys tied to boot state (LUKS + TPM)
  - Application secrets that require specific platform configuration
  - Configuration data that should only be readable in trusted state

Commands:
  tpm secret seal <name> --pcr sha256:7,11 --input secret.txt
  tpm secret unseal <name>
";

const ATTESTATION_EXPLANATION: &str = "\
Remote Attestation

Attestation allows a remote party to verify the state of a machine
by requesting a TPM quote — a signed statement of PCR values.

How it works:
  1. Verifier sends a nonce (random challenge)
  2. Machine's TPM signs the current PCR values with an Attestation Key
  3. Verifier checks the signature and PCR values against known-good state
  4. If values match, the machine is in a trusted state

Components:
  - Attestation Key (AK): a restricted signing key for quotes
  - Endorsement Key (EK): proves the AK belongs to a genuine TPM
  - Quote: the signed PCR measurement bundle
  - Event log: detailed record of what was measured into each PCR

Commands:
  tpm quote --pcr sha256:0,7,11 --ak attest/main
";

const NV_EXPLANATION: &str = "\
NV (Non-Volatile) Storage

NV indices are small, persistent storage locations in the TPM.
Unlike keys, they store arbitrary data (counters, config, certificates).

Properties:
  - Each NV index has a defined size and access policy
  - Data persists across reboots
  - Access can require authorization
  - Some NV indices are read-only after first write (write-once)
  - NV space is limited (typically a few KB total)

Common uses:
  - Monotonic counters (anti-rollback)
  - Platform certificates
  - Small configuration values
  - Endorsement Key certificates

Commands:
  tpm nv define <name> --size 64
  tpm nv write <name> --input data.bin
  tpm nv read <name>
";

const EK_EXPLANATION: &str = "\
Endorsement Key (EK)

The EK is a unique key provisioned by the TPM manufacturer. It serves
as the TPM's hardware identity.

Properties:
  - Created from the endorsement hierarchy seed
  - Typically RSA 2048 or ECC P-256
  - Private key never leaves the TPM
  - EK certificate is signed by the manufacturer
  - Used to prove a TPM is genuine

The EK is primarily used in attestation enrollment:
  1. A verifier challenges the TPM using the EK public key
  2. The TPM proves it holds the EK private key
  3. This establishes the TPM's authenticity

The EK itself is usually not used for signing — an Attestation Key (AK)
is created and certified against the EK instead.
";

const AK_EXPLANATION: &str = "\
Attestation Key (AK)

An AK is a restricted signing key used specifically for TPM quotes
(remote attestation). It is created under the endorsement or owner
hierarchy and certified against the EK.

Properties:
  - Restricted: can only sign TPM-generated data (quotes, certify)
  - Cannot be used for arbitrary data signing
  - Bound to the TPM — proves quotes come from real hardware
  - Multiple AKs can exist for different purposes

Workflow:
  1. Create an AK
  2. Certify it against the EK (proves it's on a real TPM)
  3. Use the AK to sign quotes for remote verifiers
";

const HANDLE_EXPLANATION: &str = "\
TPM Handles

Handles are numeric references to objects loaded in the TPM. This tool
manages handles automatically so you rarely need to think about them.

Handle types:
  - Transient (0x80xxxxxx): temporary, lost on context flush or reboot
  - Persistent (0x81xxxxxx): survive reboot, limited slots available
  - Session (0x03xxxxxx): auth/policy sessions
  - PCR (0x00000000-0x00000017): PCR indices
  - NV (0x01xxxxxx): NV index handles

This tool maps friendly names (e.g., 'signing/release') to handles
internally. Use `tpm key show <path>` to see the underlying handle.

The TPM has limited capacity for loaded objects and sessions.
This tool manages lifecycle automatically.
";

const SESSION_EXPLANATION: &str = "\
TPM Sessions

Sessions are the TPM's mechanism for authorization and policy evaluation.
They are created before operations and carry auth or policy state.

Session types:
  - HMAC session: proves knowledge of an auth value
  - Policy session: evaluates a policy (PCR checks, etc.)
  - Trial session: computes a policy digest without enforcement

Properties:
  - Sessions consume TPM resources (limited slots)
  - Policy sessions accumulate policy assertions
  - Sessions can be saved/loaded to free slots
  - Each command can use up to 3 sessions

This tool manages sessions automatically. You generally don't need
to create or manage them directly.
";

const DA_EXPLANATION: &str = "\
Dictionary Attack Protection (Lockout)

The TPM protects against brute-force auth attempts using a dictionary
attack counter. After too many failed attempts, the TPM locks out.

How it works:
  - Each failed auth attempt increments a counter
  - After a threshold, operations requiring auth are blocked
  - The counter decreases over time (recovery interval)
  - The lockout auth can reset the counter immediately

Key parameters:
  - Max tries: number of failures before lockout
  - Recovery time: seconds between counter decrements
  - Lockout recovery: seconds to wait after full lockout

Commands:
  tpm doctor    Shows current dictionary attack state
  tpm status    Shows if lockout is active

Warning: repeated failed auth attempts can lock the TPM. This tool
tracks failed attempts and warns before approaching the threshold.
";
