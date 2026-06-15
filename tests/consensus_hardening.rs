use ed25519_dalek::SigningKey;
use serde_json::json;
use stone::blockchain::Block;
use stone::consensus::{
    BlockProposal, ProposerVerificationPolicy, ValidatorInfo, ValidatorSet, VoteMessage, VotePhase,
    VotingRound,
};

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn minimal_block(hash: &str) -> Block {
    serde_json::from_value(json!({
        "index": 1,
        "timestamp": 1,
        "merkle_root": "",
        "data_size": 0,
        "previous_hash": "",
        "hash": hash,
    }))
    .expect("minimal block must deserialize")
}

#[test]
fn strict_policy_rejects_no_validators_configured() {
    let sk = signing_key(1);
    let proposal = BlockProposal::new(minimal_block("h1"), "node-a".to_string(), &sk, 1);
    let vs = ValidatorSet::default();

    assert!(!proposal.verify_proposer(&vs, ProposerVerificationPolicy::Strict));
    assert!(proposal.verify_proposer(
        &vs,
        ProposerVerificationPolicy::AllowNoValidatorsConfigured
    ));
}

#[test]
fn add_pre_vote_rejects_inactive_validator() {
    let sk = signing_key(2);
    let mut vs = ValidatorSet::default();
    let mut vi = ValidatorInfo::new(
        "node-inactive",
        hex::encode(sk.verifying_key().to_bytes()),
    );
    vi.active = false;
    vs.validators.push(vi);

    let vote = VoteMessage::new_with_phase(
        7,
        "block-xyz".to_string(),
        "node-inactive".to_string(),
        true,
        &sk,
        String::new(),
        VotePhase::PreVote,
    );

    let mut round = VotingRound::new(7, "block-xyz".to_string(), "proposer".to_string());
    let err = round
        .add_pre_vote(vote, &vs)
        .expect_err("inactive validator must not cast pre-vote");
    assert!(err.contains("kein aktiver Validator"));
}

#[test]
fn add_pre_commit_rejects_inactive_validator() {
    let sk = signing_key(3);
    let mut vs = ValidatorSet::default();
    let mut vi = ValidatorInfo::new(
        "node-inactive",
        hex::encode(sk.verifying_key().to_bytes()),
    );
    vi.active = false;
    vs.validators.push(vi);

    let vote = VoteMessage::new_with_phase(
        8,
        "block-abc".to_string(),
        "node-inactive".to_string(),
        true,
        &sk,
        String::new(),
        VotePhase::PreCommit,
    );

    let mut round = VotingRound::new(8, "block-abc".to_string(), "proposer".to_string());
    round.advance_to_precommit();

    let err = round
        .add_pre_commit(vote, &vs)
        .expect_err("inactive validator must not cast pre-commit");
    assert!(err.contains("kein aktiver Validator"));
}
