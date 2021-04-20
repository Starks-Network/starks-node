use core::slice;
use std::convert::TryInto;

use super::*;
use crate::mock::*;
use sp_core::{traits::TaskExecutorExt, testing::TaskExecutor};
use sp_core::offchain::{
	OffchainDbExt,
	OffchainWorkerExt,
	TransactionPoolExt,
	testing::{self as testing, TestOffchainExt, TestTransactionPoolExt},
};
use sp_core::H256;
use frame_support::{dispatch, assert_ok, assert_noop, traits::OnFinalize};
use sp_runtime::{testing::UintAuthorityId, transaction_validity::TransactionValidityError};
use frame_support::traits::OffchainWorker;
use sp_runtime::testing::TestSignature;


#[test]
fn set_key_works() {
	new_test_ext().execute_with(|| {
		advance_session();
		VALIDATORS.with(|l| *l.borrow_mut() = Some(vec![1, 2, 3, 4, 5, 6]));
		assert_eq!(Session::validators(), Vec::<u64>::new());
		// enact the change and buffer another one
		advance_session();

		assert_eq!(Session::current_index(), 2);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

#[test]
fn should_rotate_keys() {
	let mut ext = new_test_ext();
	ext.execute_with( || {
		System::set_block_number(1);
		advance_session();
		assert_eq!(Session::validators(), Vec::<u64>::new());

		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 3]);
		assert_eq!(Verifier::keys(), vec![UintAuthorityId(1), UintAuthorityId(2), UintAuthorityId(3)]);

		VALIDATORS.with(|l| *l.borrow_mut() = Some(vec![1, 2, 3, 4, 5, 6]));
		assert_eq!(Session::validators(), vec![1, 2, 3]);
 	});
}

#[test]
fn should_create_task() {
	let mut ext = new_test_ext();

	ext.execute_with( || {
		let (progam_hash, inputs, outputs, proof_id) = task_params();
		Verifier::create_task(Origin::signed(1), progam_hash, inputs.clone(), outputs.clone(), proof_id.clone());
		assert_eq!(
			Verifier::task_params(&progam_hash),
			TaskInfo {
				proof_id: b"QmSmn1rSSXmu1PyFFTosBtcL2KGzEssetk9MVFYyDHoCGa".to_vec(),
				inputs,
				outputs
			}
		);

		assert_eq!(
			Verifier::ongoing_tasks(&progam_hash),
			Some(Status {
				verifiers: Vec::<u32>::new(),
				ayes: 0,
				nays: 0
			})
		);
	})
}

#[test]
fn should_parse_http_response() {
	let (offchain, offchain_state) = TestOffchainExt::new();
	let mut ext = sp_io::TestExternalities::default();
	
	ext.register_extension(OffchainDbExt::new(offchain.clone()));
	ext.register_extension(OffchainWorkerExt::new(offchain));
	ext.register_extension(TaskExecutorExt::new(TaskExecutor::new()));

	let (program_hash, inputs, outputs, proof_id) = task_params();

	{
		let mut state = offchain_state.write();
		let uri = "https://ipfs.infura.io:5001/api/v0/cat?arg=".to_owned() + sp_std::str::from_utf8(&proof_id[..]).unwrap();
		state.expect_request(testing::PendingRequest {
			method: "GET".into(),
			uri: uri.clone(),
			response: new_proof().ok(),
			sent: true,
			..Default::default()
		});
	}

	ext.execute_with(|| {
		set_key_and_tasks();
		let proof = Verifier::fetch_proof(&program_hash);
		assert_eq!(proof.unwrap(), new_proof().unwrap());
	});
}


#[test]
fn basic_starks_verifier_works() {
	new_test_ext().execute_with(|| {
		// get proof
		let proof = new_proof().unwrap();
		let (program_hash, inputs, outputs, proof_id) = task_params();
		let program_hash = [19, 23, 145, 150, 7, 226, 183, 94, 42, 36, 220, 169, 148, 89, 125, 153, 113, 250, 202, 142, 187, 167, 14, 144, 186, 217, 89, 214, 222, 234, 43, 214];
		let res = sp_starks::starks::verify(&program_hash, &inputs, &outputs, &proof);
		assert!(res.is_ok());
	});
}


#[test]
fn should_send_extrinsic() {
	let (offchain, offchain_state) = TestOffchainExt::new();
	let (pool, pool_state) = TestTransactionPoolExt::new();
	let mut ext = sp_io::TestExternalities::default();
	ext.register_extension(TransactionPoolExt::new(pool));
	ext.register_extension(OffchainDbExt::new(offchain.clone()));
	ext.register_extension(OffchainWorkerExt::new(offchain));

	let (program_hash, inputs, outputs, proof_id) = task_params();
	three_http_request(&mut offchain_state.write());

	ext.execute_with(|| {
		UintAuthorityId::set_all_keys(vec![1, 2, 3]);
		assert_eq!(Verifier::ongoing_tasks(&program_hash), None);
		set_key_and_tasks();
		assert_eq!(Session::validators(), vec![1, 2, 3]);
		assert_eq!(Verifier::keys(), vec![UintAuthorityId(1), UintAuthorityId(2), UintAuthorityId(3)]);
	
		// Offchain worker
		Verifier::offchain_worker(System::block_number());

		// then
		let transaction = pool_state.write().transactions.pop().unwrap();
		// All validators have `0` as their session key, so we generate 2 transactions.
		assert_eq!(pool_state.read().transactions.len(), 2);

		// check the transaction
		let ex: Extrinsic = Decode::decode(&mut &*transaction).unwrap();
		let receipt = match ex.call {
			crate::mock::Call::Verifier(crate::Call::submit_verification(r, ..)) => r,
			e => panic!("Unexpected call: {:?}", e),
		};

		// pop the last one
		assert_eq!(receipt.clone(), VerificationReceipt {
			program_hash: program_hash,
    		passed: true,
    		submit_at: System::block_number(),
    		auth_index: 2,
    		validators_len: 3
		});
		// test ValidateUnsigned
		let signature = UintAuthorityId(3).sign(&receipt.clone().encode()).unwrap();
		let call = crate::Call::submit_verification(receipt.clone(), signature.clone());
		assert_ok!(
			<Verifier as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
				TransactionSource::External,
				&call
			)
		);

		let _ = Verifier::submit_verification(Origin::none(), receipt, signature);

		// check the online status
		let status = Verifier::ongoing_tasks(&program_hash);
		assert_eq!(status, Some(Status {
			verifiers: vec![2],
			ayes: 1,
			nays: 0
		}));


			// then
			let transaction_1 = pool_state.write().transactions.pop().unwrap();
			assert_eq!(pool_state.read().transactions.len(), 1);


		// check the transaction
		let ex: Extrinsic = Decode::decode(&mut &*transaction_1).unwrap();
		let receipt = match ex.call {
			crate::mock::Call::Verifier(crate::Call::submit_verification(r, ..)) => r,
			e => panic!("Unexpected call: {:?}", e),
		};

		// pop the last one
		assert_eq!(receipt.clone(), VerificationReceipt {
			program_hash: program_hash,
    		passed: true,
    		submit_at: System::block_number(),
    		auth_index: 1,
    		validators_len: 3
		});
		// test ValidateUnsigned
		let signature = UintAuthorityId(2).sign(&receipt.clone().encode()).unwrap();
		let call = crate::Call::submit_verification(receipt.clone(), signature.clone());
		assert_ok!(
			<Verifier as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
				TransactionSource::External,
				&call
			)
		);

		let _ = Verifier::submit_verification(Origin::none(), receipt, signature);

		let block_number = System::block_number() + 20;
		// check the online status, should be removed
		let status = Verifier::ongoing_tasks(&program_hash);
		assert_eq!(status, None);
		let settled_task = Verifier::settled_tasks(&block_number, &program_hash);
		assert_eq!(settled_task, true);

		Verifier::on_finalize(block_number);
		
		assert_eq!(Verifier::settled_tasks(&block_number, &program_hash), false);


	});
}

fn set_key_and_tasks() {

	// set keys
	System::set_block_number(1);
	advance_session();
	assert_eq!(Session::validators(), Vec::<u64>::new());

	advance_session();
	assert_eq!(Session::validators(), vec![1, 2, 3]);
	assert_eq!(Verifier::keys(), vec![UintAuthorityId(1), UintAuthorityId(2), UintAuthorityId(3)]);
	// craete task
	let (progam_hash, inputs, outputs, proof_id) = task_params();
	Verifier::create_task(Origin::signed(1), progam_hash.clone(), inputs.clone(), outputs.clone(), proof_id.clone());
}

// return program_hash, inputs, outputs, proof_id
fn task_params() -> (H256, Vec<u128>, Vec<u128>, Vec<u8>) {
	(
		[19, 23, 145, 150, 7, 226, 183, 94, 42, 36, 220, 169, 148, 89, 125, 153, 113, 250, 202, 142, 187, 167, 14, 144, 186, 217, 89, 214, 222, 234, 43, 214].into(),
		vec![1u128, 0u128],
		vec![8u128],
		b"QmSmn1rSSXmu1PyFFTosBtcL2KGzEssetk9MVFYyDHoCGa".to_vec()
	)
}

fn three_http_request(state: &mut testing::OffchainState)  {
	let (program_hash, inputs, outputs, proof_id) = task_params();
	let uri = "https://ipfs.infura.io:5001/api/v0/cat?arg=".to_owned() + sp_std::str::from_utf8(&proof_id[..]).unwrap();
	state.expect_request(testing::PendingRequest {
		method: "GET".into(),
		uri: uri.clone(),
		response: new_proof().ok(),
		sent: true,
		..Default::default()
	});

	state.expect_request(testing::PendingRequest {
		method: "GET".into(),
		uri: uri.clone(),
		response: new_proof().ok(),
		sent: true,
		..Default::default()
	});

	state.expect_request(testing::PendingRequest {
		method: "GET".into(),
		uri: uri.clone(),
		response: new_proof().ok(),
		sent: true,
		..Default::default()
	});
}

fn prepare_submission(
	block_number: u64,
	auth_index: u32,
	id: UintAuthorityId,
	hash: H256,
	validators: Vec<u64>
) -> dispatch::DispatchResult {
	use frame_support::unsigned::ValidateUnsigned;

	let verification_receipt = VerificationReceipt {
		program_hash: hash,
		// when a task is passed or not
		passed: true,
		submit_at: block_number,
		// submitted by who
		auth_index: auth_index,
		validators_len: validators.len() as u32,
	};

	let signature = id.sign(&verification_receipt.encode()).unwrap();
	
	Verifier::pre_dispatch(&crate::Call::submit_verification(verification_receipt.clone(), signature.clone()))
		.map_err(|e| match e {
			TransactionValidityError::Invalid(InvalidTransaction::Custom(INVALID_VALIDATORS_LEN)) =>
				"invalid validators len",
			e @ _ => <&'static str>::from(e),
	})?;

	Verifier::submit_verification(Origin::none(), verification_receipt, signature)
}




 

