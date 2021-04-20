use crate::*;
use std::cell::RefCell;

use crate::Config;
use sp_runtime::Perbill;
use sp_staking::SessionIndex;
use pallet_session::historical as pallet_session_historical;
use sp_runtime::testing::{Header, UintAuthorityId, TestXt};
use sp_runtime::traits::{IdentityLookup, BlakeTwo256, ConvertInto};
use sp_core::H256;
use frame_support::parameter_types;
use crate as verifier;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;


frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
		Historical: pallet_session_historical::{Pallet},
		Verifier: verifier::{Pallet, Call, Storage, Config<T>, Event<T>, ValidateUnsigned},
	}
);

thread_local! {
	pub static VALIDATORS: RefCell<Option<Vec<u64>>> = RefCell::new(Some(vec![
		1,
		2,
		3,
	]));
}

pub struct TestSessionManager;
impl pallet_session::SessionManager<u64> for TestSessionManager {
	fn new_session(_new_index: SessionIndex) -> Option<Vec<u64>> {
		VALIDATORS.with(|l| l.borrow_mut().take())
	}
	fn end_session(_: SessionIndex) {}
	fn start_session(_: SessionIndex) {}
}

/// An extrinsic type used for tests.
pub type Extrinsic = TestXt<Call, ()>;
type IdentificationTuple = (u64, u64);


parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub BlockWeights: frame_system::limits::BlockWeights =
		frame_system::limits::BlockWeights::simple_max(1024);
}

impl frame_system::Config for Test {
	type BaseCallFilter = ();
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type Origin = Origin;
	type Index = u64;
	type BlockNumber = u64;
	type Call = Call;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = Event;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
}

parameter_types! {
	pub const Period: u64 = 1;
	pub const Offset: u64 = 0;
}

parameter_types! {
	pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(33);
}

impl pallet_session::Config for Test {
	type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
	type SessionManager = TestSessionManager;
	type SessionHandler = (Verifier, );
	type ValidatorId = u64;
	type ValidatorIdOf = ConvertInto;
	type Keys = UintAuthorityId;
	type Event = Event;
	type DisabledValidatorsThreshold = DisabledValidatorsThreshold;
	type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
	type WeightInfo = ();
}

impl pallet_session::historical::Config for Test {
	type FullIdentification = u64;
	type FullIdentificationOf = ConvertInto;
}

parameter_types! {
	pub const UnsignedPriority: u64 = 1 << 20;
	pub const StoragePeriod: u64 = 20;
}

impl Config for Test {
	type Event = Event;
	type AuthorityId = UintAuthorityId;
	type ValidatorSet = Historical;
	type StorePeriod = StoragePeriod;
	type UnsignedPriority = UnsignedPriority;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test where
	Call: From<LocalCall>,
{
	type OverarchingCall = Call;
	type Extrinsic = Extrinsic;
}



pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::default()
		.build_storage::<Test>()
		.unwrap();
	t.into()
}


pub fn built_in_verifiers() -> Vec<UintAuthorityId> {
	Session::validators().into_iter().map(UintAuthorityId).collect()
}

pub fn advance_session() {
	let now = System::block_number().max(1);
	System::set_block_number(now + 1);
	Session::rotate_session();
	let keys = built_in_verifiers();
	Verifier::set_keys(&keys);
	assert_eq!(Session::current_index(), (now / Period::get()) as u32);
	assert_eq!(Session::validators().len(), Verifier::keys().len()); 
}



pub fn new_proof() -> std::io::Result<Vec<u8>> {
	let mut buf = Vec::new();
	let mut f = std::fs::File::open("proof.txt")?;
	use std::io::Read;
	f.read_to_end(&mut buf)?;
	Ok(buf)
}