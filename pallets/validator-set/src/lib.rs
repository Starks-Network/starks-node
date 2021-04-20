//! # ValidatorSet Module
//! A module to mock neccesary validator rotating for aura and grandpa
//! without introducing mass dependencies.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]


use sp_std::prelude::*;
use frame_support::pallet;
pub use pallet::*;
use sp_runtime::traits::{Convert, Zero};
use frame_support::traits::{ValidatorSet, ValidatorSetWithIdentification};

#[pallet]
pub mod pallet {
    use frame_support::{
		dispatch::DispatchResult,
		pallet_prelude::*,
	};
	use frame_system::pallet_prelude::*;
	use super::*;

    #[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_session::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    #[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    #[pallet::storage]
    #[pallet::getter(fn validators)]
    pub type Validators<T: Config> = StorageValue<_, Vec<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn flag)]
    pub type Flag<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub validators: Vec<T::AccountId>,
    }

    #[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self { validators: Vec::new() }
		}
	}

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            Pallet::<T>::initialize_validators(&self.validators);
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    #[pallet::metadata(T::AccountId = "AccountId")]
    pub enum Event<T: Config> {
        // New validator added.
		ValidatorAdded(T::AccountId),
		// Validator removed.
		ValidatorRemoved(T::AccountId),
    }

    #[pallet::error]
    pub enum Error<T> {
        NoValidators,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10000)]
        fn add_validator(origin: OriginFor<T>, acc: T::AccountId) -> DispatchResult {
            ensure_root(origin)?;
			let mut validators = Self::validators().ok_or(Error::<T>::NoValidators)?;
			validators.push(acc.clone());
			<Validators<T>>::put(validators);
			// Calling rotate_session to queue the new session keys.
			<pallet_session::Pallet<T>>::rotate_session();
			Self::deposit_event(Event::ValidatorAdded(acc));

			// Triggering rotate session again for the queued keys to take effect.
			Flag::<T>::put(true);
			Ok(())
        }

        #[pallet::weight(10000)]
        fn remove_validators(origin: OriginFor<T>, acc: T::AccountId) -> DispatchResult {
            ensure_root(origin)?;
			let mut validators = Self::validators().ok_or(Error::<T>::NoValidators)?;
			// Assuming that this will be a PoA network for enterprise use-cases, 
			// the validator count may not be too big; the for loop shouldn't be too heavy.
			// In case the validator count is large, we need to find another way.
			for (i, v) in validators.clone().into_iter().enumerate() {
				if v == acc {
					validators.swap_remove(i);
				}
			}
			<Validators<T>>::put(validators);
			// Calling rotate_session to queue the new session keys.
			<pallet_session::Module<T>>::rotate_session();
			Self::deposit_event(Event::ValidatorRemoved(acc));

			// Triggering rotate session again for the queued keys to take effect.
			Flag::<T>::put(true);
			Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    fn initialize_validators(validators: &[T::AccountId]) {
        <Validators<T>>::put(validators)
    }
}

	
/// Indicates to the session module if the session should be rotated.
/// We set this flag to true when we add/remove a validator.
impl<T: Config> pallet_session::ShouldEndSession<T::BlockNumber> for Pallet<T> {
	fn should_end_session(_now: T::BlockNumber) -> bool {
		Self::flag()
	}
}

// /// Provides the new set of validators to the session module when session is being rotated.
impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
	fn new_session(_new_index: u32) -> Option<Vec<T::AccountId>> {
		// Flag is set to false so that the session doesn't keep rotating.
		Flag::<T>::put(false);

		Self::validators()
	}

	fn end_session(_end_index: u32) {}

	fn start_session(_start_index: u32) {}
}

// impl<T: Config> frame_support::traits::EstimateNextSessionRotation<T::BlockNumber> for Pallet<T> {
// 	fn average_session_length() -> T::BlockNumber {
// 		Zero::zero()
// 	}

// 	fn estimate_current_session_progress(now: BlockNumber) -> (Option<Percent>, Weight) {
// 		(None, Zero::zero())
// 	}

// 	fn estimate_next_session_rotation(_: BlockNumber) -> (Option<T::BlockNumber>, Weight) {
// 		(None, Zero::zero())
// 	}
// }

/// Implementation of Convert trait for mapping ValidatorId with AccountId.
/// This is mainly used to map stash and controller keys.
/// In this module, for simplicity, we just return the same AccountId.
pub struct ValidatorOf<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> Convert<T::AccountId, Option<T::AccountId>> for ValidatorOf<T> {
	fn convert(account: T::AccountId) -> Option<T::AccountId> {
		Some(account)
	}
}