use hmac::Mac;
use kaspa_addresses::{Address, PayloadVec}; //, Prefix as AddressPrefix, Version as AddressVersion};
use kaspa_bip32::{
    secp256k1, secp256k1::PublicKey as PublicKey2, AddressType, ChildNumber, ExtendedKeyAttrs,
    ExtendedPrivateKey, HmacSha512, Language, Mnemonic, PublicKey, SecretKey, SecretKeyExt,
    KEY_SIZE,
};
use kaspa_utils::hex::{FromHex, ToHex};
use kaspa_wallet_keys::{derivation::gen0::WalletDerivationManagerV0, error::Error};
use std::{sync::Arc, sync::Mutex, thread, time::SystemTime};
use workflow_core::abortable::Abortable;
mod cache;
mod config;
use cache::*;
use config::*;

struct PubkeyManager {
    public_key: PublicKey2,
    hmac: HmacSha512,
}
impl PubkeyManager {
    pub fn check_addresses(
        &self,
        indexes: std::ops::Range<u32>,
        target_address: &Address,
    ) -> Result<bool, Error> {
        // let mut address = Address {
        //     prefix: AddressPrefix::Mainnet,
        //     payload: PayloadVec::from_slice(&[]),
        //     version: AddressVersion::PubKey,
        // };
        for index in indexes {
            let key = Self::derive_public_key_child(
                &self.public_key,
                ChildNumber::new(index, true)?,
                self.hmac.clone(),
            )?;
            let payload = PayloadVec::from_slice(&key.to_bytes()[1..]);
            if target_address.payload == payload {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn derive_public_key_child(
        key: &secp256k1::PublicKey,
        child_number: ChildNumber,
        mut hmac: HmacSha512,
    ) -> Result<secp256k1::PublicKey, Error> {
        hmac.update(&child_number.to_bytes());

        let result = hmac.finalize().into_bytes();
        let (child_key, _chain_code) = result.split_at(KEY_SIZE);

        // We should technically loop here if a `secret_key` is zero or overflows
        // the order of the underlying elliptic curve group, incrementing the
        // index, however per "Child key derivation (CKD) functions":
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
        //
        // > "Note: this has probability lower than 1 in 2^127."
        //
        // ...so instead, we simply return an error if this were ever to happen,
        // as the chances of it happening are vanishingly small.
        //let key = key.derive_child(child_key.try_into()?)?;

        Ok(key.derive_child(child_key.try_into()?)?)
    }
}

// fn check_addresses(manger: &PubkeyManager, target_address: &Address)-> Result<bool, Error>{
//     // derive 100 addresses
//     for key in manger.derive_pubkey_range(0..100)?{

//     }
//     Ok(false)
// }

fn check_wallet(mnemonic: &Mnemonic, target_address: &Address) -> Result<bool, Error> {
    //return Ok(false);
    let seed = mnemonic.create_seed(None);
    let seed_bytes =
        Vec::<u8>::from_hex(seed.as_str()).map_err(|_| Error::Custom("Invalid seed".into()))?;

    let xprv = ExtendedPrivateKey::<SecretKey>::new(seed_bytes)?;
    // println!("phrase: {}", mnemonic.phrase());
    // println!("xprv: {}", xprv.to_string(Prefix::XPRV).as_str());
    // let derivation_path = DerivationPath::from_str("m/44'/972/0'")?;
    // let wallet_xprv = xprv.derive_path(&derivation_path)?;

    // // create receive wallet
    // let derivation_path = DerivationPath::from_str("m/0'")?;
    // let receive_wallet_xprv = wallet_xprv.clone().derive_path(&derivation_path)?;
    // if check_addresses(&receive_wallet_xprv, &target_address)?{
    //     return Ok(true);
    // }

    // // create change wallet
    // let derivation_path = DerivationPath::from_str("m/1'")?;
    // let change_wallet_xprv = wallet_xprv.derive_path(&derivation_path)?;
    // if check_addresses(&change_wallet_xprv, &target_address)?{
    //     return Ok(true);
    // }

    let (private_key, attrs) =
        WalletDerivationManagerV0::derive_extended_key_from_master_key(xprv, false, 0)?;

    //let receive_wallet = WalletDerivationManagerV0::create_pubkey_manager(&private_key, AddressType::Receive, &attrs)?;
    let receive_wallet = create_pubkey_manager(&private_key, AddressType::Receive, &attrs);
    if receive_wallet.check_addresses(0..100, target_address)? {
        return Ok(true);
    }
    //let change_wallet = WalletDerivationManagerV0::create_pubkey_manager(&private_key, AddressType::Change, &attrs)?;
    let change_wallet = create_pubkey_manager(&private_key, AddressType::Change, &attrs);
    if change_wallet.check_addresses(0..100, target_address)? {
        return Ok(true);
    }
    Ok(false)
}

fn create_pubkey_manager(
    private_key: &secp256k1::SecretKey,
    address_type: AddressType,
    attrs: &ExtendedKeyAttrs,
) -> PubkeyManager {
    let (private_key, _attrs, hmac) =
        WalletDerivationManagerV0::create_pubkey_manager_data(private_key, address_type, attrs)
            .unwrap();
    // PubkeyDerivationManagerV0::new(
    //     private_key.get_public_key(),
    //     attrs.clone(),
    //     private_key.get_public_key().fingerprint(),
    //     hmac,
    //     0,
    //     false,
    // )
    PubkeyManager {
        public_key: private_key.get_public_key(),
        hmac,
    }
}

fn main() -> Result<(), Error> {
    let target_address = Arc::new(Address::try_from(TARGET_ADDRESS).unwrap());

    let now = SystemTime::now();
    println!("Attempt to fix 1 word in the mnemonic.");
    if one_word(MNEMONIC, &target_address)? {
        //
    } else if FIX_2_WORDS {
        println!("Now attempt to fix up to 2 words in the mnemonic.");
        two_words(MNEMONIC, &target_address)?;
    }
    println!("Finished in {:?}", now.elapsed().unwrap());

    Ok(())
}

fn two_words(wallet_mnemonic: &'static str, target_address: &Arc<Address>) -> Result<bool, Error> {
    let word_list = Language::English.wordlist().iter().collect::<Vec<_>>(); //[0..].to_vec();
    let word_list = Arc::new(word_list);
    let all_words = word_list.clone();
    let word_list_chuncks = word_list
        .chunks(64)
        .map(|a| Arc::new(a.iter().map(|s| String::from(*s)).collect::<Vec<String>>()))
        .collect::<Vec<_>>();

    let abortable = Abortable::new();

    let wallet_mnemonic = wallet_mnemonic.split(" ").collect::<Vec<_>>();

    let length = wallet_mnemonic.len();

    let cache = Cache::load()?;

    let found_mnemonic = Arc::new(Mutex::new(None));
    for index1 in 0..(length - 1) {
        let mut handles = vec![];
        //println!("index1: {index1} ================================= ");
        let now = SystemTime::now();
        for (thread_index, word_list) in word_list_chuncks.clone().into_iter().enumerate() {
            println!(
                "Starting Index-1: {thread_index:>2} {index1}",
                //word_list.join(" ")
            );
            let wallet_mnemonic = wallet_mnemonic.clone();
            let target_address = target_address.clone();
            let abortable = abortable.clone();
            let all_words = all_words.clone();
            let cache = cache.clone();
            let found_mnemonic = found_mnemonic.clone();
            let handle = thread::spawn(move || -> bool {
                if abortable.is_aborted() {
                    return false;
                }
                let now = SystemTime::now();
                let mut wallet_mnemonic_clone = wallet_mnemonic.clone();
                for (i, word1) in word_list.as_ref().iter().enumerate() {
                    if abortable.is_aborted() {
                        return false;
                    }
                    let now = SystemTime::now();
                    if cache.is_checked(index1, word1) {
                        println!(
                            "INDEX: {thread_index:>2} {:>2} | TIME: {:>8.6}s | WORD: {:>4} {:<15} | SKIPPED",
                            index1,
                            now.elapsed().unwrap().as_secs_f64(),
                            i,
                            word1,
                        );
                        continue;
                    }

                    wallet_mnemonic_clone[index1] = word1;

                    for index2 in (index1 + 1)..length {
                        // if abortable.is_aborted(){
                        //     return false;
                        // }
                        //println!("index1: {index1}, index2: {index2}");
                        let old_word = wallet_mnemonic_clone[index2];
                        for word2 in all_words.as_ref() {
                            wallet_mnemonic_clone[index2] = *word2;

                            let mnemonic = match Mnemonic::new(
                                wallet_mnemonic_clone.join(" "),
                                Language::English,
                            ) {
                                Ok(mnemonic) => mnemonic,
                                Err(_err) => {
                                    //println!("mnemonic error: {:?}, {}", _err, mnemonic_phrase);
                                    continue;
                                }
                            };
                            // println!("=======================\nCreating wallet with: {word1} {word2}");
                            match check_wallet(&mnemonic, &target_address) {
                                Ok(found) => {
                                    if found {
                                        println!(
                                            "🎉 Match found,  🔑: {}",
                                            mnemonic.phrase_string()
                                        );
                                        *found_mnemonic.lock().unwrap() =
                                            Some(mnemonic.phrase_string());
                                        abortable.abort();
                                        return true;
                                    }
                                }
                                Err(err) => {
                                    println!("Error: {:?}", err);
                                }
                            }
                        }
                        wallet_mnemonic_clone[index2] = old_word;
                    }

                    //if word1=="pumpkin"{
                    println!(
                        "INDEX: {thread_index:>2} {:>2} | TIME: {:>8.6}s | WORD: {:>4} {:<15}",
                        index1,
                        now.elapsed().unwrap().as_secs_f64(),
                        i,
                        word1
                    );
                    //}
                    cache.mark_checked(index1, word1);
                    //cache.save();
                }

                //cache.save();
                println!(
                    "INDEX: {:>2} {:>2} | FINISHED IN TIME: {:>8.6}s",
                    thread_index,
                    index1,
                    now.elapsed().unwrap().as_secs_f64()
                );
                false
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
        cache.mark_all(index1, &all_words);
        cache.save();
        println!(
            "INDEX {:>2} FINISHED IN {:>8.6}s",
            index1,
            now.elapsed().unwrap().as_secs_f64()
        );
        if let Some(s) = found_mnemonic.lock().unwrap().as_ref() {
            println!("🎉 Match found,  🔑: {s}");
            return Ok(true);
        }
    }

    //println!("handles: {}", handles.len());

    Ok(false)
}

fn one_word(wallet_mnemonic: &'static str, target_address: &Arc<Address>) -> Result<bool, Error> {
    let word_list = Language::English.wordlist().iter().collect::<Vec<_>>();
    let word_list = Arc::new(word_list);
    let abortable = Abortable::new();

    let wallet_mnemonic = wallet_mnemonic.split(" ").collect::<Vec<_>>();

    let length = wallet_mnemonic.len();
    let mut handles = vec![];
    for index1 in 0..length {
        let mut wallet_mnemonic_clone = wallet_mnemonic.clone();
        let word_list = word_list.clone();
        let target_address = target_address.clone();
        let abortable = abortable.clone();
        let handle = thread::spawn(move || -> bool {
            //println!("index1: {index1}");
            for word1 in word_list.as_ref() {
                wallet_mnemonic_clone[index1] = *word1;
                if abortable.is_aborted() {
                    return false;
                }
                println!("INDEX: {:>2} | WORD: {:<15}", index1, word1);

                let mnemonic_phrase = wallet_mnemonic_clone.join(" ");
                // if word1 == "bitter" && word2 == "doll"{
                //     println!("mnemonic: {mnemonic_phrase}");
                //     abortable.abort();
                // }
                let mnemonic = match Mnemonic::new(&mnemonic_phrase, Language::English) {
                    Ok(mnemonic) => mnemonic,
                    Err(_err) => {
                        //println!("mnemonic error: {:?}, {}", _err, mnemonic_phrase);
                        continue;
                    }
                };
                // println!("=======================\nCreating wallet with: {word1} {word2}");
                match check_wallet(&mnemonic, &target_address) {
                    Ok(found) => {
                        if found {
                            println!("🎉 Match found 🔑 :  {mnemonic_phrase}");
                            abortable.abort();
                            return true;
                        }
                    }
                    Err(err) => {
                        println!("Error: {:?}", err);
                    }
                }
            }
            false
        });
        handles.push(handle);
    }

    for handle in handles {
        if handle.join().unwrap() {
            return Ok(true);
        }
    }

    Ok(false)
}
