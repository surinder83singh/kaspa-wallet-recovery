

use kaspa_wallet_keys::{error::Error, derivation::gen0::{WalletDerivationManagerV0, PubkeyDerivationManagerV0}};//, derivation::traits::WalletDerivationManagerTrait};
use kaspa_bip32::{AddressType, ExtendedPrivateKey, Language, Mnemonic, SecretKey/*, Prefix, PublicKey, */};
use kaspa_utils::hex::FromHex;
use kaspa_addresses::{Address,  Prefix as AddressPrefix};
use std::time::SystemTime;
//Version as AddressVersion};
//use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use workflow_core::abortable::Abortable;


fn check_addresses(manger: &PubkeyDerivationManagerV0, target_address: &Address)-> Result<bool, Error>{
    // derive 100 addresses
    let keyes = manger.derive_pubkey_range(0..100)?;
    for key in keyes{
        let address = PubkeyDerivationManagerV0::create_address(&key, AddressPrefix::Mainnet, false)?;
        if target_address == &address {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_wallet(mnemonic: Mnemonic, target_address: &Address) -> Result<bool, Error>{
    let seed = mnemonic.create_seed(None);
    let seed_bytes = Vec::<u8>::from_hex(seed.as_str()).map_err(|_| Error::Custom("Invalid seed".into()))?;

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

    let (private_key, attrs) = WalletDerivationManagerV0::derive_extended_key_from_master_key(xprv, false, 0)?;

    let receive_wallet = WalletDerivationManagerV0::create_pubkey_manager(&private_key, AddressType::Receive, &attrs)?;
    if check_addresses(&receive_wallet, &target_address)?{
        return Ok(true);
    }
    let change_wallet = WalletDerivationManagerV0::create_pubkey_manager(&private_key, AddressType::Change, &attrs)?;
    if check_addresses(&change_wallet, &target_address)?{
        return Ok(true);
    }
    Ok(false)
}



fn main() -> Result<(), Error>{
    let target_address = Arc::new(Address::try_from("kaspa:qq6870ykcr0rk2w3hwqkzrqltl02xngcn3dklnd79p9kusl5zpptwscarjudw").unwrap());
    let wallet_mnemonic = "step buyer hidden project narrow foot depart alter glass pumpkin orchard oxyge";
    
    const USE_2_WORDS: bool = true;
    
    if USE_2_WORDS {
        two_words(wallet_mnemonic, &target_address)?;
    }else{
        one_word(wallet_mnemonic, &target_address)?;
    }
    
    Ok(())
}
fn two_words(wallet_mnemonic: &'static str, target_address: &Arc<Address>) -> Result<bool, Error>{
    let word_list = Language::English.wordlist().iter().collect::<Vec<_>>();
    let word_list = Arc::new(word_list);
    let abortable = Abortable::new();

    let wallet_mnemonic = wallet_mnemonic.split(" ").collect::<Vec<_>>();
    
    let length = wallet_mnemonic.len();
    let mut handles = vec![];
    for index1 in 0..(length-1) {
        //let mut wallet_mnemonic_clone = wallet_mnemonic.clone();
        //let word_list = word_list.clone();
        let target_address = target_address.clone();
        let abortable = abortable.clone();
        println!("index1: {index1} ================================= ");
        for word1 in word_list.as_ref(){
            let mut wallet_mnemonic_clone = wallet_mnemonic.clone();
            wallet_mnemonic_clone[index1] = *word1;
            let word1 = word1.to_string();
            let word_list = word_list.clone();
            let abortable = abortable.clone();
            let target_address = target_address.clone();
            let handle = thread::spawn(move || -> bool{
                let now = SystemTime::now();
                if abortable.is_aborted(){
                    return false;
                }
                //println!("word1: {word1}: {:?}", now.elapsed());
                //let mut handles = vec![];
                for index2 in (index1+1)..length {
                    //println!("index1: {index1}, index2: {index2}");
                    let mut wallet_mnemonic_clone = wallet_mnemonic_clone.clone();
                    let word_list = word_list.clone();
                    let target_address = target_address.clone();
                    let abortable = abortable.clone();
                    let word1 = word1.clone();
                    //let handle = thread::spawn(move || -> bool{
                        let now = SystemTime::now();
                        for word2 in word_list.as_ref(){
                            if abortable.is_aborted(){
                                return false;
                            }
                            
                            wallet_mnemonic_clone[index2] = *word2;
                            
                            let mnemonic_phrase = wallet_mnemonic_clone.join(" ");
                            // if word1 == "bitter" && word2 == "doll"{
                            //     println!("mnemonic: {mnemonic_phrase}");
                            //     abortable.abort();
                            // }
                            let mnemonic = match Mnemonic::new(&mnemonic_phrase, Language::English) {
                                Ok(mnemonic)=>mnemonic,
                                Err(_err)=>{
                                    //println!("mnemonic error: {:?}, {}", _err, mnemonic_phrase);
                                    continue;
                                }
                            };
                            // println!("=======================\nCreating wallet with: {word1} {word2}");
                            match check_wallet(mnemonic, &target_address){
                                Ok(found)=>{
                                    if found {
                                        println!("FOUND: {mnemonic_phrase}");
                                        abortable.abort();
                                        return true;
                                    }
                                }
                                Err(err)=>{
                                    println!("Error: {:?}", err);
                                }
                                
                            }
                        }
                        println!("index1: {index1} {word1} {index2} finished in: {:?}", now.elapsed());
                        //false
                    //});
                    //handles.push(handle);
                }

                
                // for handle in handles {
                //     handle.join().unwrap();
                // }

                println!("index1: {index1} finished in: {:?}", now.elapsed());

                
                false
            });
            handles.push(handle);
        }
    }

    println!("handles: {}", handles.len());

    for handle in handles {
        handle.join().unwrap();
    }
    

   Ok(false)
}

fn one_word(wallet_mnemonic: &'static str, target_address: &Arc<Address>) -> Result<bool, Error>{
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
        let handle = thread::spawn(move || -> bool{
            println!("index1: {index1}");
            for word1 in word_list.as_ref(){
                wallet_mnemonic_clone[index1] = *word1;
                if abortable.is_aborted(){
                    return false;
                }
                println!("index1: {index1} word1: {word1}");
                
                let mnemonic_phrase = wallet_mnemonic_clone.join(" ");
                // if word1 == "bitter" && word2 == "doll"{
                //     println!("mnemonic: {mnemonic_phrase}");
                //     abortable.abort();
                // }
                let mnemonic = match Mnemonic::new(&mnemonic_phrase, Language::English) {
                    Ok(mnemonic)=>mnemonic,
                    Err(_err)=>{
                        //println!("mnemonic error: {:?}, {}", _err, mnemonic_phrase);
                        continue;
                    }
                };
                // println!("=======================\nCreating wallet with: {word1} {word2}");
                match check_wallet(mnemonic, &target_address){
                    Ok(found)=>{
                        if found {
                            println!("FOUND: {mnemonic_phrase}");
                            abortable.abort();
                            return true;
                        }
                    }
                    Err(err)=>{
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
            return Ok(true)
        }
    }
    

   Ok(false)
}
