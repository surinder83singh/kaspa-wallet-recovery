

// use kaspa_wallet_keys::{error::Error};
use kaspa_bip32::{ChildNumber, DerivationPath, Error, ExtendedPrivateKey, Language, Mnemonic, Prefix, PublicKey, SecretKey};
use kaspa_utils::hex::FromHex;
use kaspa_addresses::{Address, Prefix as AddressPrefix, Version as AddressVersion};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use workflow_core::abortable::Abortable;


fn check_addresses(xprv: &ExtendedPrivateKey::<SecretKey>, target_address: &Address)-> Result<bool, Error>{
    // derive 100 addresses
    for index in 0..100{
        let xpubkey = xprv.derive_child(ChildNumber::new(index, true)?)?.public_key();
        let payload = &xpubkey.public_key().to_bytes()[1..];//.x_only_public_key().0.serialize();
        let address = Address::new(AddressPrefix::Mainnet, AddressVersion::PubKey, payload);
        if target_address == &address {
            return Ok(true);
        }
        //println!("{index} address: {}", address.to_string());
    }

    Ok(false)
}

fn check_wallet(mnemonic: Mnemonic, target_address: &Address) -> Result<bool, Error>{
    let seed = mnemonic.create_seed(None);
    let seed_bytes = Vec::<u8>::from_hex(seed.as_str()).map_err(|_| Error::String("Invalid seed".into()))?;

    let xprv = ExtendedPrivateKey::<SecretKey>::new(seed_bytes)?;
    println!("phrase: {}", mnemonic.phrase());
    println!("xprv: {}", xprv.to_string(Prefix::KPRV).as_str());
    let derivation_path = DerivationPath::from_str("m/44'/972/0'")?;
    let wallet_xprv = xprv.derive_path(&derivation_path)?;

    // create receive wallet
    let derivation_path = DerivationPath::from_str("m/0'")?;
    let receive_wallet_xprv = wallet_xprv.clone().derive_path(&derivation_path)?;
    if check_addresses(&receive_wallet_xprv, &target_address)?{
        return Ok(true);
    }

    // create change wallet
    let derivation_path = DerivationPath::from_str("m/1'")?;
    let change_wallet_xprv = wallet_xprv.derive_path(&derivation_path)?;
    if check_addresses(&change_wallet_xprv, &target_address)?{
        return Ok(true);
    }

    Ok(false)
}


fn main() -> Result<(), Error>{
    let target_address = Arc::new(Address::try_from("kaspa:qq6870ykcr0rk2w3hwqkzrqltl02xngcn3dklnd79p9kusl5zpptwscarjudw").unwrap());
    let wallet_mnemonic = "step buyer hidden project narrow foot depart alter glass pumpkin orchard oxyge";
    let word_list = Arc::new(Language::English.wordlist().iter().map(String::from).collect::<Vec<_>>());
    //let word_list_chuncks = word_list_root.chunks(200).map(|a|Arc::new(a.into_iter().map(String::from).collect::<Vec<String>>())).collect::<Vec<_>>();
    let abortable = Abortable::new();
    let wallet_mnemonic = wallet_mnemonic.split(" ").map(String::from).collect::<Vec<_>>();
    
    let length = wallet_mnemonic.len();
    let mut handles = vec![];
    for index1 in 0..length {
        let wallet_mnemonic = wallet_mnemonic.clone();
        let word_list = word_list.clone();
        let target_address = target_address.clone();
        let abortable = abortable.clone();
        let handle = thread::spawn(move || -> bool{
            println!("index1: {index1}");
            for word1 in word_list.as_ref(){
                let mut wallet_mnemonic_clone = wallet_mnemonic.clone();
                wallet_mnemonic_clone[index1] = word1.clone();
                //println!("index1: {index1} word1: {word1}");
                for index2 in (index1+1)..length {
                    //println!("index2: {index2}");
                    for word2 in word_list.as_ref(){
                        if abortable.is_aborted(){
                            return false;
                        }
                        let mut wallet_mnemonic_clone2 = wallet_mnemonic_clone.clone();
                        wallet_mnemonic_clone2[index2] = word2.clone();
                        
                        let mnemonic_phrase = wallet_mnemonic_clone2.join(" ");
                        // if word1 == "bitter" && word2 == "doll"{
                        //     println!("mnemonic: {mnemonic_phrase}");
                        //     abortable.abort();
                        // }
                        let mnemonic = match Mnemonic::new(&mnemonic_phrase, Language::English) {
                            Ok(mnemonic)=>mnemonic,
                            Err(_err)=>{
                                //println!("mnemonic error: {:?}", _err);
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
                }

            }
            false
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
    

    Ok(())
}
