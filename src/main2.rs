

// use kaspa_wallet_keys::{error::Error};
use kaspa_bip32::{Error,  ChildNumber, DerivationPath, ExtendedPrivateKey, Language, Mnemonic, SecretKey};
use kaspa_utils::hex::FromHex;
use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
use std::str::FromStr;

fn check_addresses(xprv: &ExtendedPrivateKey::<SecretKey>, target_address: &Address)-> Result<bool, Error>{
    // derive 100 addresses
    for index in 0..100{
        let xpubkey = xprv.derive_child(ChildNumber::new(index, false)?)?.public_key();
        let payload = xpubkey.public_key().x_only_public_key().0.serialize();
        let address = Address::new(Prefix::Mainnet, AddressVersion::PubKey, &payload);
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

    let derivation_path = DerivationPath::from_str("m/44'/111111'/0'")?;
    let wallet_xprv = xprv.derive_path(&derivation_path)?;

    // create receive wallet
    let derivation_path = DerivationPath::from_str("m/0")?;
    let receive_wallet_xprv = wallet_xprv.clone().derive_path(&derivation_path)?;
    if check_addresses(&receive_wallet_xprv, &target_address)?{
        return Ok(true);
    }

    // create change wallet
    let derivation_path = DerivationPath::from_str("m/1")?;
    let change_wallet_xprv = wallet_xprv.derive_path(&derivation_path)?;
    if check_addresses(&change_wallet_xprv, &target_address)?{
        return Ok(true);
    }

    Ok(false)
}


fn main() -> Result<(), Error>{
    let target_address = Address::try_from("kaspa:qrc2959g0pqda53glnfd238cdnmk24zxzkj8n5x83rkktx4h73dkc5m2z4s4v").unwrap();
    let wallet_mnemonic = "hunt bitte praise lift buyer topic crane leopard uniform network inquiry over grain pass match crush marine strike dol relax fortune trumpet sunny silk".split(" ").collect::<Vec<&str>>();

    let word_list = Language::English.wordlist();
    let length = wallet_mnemonic.len();
    for index1 in 0..length {
        let mut wallet_mnemonic_clone = wallet_mnemonic.clone();
        //println!("==================================");
        println!("index1: {index1}");
        for word1 in word_list.iter(){
            wallet_mnemonic_clone[index1] = word1;
            println!("word1: {word1}");
        
            let mnemonic_phrase = wallet_mnemonic_clone2.join(" ");
            let mnemonic = match Mnemonic::new(&mnemonic_phrase, Language::English) {
                Ok(mnemonic)=>mnemonic,
                Err(_err)=>{
                    //println!("mnemonic error: {:?}", _err);
                    continue;
                }
            };
            println!("=======================\nCreating wallet with: {word1} {word2}");
            match check_wallet(mnemonic, &target_address){
                Ok(found)=>{
                    if found {
                        println!("FOUND: {mnemonic_phrase}");
                        return Ok(());
                    }
                }
                Err(err)=>{
                    println!("Error: {:?}", err);
                }
                
            }

        }
    }
    

    Ok(())
}
