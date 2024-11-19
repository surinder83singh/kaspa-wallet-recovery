use serde::{Deserialize, Serialize};
use std::{fs::{self, File}, io::{Write, BufWriter}};
use serde_json;
use crate::config::*;
use crate::{HmacSha512, Error, Mac, ToHex};
use std::sync::{Arc, Mutex};
use std::collections::HashSet;

// Enum definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WordChecked {
    All,
    None,
    Words(HashSet<String>),
}

// Struct definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cache {
    indexes: Arc<Mutex<Vec<WordChecked>>>,

    #[serde(skip)]
    file: String
}
impl Default for Cache {
    fn default() -> Self {
        Cache{
            indexes: Arc::new(Mutex::new(vec![WordChecked::None; 12])),
            file: String::new()
        } 
    }
}

impl Cache {
    pub fn load()-> Result<Cache, Error>{
        let hmac: HmacSha512 = HmacSha512::new_from_slice(format!("kaspa-wallet-recovery-{}-", MNEMONIC).as_bytes()).map_err(kaspa_bip32::Error::Hmac)?;
        let hash = hmac.finalize().into_bytes().to_vec().to_hex().split_off(100);
        let file_path = format!("cache/{}.json", hash);
        fs::create_dir_all("cache").expect("could not create cache dir.");
        let mut c = read_json(&file_path).unwrap_or_default();
        c.file = file_path;
        Ok(c)
    }

    pub fn is_checked(&self, index: usize, word: &String)->bool{
        match self.indexes.lock().unwrap().get(index){
            Some(c)=>{
                match c {
                    WordChecked::All=>true,
                    WordChecked::None=>false,
                    WordChecked::Words(list)=>{
                        list.contains(word)
                    }

                }
            }
            None=>false
        }
    }



    pub fn mark_checked(&self, index: usize, word: &str){
        let insert = match self.indexes.lock().unwrap().get_mut(index){
            Some(c)=>{
                match c {
                    WordChecked::All=>false,
                    WordChecked::None=>true,
                    WordChecked::Words(list)=>{
                        list.insert(word.into());
                        false
                    }

                }
            }
            None=>true
        };
        if insert {
            self.indexes.lock().unwrap().insert(index, WordChecked::Words([word.to_string()].into()))
        }
    }

    pub fn mark_all(&self, index: usize, all_words: &Vec<&str>){
        let insert = match self.indexes.lock().unwrap().get(index){
            Some(c)=>{
                match c {
                    WordChecked::All=>false,
                    WordChecked::None=>false,
                    WordChecked::Words(list)=>{
                        all_words.iter().all(|word| list.contains(*word))
                    }

                }
            }
            None=>false
        };

        if insert {
            self.indexes.lock().unwrap().insert(index, WordChecked::All);
            self.save();
        } 
    }

    // pub fn mark_clear(&mut self, index: usize){
    //     self.indexes.insert(index, WordChecked::None); 
    // }

    pub fn save(&self){
        write_json(&self.file, self).map_err(|err|{
            println!("write_json failed : {:?}", err)
        }).ok();
    }

}


// Read from JSON file
fn read_json(file_path: &str) -> Result<Cache, Box<dyn std::error::Error>> {
    let json_str = fs::read_to_string(file_path)?;
    let cache: Cache = serde_json::from_str(&json_str)?;
    Ok(cache)
}

// Write to JSON file
fn write_json(file_path: &str, cache: &Cache) -> Result<(), Box<dyn std::error::Error>> {
    let json_str = serde_json::to_string(cache)?;
    let file = File::create(file_path)?;
    let mut buf_writer = BufWriter::new(file);
    buf_writer.write_all(json_str.as_bytes())?;
    Ok(())
}