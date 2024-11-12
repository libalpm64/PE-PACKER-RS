 use std::io::{self, Write};
use std::path::Path;
use std::fs;
use goblin::pe::PE;
use crate::obfuscation::CodeObfuscator;
use crate::anti_analysis::apply_protections;

pub struct PackerConfig {
    pub input_file: String,
    pub output_file: String,
    pub encryption_enabled: bool,
    pub anti_analysis_enabled: bool,
    pub obfuscation_enabled: bool,
    pub mutation_rounds: u32,
}

impl PackerConfig {
    pub fn new(input: String, output: String) -> Self {
        Self {
            input_file: input,
            output_file: output,
            encryption_enabled: true,
            anti_analysis_enabled: true,
            obfuscation_enabled: true,
            mutation_rounds: 3,
        }
    }

    pub fn pack(&self) -> io::Result<()> {
        println!("Reading input file: {}", self.input_file);
        let input_data = fs::read(&self.input_file)?;
        
        let pe = PE::parse(&input_data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        let text_section = pe.sections
            .iter()
            .find(|s| s.name().unwrap_or("").starts_with(".text"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No .text section found"))?;
        
        let mut code_data = input_data[text_section.pointer_to_raw_data as usize..
                                     (text_section.pointer_to_raw_data + text_section.size_of_raw_data) as usize]
                                     .to_vec();

        if self.anti_analysis_enabled {
            if !apply_protections(&mut code_data) {
                println!("Warning: Some anti-analysis protections couldn't be applied");
            }
        }

        if self.obfuscation_enabled {
            let mut obfuscator = CodeObfuscator::new();
            code_data = obfuscator.obfuscate(&code_data);
        }

        let mut output_data = input_data.clone();
        output_data[text_section.pointer_to_raw_data as usize..
                   (text_section.pointer_to_raw_data + text_section.size_of_raw_data) as usize]
            .copy_from_slice(&code_data);

        fs::write(&self.output_file, output_data)?;
        println!("Protected executable written to: {}", self.output_file);

        Ok(())
    }
}

pub fn run(input: String, output: String) -> io::Result<()> {
    let config = PackerConfig::new(input, output);
    config.pack()
}

