use std::collections::{HashMap, HashSet};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand::rngs::StdRng;
use std::vec::Vec;

pub struct CodeObfuscator {
    rng: StdRng,
    junk_code_ratio: f64,
    opaque_predicates: Vec<Box<dyn Fn(u64) -> bool>>,
    control_flow_flattening: bool,
    instruction_substitution: bool,
    dead_code_injection: bool,
    bogus_control_transfers: bool,
    constant_unfolding: bool,
    metamorphic_engine: bool,
    entry_point_mutation: bool,
    code_virtualization: bool,
    anti_disasm_tricks: bool,
    code_encryption: bool,
    section_mutation: bool,
}

impl CodeObfuscator {
    pub fn new() -> Self {
        CodeObfuscator {
            rng: StdRng::from_entropy(),
            junk_code_ratio: 0.4,
            opaque_predicates: Vec::new(),
            control_flow_flattening: true,
            instruction_substitution: true,
            dead_code_injection: true,
            bogus_control_transfers: true,
            constant_unfolding: true,
            metamorphic_engine: true,
            entry_point_mutation: true,
            code_virtualization: true,
            anti_disasm_tricks: true,
            code_encryption: true,
            section_mutation: true,
        }
    }

    pub fn obfuscate(&mut self, binary: &[u8]) -> Vec<u8> {
        let mut protected = binary.to_vec();

        // Apply multiple layers of advanced obfuscation
        if self.entry_point_mutation {
            protected = self.mutate_entry_point(protected);
        }

        if self.code_encryption {
            protected = self.encrypt_code_sections(protected);
        }

        if self.metamorphic_engine {
            protected = self.apply_metamorphic_transformations(protected);
        }

        protected = self.apply_control_flow_flattening(protected);
        protected = self.apply_instruction_substitution(protected);
        protected = self.inject_dead_code(protected);
        protected = self.add_bogus_control_transfers(protected);
        protected = self.unfold_constants(protected);
        protected = self.add_opaque_predicates(protected);

        if self.anti_disasm_tricks {
            protected = self.add_anti_disasm_sequences(protected);
        }

        if self.section_mutation {
            protected = self.mutate_sections(protected);
        }

        if self.code_virtualization {
            protected = self.virtualize_code_sections(protected);
        }

        protected
    }

    fn mutate_entry_point(&mut self, binary: Vec<u8>) -> Vec<u8> {
        let mut mutated = Vec::new();
        let entry_stub = self.generate_entry_point_stub();
        
        // Add decryption stub and jump chain
        mutated.extend(entry_stub);
        for _ in 0..5 {
            let fake_entry = self.generate_fake_entry_point();
            let insert_pos = self.rng.gen_range(0..binary.len());
            mutated.extend_from_slice(&binary[..insert_pos]);
            mutated.extend(fake_entry);
            mutated.extend_from_slice(&binary[insert_pos..]);
        }
        
        mutated.extend(binary);
        mutated
    }

    fn encrypt_code_sections(&mut self, binary: Vec<u8>) -> Vec<u8> {
        let mut encrypted = Vec::new();
        let key = self.generate_encryption_key();
        for chunk in binary.chunks(64) {
            let mut protected_chunk = chunk.to_vec();
            
            // Apply RC4 and XOR encryption at each layer
            protected_chunk = self.rc4_encrypt(&protected_chunk, &key);
            protected_chunk = self.xor_encrypt(&protected_chunk, &key);
            protected_chunk = self.add_decrypt_stub(&protected_chunk);
            
            encrypted.extend(protected_chunk);
        }
        
        encrypted
    }

    fn apply_metamorphic_transformations(&mut self, binary: Vec<u8>) -> Vec<u8> {
        let mut morphed = binary;
        
        for _ in 0..3 {
            morphed = self.reorder_instructions(morphed);
            morphed = self.reassign_registers(morphed);
            morphed = self.substitute_instruction_patterns(morphed);
            morphed = self.add_garbage_code(morphed);
        }
        
        morphed
    }

    fn apply_control_flow_flattening(&mut self, binary: Vec<u8>) -> Vec<u8> {
        let mut flattened = Vec::new();
        let mut dispatch_table = HashMap::new();
        
        // Dispatch table creation
        let mut block_order: Vec<u32> = (0..binary.len() as u32/32).collect();
        block_order.shuffle(&mut self.rng);
        
        // Build the nested dispatch tables
        for (i, chunk) in binary.chunks(32).enumerate() {
            let target = block_order[i];
            let encrypted_chunk = self.encrypt_block(chunk);
            dispatch_table.insert(target, encrypted_chunk);
        }

        // Add the multi-level dispatcher
        flattened.extend(self.build_nested_dispatcher(&dispatch_table));
        
        // Add the state machine transitions
        for block in dispatch_table.values() {
            flattened.extend(self.add_state_transitions(block));
        }
        
        flattened
    }

    fn add_anti_disasm_sequences(&mut self, binary: Vec<u8>) -> Vec<u8> {
        let mut protected = Vec::new();
        
        for chunk in binary.chunks(16) {
            // Add jump islands
            protected.extend(self.generate_jump_islands());
            
            // Add invalid opcodes that decode differently
            protected.extend(self.generate_invalid_opcodes());
            
            // Add original code
            protected.extend_from_slice(chunk);
            
            // Add overlapping instructions
            protected.extend(self.generate_overlapping_instructions());
        }
        
        protected
    }

    // Helper methods
    fn generate_entry_point_stub(&mut self) -> Vec<u8> {
        let mut stub = Vec::new();
        stub.extend(vec![
            0xEB, 0x02,       // Short jump to skip anti-debug
            0xCD, 0x03,       // Int 3 - debug trap
            0xE8, 0x00, 0x00, 0x00, 0x00,  // Call next instruction
            0x58,             // Pop eax - get current address
            0x83, 0xC0, 0x05, // Add 5 to eax
            0xFF, 0xE0        // Indirect jump to calculated address
        ]);
        stub
    }

    fn generate_encryption_key(&mut self) -> Vec<u8> {
        let mut key = Vec::new();
        for _ in 0..32 {
            key.push(self.rng.gen());
        }
        key
    }

    fn rc4_encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut s = [0u8; 256];
        let mut j: u8 = 0;
        let mut result = Vec::with_capacity(data.len());

        // Initialize S-box
        for i in 0..256 {
            s[i] = i as u8;
        }

        // Key scheduling algorithm (KSA)
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        // Pseudo-random generation algorithm (PRGA)
        let mut i: u8 = 0;
        j = 0;
        for &byte in data {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[((s[i as usize].wrapping_add(s[j as usize])) as usize) % 256];
            result.push(byte ^ k);
        }

        result
    }

    fn xor_encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        for (i, b) in data.iter().enumerate() {
            result.push(b ^ key[i % key.len()]);
        }
        result
    }

    fn encrypt_block(&mut self, block: &[u8]) -> Vec<u8> {
        let key = self.generate_encryption_key();
        self.xor_encrypt(block, &key)
    }

    fn build_nested_dispatcher(&self, dispatch_table: &HashMap<u32, Vec<u8>>) -> Vec<u8> {
        let mut dispatcher = Vec::new();
        dispatcher.extend(vec![0xE9, 0x00, 0x00, 0x00, 0x00]); // JMP PLCER
        dispatcher
    }

    fn add_state_transitions(&mut self, block: &[u8]) -> Vec<u8> {
        let mut with_transitions = block.to_vec();
        // Add state transitions between blocks
        with_transitions.extend(vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // IMUL_jump
        with_transitions
    }

    fn generate_jump_islands(&mut self) -> Vec<u8> {
        vec![
            0xEB, 0x05,  // Short jump forward
            0xE8, 0xFF, 0xFF, 0xFF, 0xFF, // Call to invalid address
            0xE9, 0x00, 0x00, 0x00, 0x00  // Jump to next chunk
        ]
    }

    fn generate_invalid_opcodes(&mut self) -> Vec<u8> {
        vec![0xF1, 0xC4, 0xF0, 0x0F, 0xFF] // Invalid/reserved opcodes
    }

    fn generate_overlapping_instructions(&mut self) -> Vec<u8> {
        vec![
            0xEB, 0x02,  // Jump over next bytes
            0x74, 0x04,  // Conditional jump (part of another instruction when jumped over)
            0x75, 0x05   // Another conditional jump
        ]
    }
}
