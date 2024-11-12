use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::vec::Vec;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

#[derive(Debug, Clone)]
pub enum VMInstruction {
    Push(u64),
    Pop,
    Dup,
    Swap,
    Add,
    Sub,
    Mul, 
    Div,
    Xor,
    Rol,
    Ror,
    ModExp,
    Jump(usize),
    Call(usize),
    Ret,
    Branch(usize, usize),
    Switch(Vec<(u64, usize)>),
    IndirectJump,
    LoadReg(usize),
    StoreReg(usize),
    ShuffleRegs,
    SpawnVM,
    KillVM,
    MigrateVM(usize),
    GetVMID,
    GetParentVM,
    GetChildVMs,
}

pub struct VMContext {
    id: usize,
    parent_id: Option<usize>,
    stack: Vec<u64>,
    registers: [u64; 64],
    instruction_pointer: usize,
    instructions: Vec<VMInstruction>,
    call_stack: VecDeque<usize>,
    child_vms: Vec<usize>,
    rng: StdRng,
    reg_map: Vec<usize>,
}

impl VMContext {
    pub fn new(id: usize, parent: Option<usize>, instructions: Vec<VMInstruction>) -> Self {
        let mut rng = StdRng::from_entropy();
        let mut reg_map: Vec<usize> = (0..64).collect();
        reg_map.shuffle(&mut rng);
        
        VMContext {
            id,
            parent_id: parent,
            stack: Vec::with_capacity(2048),
            registers: [0; 64],
            instruction_pointer: 0,
            instructions,
            call_stack: VecDeque::new(),
            child_vms: Vec::new(),
            rng,
            reg_map,
        }
    }

    fn map_register(&self, reg: usize) -> usize {
        self.reg_map[reg % 64]
    }

    // Execute the VM Instructions under the new packed binary.
    pub fn execute(&mut self) -> io::Result<()> {
        while self.instruction_pointer < self.instructions.len() {
            match &self.instructions[self.instruction_pointer] {
                VMInstruction::Push(val) => {
                    let obfuscated = val ^ self.rng.gen::<u64>();
                    self.stack.push(obfuscated);
                },
                VMInstruction::Pop => {
                    self.stack.pop().expect("Stack underflow");
                },
                VMInstruction::Dup => {
                    let val = *self.stack.last().expect("Stack empty");
                    self.stack.push(val ^ self.rng.gen::<u64>());
                },
                VMInstruction::Swap => {
                    let len = self.stack.len();
                    if len >= 2 {
                        self.stack.swap(len-1, len-2);
                    }
                },
                VMInstruction::Add => {
                    let b = self.stack.pop().unwrap();
                    let a = self.stack.pop().unwrap();
                    let result = a.wrapping_add(b).rotate_left(self.rng.gen::<u32>() % 64);
                    self.stack.push(result);
                },
                VMInstruction::Sub => {
                    let b = self.stack.pop().unwrap();
                    let a = self.stack.pop().unwrap();
                    let result = a.wrapping_sub(b).rotate_right(self.rng.gen::<u32>() % 64);
                    self.stack.push(result);
                },
                VMInstruction::Mul => {
                    let b = self.stack.pop().unwrap();
                    let a = self.stack.pop().unwrap();
                    let result = a.wrapping_mul(b) ^ self.rng.gen::<u64>();
                    self.stack.push(result);
                },
                VMInstruction::Div => {
                    let b = self.stack.pop().unwrap();
                    let a = self.stack.pop().unwrap();
                    if b != 0 {
                        let result = a.wrapping_div(b).rotate_left(3);
                        self.stack.push(result);
                    }
                },
                VMInstruction::Xor => {
                    let b = self.stack.pop().unwrap();
                    let a = self.stack.pop().unwrap();
                    self.stack.push(a ^ b ^ self.rng.gen::<u64>());
                },
                VMInstruction::Rol => {
                    let bits = self.stack.pop().unwrap() as u32;
                    let val = self.stack.pop().unwrap();
                    self.stack.push(val.rotate_left(bits));
                },
                VMInstruction::Ror => {
                    let bits = self.stack.pop().unwrap() as u32;
                    let val = self.stack.pop().unwrap();
                    self.stack.push(val.rotate_right(bits));
                },
                VMInstruction::ModExp => {
                    let exp = self.stack.pop().unwrap();
                    let base = self.stack.pop().unwrap();
                    let modulus = 0xFFFFFFFFFFFFFFFF;
                    let mut result = 1u64;
                    let mut base = base;
                    let mut exp = exp;
                    while exp > 0 {
                        if exp & 1 == 1 {
                            result = result.wrapping_mul(base) % modulus;
                        }
                        base = base.wrapping_mul(base) % modulus;
                        exp >>= 1;
                    }
                    self.stack.push(result);
                },
                VMInstruction::Jump(addr) => {
                    self.instruction_pointer = (*addr + self.rng.gen::<usize>() % 3 - 1) % self.instructions.len();
                    continue;
                },
                VMInstruction::Call(addr) => {
                    self.call_stack.push_back(self.instruction_pointer + 1);
                    self.instruction_pointer = *addr;
                    continue;
                },
                VMInstruction::Ret => {
                    if let Some(addr) = self.call_stack.pop_back() {
                        self.instruction_pointer = addr;
                        continue;
                    }
                },
                VMInstruction::Branch(addr1, addr2) => {
                    let condition = self.stack.pop().unwrap();
                    self.instruction_pointer = if condition & self.rng.gen::<u64>() != 0 { *addr1 } else { *addr2 };
                    continue;
                },
                VMInstruction::Switch(cases) => {
                    let key = self.stack.pop().unwrap() ^ self.rng.gen::<u64>();
                    if let Some((_, target)) = cases.iter().find(|(val, _)| *val == key) {
                        self.instruction_pointer = *target;
                        continue;
                    }
                },
                VMInstruction::IndirectJump => {
                    let target = self.stack.pop().unwrap() as usize % self.instructions.len();
                    self.instruction_pointer = target;
                    continue;
                },
                VMInstruction::LoadReg(reg) => {
                    let mapped_reg = self.map_register(*reg);
                    self.stack.push(self.registers[mapped_reg] ^ self.rng.gen::<u64>());
                },
                VMInstruction::StoreReg(reg) => {
                    let mapped_reg = self.map_register(*reg);
                    self.registers[mapped_reg] = self.stack.pop().unwrap() ^ self.rng.gen::<u64>();
                },
                VMInstruction::ShuffleRegs => {
                    self.reg_map.shuffle(&mut self.rng);
                },
                VMInstruction::GetVMID => {
                    self.stack.push((self.id as u64) ^ self.rng.gen::<u64>());
                },
                VMInstruction::GetParentVM => {
                    self.stack.push((self.parent_id.unwrap_or(0) as u64) ^ self.rng.gen::<u64>());
                },
                _ => {}
            }
            self.instruction_pointer += 1;
        }
        Ok(())
    }
}

pub struct VMManager {
    vms: HashMap<usize, VMContext>,
    next_vm_id: usize,
    rng: StdRng,
}

impl VMManager {
    pub fn new() -> Self {
        VMManager {
            vms: HashMap::new(),
            next_vm_id: 0,
            rng: StdRng::from_entropy(),
        }
    }

    pub fn create_vm(&mut self, parent: Option<usize>, mut instructions: Vec<VMInstruction>) -> usize {
        let id = self.next_vm_id;
        self.next_vm_id += 1;
        // Insert NOPs into the instructions
        let mut new_instructions = Vec::new();
        for inst in instructions {
            if self.rng.gen_bool(0.2) {
                new_instructions.push(VMInstruction::Nop);
            }
            new_instructions.push(inst);
        }
        
        let vm = VMContext::new(id, parent, new_instructions);
        self.vms.insert(id, vm);
        id
    }

    pub fn execute_vm(&mut self, id: usize) -> io::Result<()> {
        if let Some(vm) = self.vms.get_mut(&id) {
            vm.execute()?;
        }
        Ok(())
    }
}
