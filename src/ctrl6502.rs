/*
    Copyright 2022 Peter De Schrijver

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
#[derive(PartialEq, Debug)]
pub struct Ctrl6502 {
    rw: Ctrl6502RW,
    nmi: ActiveLow,
    rom: ActiveLow,
    irq: ActiveLow,
    ba: ActiveHigh,
    exrom: ActiveLow,
    game: ActiveLow,
    phi2: ActiveHigh,
}

fn is_bit_set(byte: u8, bitnumber: usize) -> bool {
    assert!(bitnumber < 8);
    let mask = 1 << bitnumber;
    byte & mask == mask
}

impl Ctrl6502 {
    pub fn from_raw_signals(signals: u8) -> Self {
        let rw = is_bit_set(signals, 0).into();
        let nmi = is_bit_set(signals, 1).into();
        let rom = is_bit_set(signals, 2).into();
        let irq = is_bit_set(signals, 3).into();
        let ba = is_bit_set(signals, 4).into();
        let exrom = is_bit_set(signals, 5).into();
        let game = is_bit_set(signals, 6).into();
        let phi2 = is_bit_set(signals, 7).into();
        Ctrl6502 {
            rw,
            nmi,
            rom,
            irq,
            ba,
            exrom,
            game,
            phi2,
        }
    }

    pub fn get_rw(&self) -> Ctrl6502RW {
        self.rw
    }

    pub fn get_nmi(&self) -> ActiveLow {
        self.nmi
    }

    pub fn get_rom(&self) -> ActiveLow {
        self.rom
    }

    pub fn get_irq(&self) -> ActiveLow {
        self.irq
    }

    pub fn get_exrom(&self) -> ActiveLow {
        self.exrom
    }

    pub fn get_game(&self) -> ActiveLow {
        self.game
    }

    pub fn get_phi2(&self) -> ActiveHigh {
        self.phi2
    }

    pub fn get_ba(&self) -> ActiveHigh {
        self.ba
    }
}
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ActiveHigh {
    Off,
    On,
}

impl std::convert::From<bool> for ActiveHigh {
    fn from(b: bool) -> Self {
        if b {
            ActiveHigh::On
        } else {
            ActiveHigh::Off
        }
    }
}

impl ActiveHigh {
    pub fn is_active(&self) -> bool {
        *self == ActiveHigh::On
    }

    pub fn as_vcd_value(&self) -> vcd::Value {
        use vcd::Value::{V0, V1};
        match self {
            ActiveHigh::Off => V0,
            _ => V1,
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ActiveLow {
    Off,
    On,
}
impl std::convert::From<bool> for ActiveLow {
    fn from(b: bool) -> Self {
        if b {
            ActiveLow::Off
        } else {
            ActiveLow::On
        }
    }
}

impl ActiveLow {
    pub fn is_active(&self) -> bool {
        *self == ActiveLow::On
    }

    pub fn as_vcd_value(&self) -> vcd::Value {
        use vcd::Value::{V0, V1};
        match self {
            ActiveLow::On => V0,
            _ => V1,
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Ctrl6502RW {
    R,
    W,
}

impl std::convert::From<bool> for Ctrl6502RW {
    fn from(b: bool) -> Self {
        if b {
            Ctrl6502RW::R
        } else {
            Ctrl6502RW::W
        }
    }
}

impl Ctrl6502RW {
    pub fn is_read(&self) -> bool {
        *self == Ctrl6502RW::R
    }

    pub fn is_write(&self) -> bool {
        !self.is_read()
    }

    pub fn as_vcd_value(&self) -> vcd::Value {
        use vcd::Value::{V0, V1};
        match self {
            Ctrl6502RW::R => V1,
            _ => V0,
        }
    }
}

impl std::fmt::Display for Ctrl6502RW {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Ctrl6502RW::R => write!(dest, "R"),
            Ctrl6502RW::W => write!(dest, "W"),
        }
    }
}
