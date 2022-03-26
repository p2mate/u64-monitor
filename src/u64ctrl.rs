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
use byteorder::{LittleEndian, WriteBytesExt};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path;
use std::sync::{mpsc, Arc, Mutex};
#[derive(PartialEq, Debug, Clone)]
#[allow(dead_code)]
pub enum U64CommandID {
    DMA = 0xFF01,
    DMARun = 0xFF02,
    Keyb = 0xFF03,
    Reset = 0xFF04,
    Wait = 0xFF05,
    DMAWrite = 0xFF06,
    REUWrite = 0xFF07,
    KernalWrite = 0xFF08,
    DMAJump = 0xFF09,
    MountImg = 0xFF0A,
    RunImg = 0xFF0B,
    PowerOff = 0xFF0C,
    RunCRT = 0xFF0D,
    MountImgByPath = 0xFF10,
    RunImgByPath = 0xFF11,
    RunCrtByPath = 0xFF12,
    DMARunByPath = 0xFF13,
    ResetU64 = 0xFF14,
    VICStreamOn = 0xFF20,
    AudioStreamOn = 0xFF21,
    DebugStreamOn = 0xFF22,
    VICStreamOff = 0xFF30,
    AudioStreamOff = 0xFF31,
    DebugStreamOff = 0xFF32,
    LoadSIDCRT = 0xFF71,
    LoadBootCRT = 0xFF72,
    ReadMem = 0xFF74,
    ReadFlash = 0xFF75,
    DebugReg = 0xFF76,
    Flash = 0xFF80,
}

#[derive(Clone, Debug)]
pub struct U64Command {
    cmd: U64CommandID,
    data: Vec<u8>,
}

pub enum U64TraceCtrl {
    On,
    Off,
}

pub enum U64ResetCtrl {
    C64,
    U64,
}

#[derive(Debug)]
pub struct U64CommandTransaction {
    u64command: U64Command,
    reply_channel: Option<mpsc::Sender<Vec<u8>>>,
}
#[derive(Debug, Clone)]
pub struct U64Controller {
    ctrl_socket: Arc<Mutex<TcpStream>>,
}

impl U64Controller {
    pub fn new<A: std::net::ToSocketAddrs>(ctrl_addr: A) -> anyhow::Result<Self> {
        let ctrl_socket = TcpStream::connect(ctrl_addr)?;
        Ok(U64Controller {
            ctrl_socket: Arc::new(Mutex::new(ctrl_socket)),
        })
    }

    pub fn debug_trace_crtl(&self, ctrl: U64TraceCtrl) -> anyhow::Result<()> {
        match ctrl {
            U64TraceCtrl::On => {
                let mut buffer = Vec::new();
                buffer.write_u16::<LittleEndian>(0)?;
                buffer.append(
                    &mut self
                        .ctrl_socket
                        .lock()
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .ip()
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                );
                self.raw_cmd(U64CommandID::DebugStreamOn, &buffer)
            }
            U64TraceCtrl::Off => self.raw_cmd(U64CommandID::DebugStreamOff, &[0u8; 0]),
        }
    }

    pub fn run<P: AsRef<std::path::Path>>(&self, name: P) -> anyhow::Result<()> {
        self.raw_cmd_file(U64CommandID::DMARun, name)
    }

    pub fn raw_cmd_rx(&self, cmd: U64CommandID, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut ctrl_socket = self.ctrl_socket.lock().unwrap();
        let buf = Vec::new();
        let mut buffer = Cursor::new(buf);
        buffer.write_u16::<LittleEndian>(cmd.clone() as u16)?;
        match cmd {
            U64CommandID::MountImg | U64CommandID::RunImg | U64CommandID::RunCRT => {
                buffer.write_u24::<LittleEndian>(data.len() as u32)
            }
            _ => buffer.write_u16::<LittleEndian>(data.len() as u16),
        }
        .unwrap();
        buffer.write(&data)?;
        ctrl_socket.write(&buffer.into_inner()).map(|_| ())?;
        let rx_bytes = match cmd {
            U64CommandID::ReadMem => {
                let mut buf = Vec::with_capacity(0x800000);
                buf.resize(0x800000, 0);
                ctrl_socket.read_exact(&mut buf)?;
                buf
            }
            U64CommandID::DebugReg => {
                let mut buf = Vec::with_capacity(4);
                ctrl_socket.read_exact(&mut buf)?;
                buf
            }
            _ => Vec::new(),
        };
        Ok(rx_bytes)
    }

    pub fn raw_cmd(&self, cmd: U64CommandID, data: &[u8]) -> anyhow::Result<()> {
        let _ = self.raw_cmd_rx(cmd, data)?;
        Ok(())
    }

    pub fn raw_cmd_file<P: AsRef<std::path::Path>>(
        &self,
        cmd: U64CommandID,
        name: P,
    ) -> anyhow::Result<()> {
        let mut buf = Vec::new();
        let mut f = File::open(name)?;
        f.read_to_end(&mut buf)?;
        self.raw_cmd(cmd, &buf)
    }

    pub fn mount<P: AsRef<std::path::Path>>(&self, name: P) -> anyhow::Result<()> {
        self.raw_cmd_file(U64CommandID::MountImg, name)
    }

    pub fn run_image<P: AsRef<std::path::Path>>(&self, name: P) -> anyhow::Result<()> {
        self.raw_cmd_file(U64CommandID::RunImg, name)
    }

    pub fn run_cartridge<P: AsRef<std::path::Path>>(&self, name: P) -> anyhow::Result<()> {
        self.raw_cmd_file(U64CommandID::RunCRT, name)
    }

    pub fn reset(&self, reset_type: U64ResetCtrl) -> anyhow::Result<()> {
        match reset_type {
            U64ResetCtrl::C64 => self.raw_cmd(U64CommandID::Reset, &[0_u8; 0]),
            U64ResetCtrl::U64 => self.raw_cmd(U64CommandID::ResetU64, &[0_u8; 0]),
        }
    }

    pub fn keys(&self, keystrokes: &[u8]) -> anyhow::Result<()> {
        for data in keystrokes.chunks(10) {
            self.raw_cmd(U64CommandID::Keyb, data)?;
        }
        Ok(())
    }

    pub fn dumpmem<T: AsRef<path::Path>>(&self, name: T) -> anyhow::Result<()> {
        let reply = self.raw_cmd_rx(U64CommandID::ReadMem, &[0_u8; 0])?;
        let mut f = File::create(name)?;
        f.write_all(&reply)?;
        Ok(())
    }

    pub fn flash<T: AsRef<str>>(&self, name: T) -> anyhow::Result<()> {
        self.raw_cmd(U64CommandID::Flash, name.as_ref().as_bytes())
    }

    pub fn poweroff(&self) -> anyhow::Result<()> {
        self.raw_cmd(U64CommandID::PowerOff, &[0_u8; 0])
    }

    pub fn get_peer_addr(&self) -> anyhow::Result<SocketAddr> {
        let socket = self.ctrl_socket.lock().unwrap();
        socket.peer_addr().map_err(|e| e.into())
    }

    pub fn mount_img_by_path<T: AsRef<str>>(&self, name: T) -> anyhow::Result<()> {
        self.raw_cmd(U64CommandID::MountImgByPath, name.as_ref().as_bytes())
    }

    pub fn run_img_by_path<T: AsRef<str>>(&self, name: T) -> anyhow::Result<()> {
        self.raw_cmd(U64CommandID::RunImgByPath, name.as_ref().as_bytes())
    }

    pub fn run_crt_by_path<T: AsRef<str>>(&self, name: T) -> anyhow::Result<()> {
        self.raw_cmd(U64CommandID::RunCrtByPath, name.as_ref().as_bytes())
    }
    pub fn run_prg_by_path<T: AsRef<str>>(&self, name: T) -> anyhow::Result<()> {
        self.raw_cmd(U64CommandID::DMARunByPath, name.as_ref().as_bytes())
    }
}
