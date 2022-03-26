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
mod ctrl6502;
mod u64ctrl;
mod u64ftp;
use byteorder::{LittleEndian, ReadBytesExt};
use clap::ArgMatches;
use crossbeam_channel;
use ctrl6502::Ctrl6502;
use std::io::{BufWriter, Cursor, Error, ErrorKind, Write};
use std::net::{ToSocketAddrs, UdpSocket};
use std::num::Wrapping;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use u64ctrl::{U64Controller, U64ResetCtrl, U64TraceCtrl};

const DEFAULT_ADDRESSES: (u16, u16) = (0xa871, 0xa84b);

#[derive(Debug)]
enum UdpMinionCmd {
    Start(crossbeam_channel::Sender<Vec<u8>>),
    Stop(crossbeam_channel::Sender<Vec<u8>>),
}
#[derive(Debug)]
enum UdpMinionData {
    Data(Vec<u8>),
    End,
}

#[derive(Debug)]
struct UdpMinion {
    cmd_tx: crossbeam_channel::Sender<UdpMinionCmd>,
    request_stop: crossbeam_channel::Sender<()>,
    minion_thread: Option<thread::JoinHandle<anyhow::Result<()>>>,
    udp_rx_thread: thread::JoinHandle<anyhow::Result<()>>,
}

impl UdpMinion {
    fn new() -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:11002")?;
        let (cmd_tx, cmd_rx) = crossbeam_channel::unbounded();
        let (udp_tx, udp_rx) = crossbeam_channel::unbounded();
        let (request_stop, stop_received) = crossbeam_channel::unbounded();
        let udp_rx_thread = thread::spawn(move || {
            loop {
                let mut buf = [0; 1444];
                if let Ok((amt, from)) = socket.recv_from(&mut buf) {
                    if from.port() != 6510 {
                        continue;
                    }
                    let mut msg: Vec<u8> = buf.to_vec();
                    msg.truncate(amt);
                    match udp_tx.send(UdpMinionData::Data(msg)) {
                        Ok(_) => {}
                        _ => break,
                    }
                } else {
                    let _ = udp_tx.send(UdpMinionData::End);
                    break;
                }
            }
            Ok(())
        });

        let minion_thread = thread::spawn(move || {
            let mut udp_fwd: Vec<crossbeam_channel::Sender<Vec<u8>>> = Vec::new();
            loop {
                let mut sel = crossbeam_channel::Select::new();
                let udp_receive = sel.recv(&udp_rx);
                let cmd_receive = sel.recv(&cmd_rx);
                let stop_rx = sel.recv(&stop_received);
                match sel.ready() {
                    i if i == udp_receive => {
                        let m = udp_rx.recv().unwrap();
                        match m {
                            UdpMinionData::Data(msg) => {
                                udp_fwd.retain(|tx| match tx.send(msg.clone()) {
                                    Ok(_) => true,
                                    _ => false,
                                });
                            }
                            UdpMinionData::End => break,
                        };
                    }
                    i if i == cmd_receive => {
                        let cmd = cmd_rx.recv().unwrap();
                        match cmd {
                            UdpMinionCmd::Start(x) => udp_fwd.push(x),
                            UdpMinionCmd::Stop(x) => {
                                if let Some(c) = udp_fwd.iter().position(|y| x.same_channel(y)) {
                                    udp_fwd.remove(c);
                                }
                            }
                        }
                    }
                    i if i == stop_rx => {
                        let _ = stop_received.recv();
                        break;
                    }
                    _ => unreachable!(),
                }
            }
            Ok(())
        });
        Ok(UdpMinion {
            cmd_tx,
            minion_thread: Some(minion_thread),
            udp_rx_thread,
            request_stop,
        })
    }

    fn get_cmd_channel(&self) -> crossbeam_channel::Sender<UdpMinionCmd> {
        self.cmd_tx.clone()
    }

    fn stop(&mut self) {
        let _ = self.request_stop.send(());
        let _ = self.minion_thread.take().unwrap().join();
    }
}

trait Logger {
    fn log_item(&mut self, item: &U64DebugStreamItem, cycles: u64) -> anyhow::Result<()>;
}

struct VCDLogger<W: Write + Send + Sync> {
    handle: vcd::Writer<W>,
    addr: vcd::IdCode,
    data: vcd::IdCode,
    rw: vcd::IdCode,
    nmi: vcd::IdCode,
    rom: vcd::IdCode,
    irq: vcd::IdCode,
    ba: vcd::IdCode,
    exrom: vcd::IdCode,
    game: vcd::IdCode,
    phi2: vcd::IdCode,
}

fn u16_to_vcd(word: u16) -> Vec<vcd::Value> {
    use vcd::Value::{V0, V1};
    (0..16)
        .map(|x| {
            if (word & (1 << (15 - x))) == 0 {
                V0
            } else {
                V1
            }
        })
        .collect::<Vec<_>>()
}

fn u8_to_vcd(word: u8) -> Vec<vcd::Value> {
    use vcd::Value::{V0, V1};
    (0..8)
        .map(|x| if (word & (1 << (7 - x))) == 0 { V0 } else { V1 })
        .collect()
}

impl<T: Write + Send + Sync> Logger for VCDLogger<T> {
    fn log_item(&mut self, item: &U64DebugStreamItem, cycles: u64) -> anyhow::Result<()> {
        self.handle.timestamp(cycles)?;
        self.handle
            .change_vector(self.addr, &u16_to_vcd(item.address))?;
        self.handle
            .change_vector(self.data, &u8_to_vcd(item.data))?;
        self.handle
            .change_scalar(self.rw, item.ctrl_signals.get_rw().as_vcd_value())?;
        self.handle
            .change_scalar(self.nmi, item.ctrl_signals.get_nmi().as_vcd_value())?;
        self.handle
            .change_scalar(self.rom, item.ctrl_signals.get_rom().as_vcd_value())?;
        self.handle
            .change_scalar(self.irq, item.ctrl_signals.get_irq().as_vcd_value())?;
        self.handle
            .change_scalar(self.ba, item.ctrl_signals.get_ba().as_vcd_value())?;
        self.handle
            .change_scalar(self.exrom, item.ctrl_signals.get_exrom().as_vcd_value())?;
        self.handle
            .change_scalar(self.game, item.ctrl_signals.get_game().as_vcd_value())?;
        self.handle
            .change_scalar(self.phi2, item.ctrl_signals.get_phi2().as_vcd_value())?;

        Ok(())
    }
}

impl<T: Write + Send + Sync> VCDLogger<T> {
    fn new(writer: T) -> anyhow::Result<Self> {
        use vcd::{SimulationCommand, Value};
        let mut handle = vcd::Writer::new(writer);
        handle.timescale(1, vcd::TimescaleUnit::US)?;
        handle.add_module("Ultimate64")?;
        let addr = handle.add_wire(16, "Address")?;
        let data = handle.add_wire(8, "Data")?;
        let rw = handle.add_wire(1, "R/W#")?;
        let nmi = handle.add_wire(1, "NMI#")?;
        let rom = handle.add_wire(1, "ROM#")?;
        let irq = handle.add_wire(1, "IRQ#")?;
        let ba = handle.add_wire(1, "BA")?;
        let exrom = handle.add_wire(1, "EXROM#")?;
        let game = handle.add_wire(1, "GAME#")?;
        let phi2 = handle.add_wire(1, "PHI2")?;
        handle.upscope()?;
        handle.enddefinitions()?;
        //  handle.begin(SimulationCommand::Dumpvars)?;
        //  handle.change_scalar(rw, Value::V1)?;
        //  handle.change_scalar(nmi, Value::V1)?;
        //  handle.change_scalar(rom, Value::V1)?;
        //  handle.change_scalar(irq, Value::V1)?;
        //  handle.change_scalar(ba, Value::V0)?;
        //  handle.change_scalar(game, Value::V1)?;
        //  handle.change_scalar(phi2, Value::V0)?;
        //  handle.change_vector(addr, &u16_to_vcd(0))?;
        //  handle.change_vector(data, &u8_to_vcd(0))?;
        //  handle.end()?;

        Ok(VCDLogger {
            handle,
            addr,
            data,
            rw,
            nmi,
            rom,
            irq,
            ba,
            exrom,
            game,
            phi2,
        })
    }
}

struct SimpleLogger {
    handle: Box<dyn Write + Sync + Send>,
}

impl Logger for SimpleLogger {
    fn log_item(&mut self, item: &U64DebugStreamItem, cycles: u64) -> anyhow::Result<()> {
        if item.ctrl_signals.get_phi2().is_active() {
            self.print(format!(
                "{:#010x} {} {:#04x} @ {:#06x}\n",
                cycles,
                item.ctrl_signals.get_rw(),
                item.data,
                item.address,
            ))?;
        }
        Ok(())
    }
}

impl SimpleLogger {
    fn print(&mut self, output: String) -> anyhow::Result<()> {
        self.handle.write_all(output.as_bytes())?;
        self.handle.flush()?;
        Ok(())
    }

    fn new(handle: Box<dyn Write + Send + Sync>) -> anyhow::Result<Self> {
        Ok(SimpleLogger { handle })
    }
}

#[derive(PartialEq, Debug)]
enum TraceState {
    Stop,
    WaitForStart,
    Running,
}

struct LogMinion {
    seq_number: Option<Wrapping<u16>>,
    cycles: u64,
    state: TraceState,
    start_addr: Option<u16>,
    end_addr: Option<u16>,
    logger: Box<dyn Logger + Send + Sync>,
}

impl LogMinion {
    fn new(logger: Box<dyn Logger + Send + Sync>) -> anyhow::Result<Self> {
        Ok(LogMinion {
            seq_number: None,
            cycles: 0,
            state: TraceState::Stop,
            start_addr: None,
            end_addr: None,
            logger,
        })
    }

    fn set_start_addr(&mut self, start_addr: u16) {
        self.start_addr = Some(start_addr);
    }

    fn set_end_addr(&mut self, end_addr: u16) {
        self.end_addr = Some(end_addr);
    }

    fn run(&mut self, input: &[u8]) -> anyhow::Result<bool> {
        let mut rdr = Cursor::new(input);
        let new_seq = Wrapping(rdr.read_u16::<LittleEndian>()?);

        match self.state {
            TraceState::Stop if new_seq == Wrapping(0) => self.state = TraceState::WaitForStart,
            TraceState::Stop => return Ok(true),
            _ => {}
        };

        self.seq_number = match self.seq_number {
            None => Some(new_seq),
            Some(x) if x + Wrapping(1) == new_seq => Some(new_seq),
            _ => unimplemented!(),
        };

        let _ = rdr.read_u16::<LittleEndian>().unwrap();

        while let Ok(word) = rdr.read_u32::<LittleEndian>() {
            let item = U64DebugStreamItem::from_u32(word)?;

            if item.ctrl_signals.get_phi2().is_active()
                && item.ctrl_signals.get_rw().is_read()
                && self.state == TraceState::WaitForStart
            {
                if let Some(start_addr) = self.start_addr {
                    if item.address == start_addr {
                        self.state = TraceState::Running;
                        self.cycles = 0;
                    }
                } else {
                    self.state = TraceState::Running;
                    self.cycles = 0;
                }
            }

            if self.state == TraceState::Running {
                self.logger.log_item(&item, self.cycles)?;
                self.cycles += 1;
                if let Some(end_addr) = self.end_addr {
                    if item.address == end_addr {
                        return Ok(false);
                    }
                }
            }
        }
        return Ok(true);
    }
}
#[derive(PartialEq, Debug)]
struct U64DebugStreamItem {
    data: u8,
    address: u16,
    ctrl_signals: Ctrl6502,
}

impl U64DebugStreamItem {
    fn from_u32(word: u32) -> anyhow::Result<Self> {
        let address = (word & 0xffff) as u16;
        let data = ((word >> 16) & 0xff) as u8;
        let ctrl_signals = Ctrl6502::from_raw_signals((word >> 24) as u8);
        Ok(U64DebugStreamItem {
            data,
            address,
            ctrl_signals,
        })
    }
}

fn log_minion_loop(
    rx: &crossbeam_channel::Receiver<Vec<u8>>,
    logger: Arc<Mutex<LogMinion>>,
) -> anyhow::Result<()> {
    let mut logger = logger.lock().unwrap();
    loop {
        let msg = rx.recv()?;
        let cont = logger.run(&msg)?;
        if !cont {
            break;
        }
    }
    Ok(())
}

struct U64Trace {
    ctrl: U64Controller,
    udp_minion: UdpMinion,
    udp_cmd_channel: crossbeam_channel::Sender<UdpMinionCmd>,
    logminion_handle: Option<thread::JoinHandle<anyhow::Result<()>>>,
    logminion: Arc<Mutex<LogMinion>>,
}

impl U64Trace {
    fn new(
        controller: &U64Controller,
        handle: Box<dyn Write + Send + Sync>,
        vcd: bool,
    ) -> anyhow::Result<U64Trace> {
        let logger: Box<dyn Logger + Send + Sync> = if vcd {
            Box::new(VCDLogger::new(handle)?)
        } else {
            Box::new(SimpleLogger::new(handle)?)
        };
        let logminion = LogMinion::new(logger)?;
        let udp_minion = UdpMinion::new()?;
        let udp_cmd_channel = udp_minion.get_cmd_channel();
        let u64_trace = U64Trace {
            ctrl: controller.clone(),
            udp_minion,
            logminion_handle: None,
            udp_cmd_channel: udp_cmd_channel.clone(),
            logminion: Arc::new(Mutex::new(logminion)),
        };
        Ok(u64_trace)
    }

    fn start_trace(
        &mut self,
        start_addr: Option<u16>,
        end_addr: Option<u16>,
    ) -> anyhow::Result<()> {
        self.ctrl.debug_trace_crtl(U64TraceCtrl::Off)?;
        let (udp_tx, udp_rx) = crossbeam_channel::unbounded();
        self.udp_cmd_channel
            .send(UdpMinionCmd::Start(udp_tx.clone()))
            .map_err(|_| Error::new(ErrorKind::Other, "crossbeam tx failed"))?;

        if let Some(start) = start_addr {
            self.logminion.lock().unwrap().set_start_addr(start);
        }
        if let Some(end) = end_addr {
            self.logminion.lock().unwrap().set_end_addr(end);
        }
        let logger = self.logminion.clone();
        let rx = udp_rx.clone();
        self.logminion_handle = Some(thread::spawn(move || log_minion_loop(&rx, logger.clone())));

        self.ctrl.debug_trace_crtl(U64TraceCtrl::On)?;
        Ok(())
    }

    fn stop_trace(&mut self) -> anyhow::Result<()> {
        self.udp_minion.stop();
        let _ = self.logminion_handle.take().unwrap().join();
        self.ctrl.debug_trace_crtl(U64TraceCtrl::Off)?;
        Ok(())
    }
}

fn handle_trace_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    fn parse_addr(param: &str) -> Option<u16> {
        use parse_int::parse;
        let addr = parse(param);
        if let Ok(a) = addr {
            Some(a)
        } else if param.to_lowercase() == "default" {
            Some(DEFAULT_ADDRESSES.0)
        } else {
            None
        }
    }

    let start_addr = match args.value_of("trace_start") {
        Some(s) => parse_addr(s),
        None => None,
    };

    let stop_addr = match args.value_of("trace_end") {
        Some(s) => parse_addr(s),
        None => None,
    };
    let vcd = args.is_present("vcd");
    let name = args.value_of("trace_output");
    let handle = match name {
        Some(x) => {
            let output_file = std::fs::File::create(x)?;
            let handle = BufWriter::new(output_file);
            Box::new(handle) as Box<dyn Write + Send + Sync>
        }
        None => Box::new(BufWriter::new(std::io::stdout())) as Box<dyn Write + Send + Sync>,
    };

    let mut trace = U64Trace::new(u64_ctrl, handle, vcd)?;
    trace.start_trace(start_addr, stop_addr)?;

    if args.is_present("program") {
        u64_ctrl.run(args.value_of("program").unwrap())?;
    } else if args.is_present("d64_image") {
        u64_ctrl.run_image(args.value_of("d64_image").unwrap())?;
    }

    use signal_hook::{iterator::Signals, SIGINT};
    let signals = Signals::new(&[SIGINT])?;
    dbg!();
    signals.wait();
    dbg!();
    trace.stop_trace()?;
    dbg!();

    Ok(())
}

fn handle_run_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    let (name, filename) = if args.is_present("local_file") {
        let local_file = args.value_of("local_file").unwrap().to_string();
        (upload_file(u64_ctrl, &local_file)?, local_file)
    } else if args.is_present("remote_file") {
        let remote_file = args.value_of("remote_file").unwrap().to_string();
        (remote_file.clone(), remote_file)
    } else {
        unreachable!();
    };

    if args.is_present("program") {
        u64_ctrl.run_prg_by_path(name)
    } else if args.is_present("d64") {
        u64_ctrl.run_img_by_path(name)
    } else if args.is_present("crt") {
        u64_ctrl.run_crt_by_path(name)
    } else {
        use anyhow::anyhow;
        let path = Path::new(&filename);
        match path.extension().map(|e| e.to_ascii_lowercase()) {
            Some(ext) if ext == "d64" => u64_ctrl.run_img_by_path(name),
            Some(ext) if ext == "prg" => u64_ctrl.run_prg_by_path(name),
            Some(ext) if ext == "crt" => u64_ctrl.run_crt_by_path(name),
            Some(ext) => Err(anyhow!(
                "Unknown extension {}. Specify filetype using options.",
                ext.to_string_lossy()
            )),
            None => Err(anyhow!(
                "No file extenstion detected. Specify filetype using options."
            )),
        }
    }
}

fn handle_mount_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    let name = if args.is_present("d64_local_image") {
        upload_file(u64_ctrl, args.value_of("d64_local_image").unwrap())?
    } else if args.is_present("d64_remote_image") {
        args.value_of("d64_remote_image").unwrap().to_owned()
    } else {
        unreachable!();
    };

    u64_ctrl.mount_img_by_path(&name)?;
    Ok(())
}

fn handle_reset_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    let reset_type = match args.subcommand() {
        ("c64", _) => U64ResetCtrl::C64,
        ("u64", _) => U64ResetCtrl::U64,
        _ => unreachable!(),
    };

    u64_ctrl.reset(reset_type)
}

fn handle_keyb_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    let keys = args.values_of("keystrokes").unwrap().collect::<String>();
    u64_ctrl.keys(keys.as_bytes())?;
    Ok(())
}

fn handle_dumpmem_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    let name = args.value_of("filename").unwrap();
    u64_ctrl.dumpmem(name)
}

fn upload_file<P: AsRef<std::path::Path>>(
    u64_ctrl: &U64Controller,
    local: P,
) -> anyhow::Result<String> {
    let remote = "/Temp/ftpimage".to_string();
    let mut reader = std::fs::File::open(local)?;
    let mut ftp = u64ftp::U64Ftp::from_u64_ctrl(u64_ctrl)?;
    ftp.put(&mut reader, &remote)?;
    Ok(remote)
}

fn handle_flash_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    let name = if args.is_present("local_file") {
        upload_file(u64_ctrl, args.value_of("local_file").unwrap())?
    } else if args.is_present("remote_file") {
        args.value_of("remote_file").unwrap().to_owned()
    } else {
        unreachable!();
    };
    u64_ctrl.flash(name)
}

fn handle_poweroff_cmd(u64_ctrl: &U64Controller) -> anyhow::Result<()> {
    u64_ctrl.poweroff()
}

fn handle_fs_cmd(u64_ctrl: &U64Controller, args: &ArgMatches) -> anyhow::Result<()> {
    use u64ftp::U64Ftp;
    match args.subcommand() {
        ("ls", Some(sub_args)) => {
            let mut ftp = U64Ftp::from_u64_ctrl(u64_ctrl)?;
            for l in ftp.ls(sub_args.value_of("path"))? {
                println!("{}", l);
            }
        }
        ("put", Some(sub_args)) => {
            let mut ftp = U64Ftp::from_u64_ctrl(u64_ctrl)?;
            let local = sub_args.value_of("local").unwrap();
            let mut reader = std::fs::File::open(local)?;
            let local_filename = Path::new(local).file_name().unwrap();
            let remote = match sub_args.value_of("remote") {
                Some(x) if x.ends_with("/") || Path::new(x).file_name().is_none() => {
                    let mut r = x.to_string();
                    r.push_str(&local_filename.to_string_lossy());
                    r
                }
                Some(x) => x.to_string(),
                None => local_filename.to_string_lossy().to_string(),
            };
            ftp.put(&mut reader, remote)?;
        }
        ("get", Some(sub_args)) => {
            let remote = sub_args.value_of("remote").unwrap();
            let remote_filename = if !remote.ends_with("/") {
                match Path::new(remote).file_name() {
                    Some(f) => Ok(f),
                    None => Err(Error::new(
                        ErrorKind::Other,
                        format!("{} is not a filename", remote),
                    )),
                }
            } else {
                Err(Error::new(
                    ErrorKind::Other,
                    format!("{} is not a filename", remote),
                ))
            }?;

            let local = match sub_args.value_of("local") {
                Some(x) => std::ffi::OsStr::new(x),
                None => remote_filename,
            };
            let mut ftp = U64Ftp::from_u64_ctrl(u64_ctrl)?;
            let buffer = ftp.get(remote)?;
            let buffer = buffer.get_ref();
            let mut file = std::fs::File::create(local)?;
            file.write_all(buffer)?;
        }
        ("rm", Some(sub_args)) => {
            let remote = sub_args.value_of("remote").unwrap();
            let mut ftp = U64Ftp::from_u64_ctrl(u64_ctrl)?;
            ftp.rm(remote)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    use clap::{App, AppSettings, Arg, SubCommand};

    let cli_args = App::new("u64-monitor")
        .version("0.1")
        .author("Peter De Schrijver")
        .about("Ultimate64 remote control program")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(
            Arg::with_name("U64 address")
                .help("Ultimate64 hostname[:port]")
                .short("-u")
                .takes_value(true)
                .long("ultimate64"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Run CRT, D64 or PRG file")
                .arg(
                    Arg::with_name("program")
                        .short("p")
                        .help("Run program")
                        .conflicts_with_all(&["d64", "crt"])
                        .long("program"),
                )
                .arg(
                    Arg::with_name("d64")
                        .short("d")
                        .help("Run D64 image")
                        .conflicts_with_all(&["program", "crt"])
                        .long("image"),
                )
                .arg(
                    Arg::with_name("crt")
                        .short("c")
                        .help("Cartridge to run")
                        .conflicts_with_all(&["d64", "program"])
                        .long("cartridge"),
                )
                .arg(
                    Arg::with_name("local_file")
                        .short("l")
                        .help("Local file to use")
                        .takes_value(true)
                        .required_unless_one(&["remote_file"])
                        .conflicts_with_all(&["remote_file"])
                        .long("local"),
                )
                .arg(
                    Arg::with_name("remote_file")
                        .short("r")
                        .help("Remote file to use")
                        .takes_value(true)
                        .required_unless_one(&["local_file"])
                        .conflicts_with_all(&["local_file"])
                        .long("remote"),
                ),
        )
        .subcommand(
            SubCommand::with_name("mount")
                .about("Mount D64 image")
                .arg(
                    Arg::with_name("d64_local_image")
                        .short("l")
                        .help("Local image to mount")
                        .takes_value(true)
                        .required_unless_one(&["d64_remote_image"])
                        .conflicts_with_all(&["d64_remote_image"])
                        .long("local"),
                )
                .arg(
                    Arg::with_name("d64_remote_image")
                        .short("r")
                        .help("Remote image to mount")
                        .takes_value(true)
                        .required_unless_one(&["d64_local_image"])
                        .conflicts_with_all(&["d64_local_image"])
                        .long("remote"),
                ),
        )
        .subcommand(
            SubCommand::with_name("reset")
                .about("Reset C64 or U64")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(SubCommand::with_name("c64").about("Reset C64"))
                .subcommand(SubCommand::with_name("u64").about("Reset U64")),
        )
        .subcommand(
            SubCommand::with_name("keyb").about("Send keystrokes").arg(
                Arg::with_name("keystrokes")
                    .index(1)
                    .min_values(1)
                    .max_values(1)
                    .required(true),
            ),
        )
        .subcommand(
            SubCommand::with_name("dumpmem")
                .about("Dump U64 memory")
                .arg(
                    Arg::with_name("filename")
                        .short("o")
                        .long("dump_output")
                        .help("Output filename")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("trace")
                .about("Trace U64 execution")
                .arg(
                    Arg::with_name("program")
                        .short("p")
                        .help("Program to run")
                        .takes_value(true)
                        .long("program"),
                )
                .arg(
                    Arg::with_name("d64_image")
                        .short("i")
                        .help("Image to run")
                        .takes_value(true)
                        .conflicts_with("program")
                        .long("image"),
                )
                .arg(
                    Arg::with_name("trace_output")
                        .short("o")
                        .long("trace_output")
                        .help("Trace output filename")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("trace_start")
                        .short("b")
                        .long("begin_address")
                        .help("Start address for tracing")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("trace_end")
                        .short("e")
                        .long("end_address")
                        .help("Stop address for tracing")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("vcd")
                        .long("vcd")
                        .help("Output in VCD format"),
                ),
        )
        .subcommand(
            SubCommand::with_name("flash")
                .about("Update U64 firmware")
                .arg(
                    Arg::with_name("local_file")
                        .short("l")
                        .long("local")
                        .help("Local firmware image to flash")
                        .required_unless_one(&["remote_file"])
                        .conflicts_with_all(&["remote_file"])
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("remote_file")
                        .short("r")
                        .long("remote")
                        .help("Remote firmware image to flash")
                        .required_unless_one(&["local_file"])
                        .conflicts_with_all(&["local_file"])
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(SubCommand::with_name("poweroff").about("Power off U64"))
        .subcommand(
            SubCommand::with_name("fs")
                .about("U64 fs manipulation")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("ls")
                        .about("List directory")
                        .arg(Arg::with_name("path").takes_value(true)),
                )
                .subcommand(
                    SubCommand::with_name("put")
                        .about("Write file to target")
                        .arg(Arg::with_name("local").takes_value(true).required(true))
                        .arg(Arg::with_name("remote").takes_value(true).required(false)),
                )
                .subcommand(
                    SubCommand::with_name("get")
                        .about("Read file From target")
                        .arg(Arg::with_name("remote").takes_value(true).required(true))
                        .arg(Arg::with_name("local").takes_value(true).required(false)),
                )
                .subcommand(
                    SubCommand::with_name("rm")
                        .about("Remove remote file")
                        .arg(Arg::with_name("remote").takes_value(true).required(true)),
                ),
        )
        .get_matches();

    let u64_address = if let Some(address) = cli_args.value_of("U64 address") {
        if let Ok(_) = address.to_socket_addrs() {
            address.to_owned()
        } else {
            let mut addr = address.to_string();
            addr.push_str(":64");
            addr
        }
    } else {
        "Ultimate-64:64".to_owned()
    };

    let u64_ctrl = U64Controller::new(u64_address)?;

    match cli_args.subcommand() {
        ("run", Some(sub_m)) => handle_run_cmd(&u64_ctrl, &sub_m),
        ("mount", Some(sub_m)) => handle_mount_cmd(&u64_ctrl, &sub_m),
        ("reset", Some(sub_m)) => handle_reset_cmd(&u64_ctrl, &sub_m),
        ("keyb", Some(sub_m)) => handle_keyb_cmd(&u64_ctrl, &sub_m),
        ("dumpmem", Some(sub_m)) => handle_dumpmem_cmd(&u64_ctrl, &sub_m),
        ("trace", Some(sub_m)) => handle_trace_cmd(&u64_ctrl, &sub_m),
        ("flash", Some(sub_m)) => handle_flash_cmd(&u64_ctrl, &sub_m),
        ("poweroff", Some(_)) => handle_poweroff_cmd(&u64_ctrl),
        ("fs", Some(sub_m)) => handle_fs_cmd(&u64_ctrl, &sub_m),
        _ => {
            unimplemented!();
        }
    }
}
