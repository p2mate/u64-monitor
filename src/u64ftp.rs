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
use crate::u64ctrl::U64Controller;
use chrono::naive::datetime;
use ftp::FtpStream;
use regex::Regex;
use std::{
    fmt::{Display, Formatter},
    fs::File,
    io::Write,
    net::SocketAddr,
};

pub struct U64Ftp {
    ftp: FtpStream,
}

#[derive(Debug)]
pub struct DirEntry {
    name: String,
    modified_date: datetime::NaiveDateTime,
    filetype: FileType,
}

#[derive(Debug)]
pub enum FileType {
    File(usize),
    Dir,
}

lazy_static::lazy_static! {
    static ref PORT_RE: Regex = Regex::new(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)").unwrap();
    static ref MLSD_RE: Regex = Regex::new(r"type=(.*);size=(.*);modify=(.*);(.*)").unwrap();
}

impl Display for DirEntry {
    fn fmt(&self, dest: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self.filetype {
            FileType::File(l) => write!(
                dest,
                "{} {:10} {}",
                self.modified_date.format("%Y-%b-%d %H:%M"),
                l,
                self.name
            ),
            FileType::Dir => write!(
                dest,
                "{} {:>10} {}/",
                self.modified_date.format("%Y-%b-%d %H:%M"),
                "<DIR>",
                self.name
            ),
            _ => unreachable!(),
        }
    }
}

impl U64Ftp {
    pub fn from_u64_ctrl(u64_ctrl: &U64Controller) -> anyhow::Result<Self> {
        let mut peer = u64_ctrl.get_peer_addr()?;
        peer.set_port(21);
        let mut ftp = FtpStream::connect(peer)?;
        ftp.login("", "")?;
        Ok(U64Ftp { ftp })
    }

    fn do_mlsd<T: AsRef<str>>(&mut self, path: T) -> anyhow::Result<Vec<DirEntry>> {
        use std::io::{BufRead, BufReader};
        use std::net::TcpStream;
        let server_addr = self.do_pasv()?;
        let mut tcp_stream = self.ftp.get_ref();
        tcp_stream.write("MLSD ".as_bytes())?;
        tcp_stream.write(path.as_ref().as_bytes())?;
        tcp_stream.write("\r\n".as_bytes())?;
        drop(tcp_stream);
        let _ = self.ftp.read_response(150)?;
        let server = TcpStream::connect(server_addr)?;
        let buffered_connection = BufReader::new(server);
        let mut result = Vec::new();
        for l in buffered_connection.lines() {
            let line = l?;
            let (filetype, length, modified_date, name) = MLSD_RE
                .captures(&line)
                .ok_or(ftp::FtpError::InvalidResponse(format!(
                    "Unexpected MLSD line: {}",
                    line
                )))
                .and_then(|captured| {
                    Ok((
                        captured[1].to_owned(),
                        captured[2].parse::<usize>(),
                        chrono::NaiveDateTime::parse_from_str(&captured[3], "%Y%m%d%H%M%S"),
                        captured[4].trim().to_owned(),
                    ))
                })?;

            let filetype = match filetype.as_str() {
                "file" => Ok(FileType::File(length?)),
                "dir" => Ok(FileType::Dir),
                _ => Err(ftp::FtpError::InvalidResponse(format!(
                    "Invalid file type {}",
                    filetype
                ))),
            }?;

            let modified_date = modified_date?;
            result.push(DirEntry {
                name,
                modified_date,
                filetype,
            })
        }
        let _ = self.ftp.read_response(226)?;
        Ok(result)
    }

    fn do_pasv(&mut self) -> anyhow::Result<SocketAddr> {
        let mut tcp_stream = self.ftp.get_ref();
        tcp_stream.write("PASV\r\n".as_bytes())?;
        drop(tcp_stream);
        let ftp::types::Line(code, line) = self.ftp.read_response(227)?;
        if code != 227 {
            return Err(ftp::FtpError::InvalidResponse(format!(
                "Unexpected response code {}",
                code
            ))
            .into());
        }

        PORT_RE
            .captures(&line)
            .ok_or(ftp::FtpError::InvalidResponse(format!("Unexpected response {}", line)).into())
            .and_then(|captured| {
                use std::net::{IpAddr, Ipv4Addr};

                let addr_bytes = (
                    captured[1].parse::<u8>()?,
                    captured[2].parse::<u8>()?,
                    captured[3].parse::<u8>()?,
                    captured[4].parse::<u8>()?,
                );
                let port_bytes = (captured[5].parse::<u16>()?, captured[6].parse::<u16>()?);
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        addr_bytes.0,
                        addr_bytes.1,
                        addr_bytes.2,
                        addr_bytes.3,
                    )),
                    (port_bytes.0 << 8) + port_bytes.1,
                ))
            })
    }

    pub fn ls<T: AsRef<str> + ?Sized>(
        &mut self,
        path: Option<&T>,
    ) -> anyhow::Result<Vec<DirEntry>> {
        let dir_path = path.map(|p| p.as_ref()).unwrap_or("");
        self.do_mlsd(dir_path)
    }

    pub fn put<R: std::io::Read, T: AsRef<str>>(
        &mut self,
        local: &mut R,
        remote: T,
    ) -> anyhow::Result<()> {
        self.ftp.put(remote.as_ref(), local).map_err(|e| e.into())
    }

    pub fn get<T: AsRef<str>>(&mut self, remote: T) -> anyhow::Result<std::io::Cursor<Vec<u8>>> {
        self.ftp.simple_retr(remote.as_ref()).map_err(|e| e.into())
    }
    pub fn rm<T: AsRef<str>>(&mut self, remote: T) -> anyhow::Result<()> {
        self.ftp.rm(remote.as_ref()).map_err(|e| e.into())
    }
}
