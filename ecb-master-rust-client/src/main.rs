use clap::{Parser, Subcommand};
use ecbm::{signals, tlv, Ecbm};
use serde::{Deserialize, Serialize};

use std::{io::{Read, Write}, net::{SocketAddr, TcpStream}, sync::mpsc::{channel, Receiver, Sender}, thread, time::Duration};


const DEFAULT_CONFIG_PATH_STR: &str = "config.toml";


#[derive(Debug, Parser)]
struct CliExec {
    /// TCP port of slave-server
    #[arg(default_value_t=25001)]
    port: u16,

    /// Silence all log output.
    #[arg(short='q')]
    quiet: bool,

    /// Increase log level verbosity.
    #[arg(short='v', default_value_t=0)]
    verbose: usize,
}

#[derive(Debug, Subcommand)]
enum CliInteractiveSubcommand {
    /// Quit from app.
    Q,
    /// Read signal from slave.
    Read {
        addr: u8,
        sig: u16,
    },
    /// Read signal from slave with encryption.
    ReadEnc {
        addr: u8,
        sig: u16,
    },
    /// Write signal to slave.
    Write {
        addr: u8,
        sig: u16,
        data: Vec<u8>,
    },
    /// Write signal to slave with encryption.
    WriteEnc {
        addr: u8,
        sig: u16,
        data: Vec<u8>,
    },
    /// Write signal to slave with authentication.
    WriteAuth {
        addr: u8,
        sig: u16,
        data: Vec<u8>,
    },
    /// Write signal to slave(s) without slave assert answer.
    WriteNoAnsw {
        /// 0 for broadcast
        addr: u8,
        sig: u16,
        data: Vec<u8>,
    },
    /// Write signal to slave(s) with encryption, without slave assert answer.
    WriteNoAnswEnc {
        /// 0 for broadcast
        addr: u8,
        sig: u16,
        data: Vec<u8>,
    },
    /// Open encryption session with slave, key may be given from storage by addr.
    OpenEnc {
        addr: u8,
        #[arg(short)]
        key: Option<Vec<u8>>,
        #[arg(short)]
        store: bool,
    },
    /// Open stream - fast sending of data from slave, one stream blocking bus. 
    OpenStream {
        addr: u8,
        sig: u16,
    },
    /// Open stream with encryption - fast sending of data from slave, one stream blocking bus. 
    OpenStreamEnc {
        addr: u8,
        sig: u16,
    },
    /// Close opened stream.
    CloseStream,
    /// Read device info from slave, signal 
    ReadInfo {
        addr: u8,
    }
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct CliInteractive {
    #[command(subcommand)]
    cmd: CliInteractiveSubcommand,
}


#[derive(Debug, Serialize, Deserialize)]
struct EncKey {
    pub addr: u8,
    pub key: [u8;16],
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(skip)]
    path: String,

    pub enc_keys: Vec<EncKey>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, std::io::Error> {
        let mut config_file = std::fs::File::open(path)?;
        let mut config_raw = String::new();
        config_file.read_to_string(&mut config_raw)?;
        match toml::from_str::<Config>(&config_raw) {
            Ok(mut config) => {
                config.path = path.to_string();
                Ok(config)
            },
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())),
        }
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        match toml::to_string(self) {
            Ok(config_raw) => {
                let mut config_file = std::fs::File::open(&self.path)?;
                config_file.write_all(&config_raw.as_bytes())
            },
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())),
        }
    }

    pub fn find_key(&self, addr: u8) -> Result<Vec<u8>, std::io::Error> {
        for k in &self.enc_keys {
            if k.addr == addr {
                return Ok(k.key.to_vec());
            }
        }
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Encryption key not found in config."))
    }

    pub fn add_key(&mut self, addr: u8, key: &[u8]) {
        for k in &mut self.enc_keys {
            if k.addr == addr {
                k.key.copy_from_slice(key);
                return;
            }
        }
        self.enc_keys.push(EncKey { addr: addr, key: key.try_into().unwrap() });
    }
}


fn cli_interactive_input_th(tx: Sender<Vec<String>>) {
    loop {
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        let buf_split: Vec<String> = buf.split_whitespace().map(|str| str.to_string()).collect();
        tx.send(buf_split).unwrap();
    }
}

fn print_vec_with_str_repr(data: &[u8]) {
    println!("Read data({}): {:?}, str: {}.", data.len(), data, String::from_utf8_lossy(data));
}

fn start_stream(stream: Receiver<Vec<u8>>) {
    thread::spawn(move || {
        loop {
            match stream.try_recv() {
                Ok(data) => println!("Stream data: {data:?} str: {}", String::from_utf8_lossy(&data)),
                Err(err) => match err {
                    std::sync::mpsc::TryRecvError::Disconnected => {
                        println!("Stream closed.");
                        break;
                    },
                    std::sync::mpsc::TryRecvError::Empty => (),
                },
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
}


fn main() -> Result<(), std::io::Error> {
    let cli = CliExec::parse();
    stderrlog::new()
        .modules([module_path!(), "ecbm"])
        .quiet(cli.quiet)
        .verbosity(cli.verbose)
        .timestamp(stderrlog::Timestamp::Off)
        .show_module_names(true)
        .init()
        .unwrap();
    let mut config = match Config::from_file(DEFAULT_CONFIG_PATH_STR) {
        Ok(v) => v,
        Err(err) => {
            println!("Fail to open config file.");
            return  Err(err);
        },
    };
    let (cli_tx, cli_rx) = channel::<Vec<String>>();
    thread::spawn(move || cli_interactive_input_th(cli_tx));
    let sock_addr: SocketAddr = format!("127.0.0.1:{}", cli.port).parse().unwrap();
    let stream = match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(500)) {
        Ok(v) => v,
        Err(err) => {
            println!("Fail to connect to ecb-slave-server.");
            return Err(err);
        }
    };
    stream.set_nonblocking(true).unwrap();
    let mut ecbm = Ecbm::<TcpStream>::new(stream);
    if let Err(err) = ecbm.close_stream() {
        println!("Fail to close possibly open streams on bus.");
        return Err(err.into());
    }
    loop {
        let mut cmd_raw = cli_rx.recv().unwrap();
        cmd_raw.insert(0, "INTERACTIVE".to_string());
        match CliInteractive::try_parse_from(cmd_raw) {
            Ok(cli_interactive) => match cli_interactive.cmd {
                CliInteractiveSubcommand::Q => break Ok(()),
                CliInteractiveSubcommand::Read { addr, sig } => match ecbm.read(addr, sig, None) {
                    Ok(data) => print_vec_with_str_repr(&data),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::ReadEnc { addr, sig } => match ecbm.read_enc(addr, sig, None) {
                    Ok(data) => print_vec_with_str_repr(&data),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::Write { addr, sig, data } => match ecbm.write(addr, sig, &data, None) {
                    Ok(()) => println!("Write ok."),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::WriteEnc { addr, sig, data } => match ecbm.write_enc(addr, sig, &data, None) {
                    Ok(()) => println!("Write ok."),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::WriteAuth { addr, sig, data } => match ecbm.write_auth(addr, sig, &data, None) {
                    Ok(()) => println!("Write ok."),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::WriteNoAnsw { addr, sig, data } => match ecbm.write_no_answ(addr, sig, &data) {
                    Ok(()) => println!("Write ok."),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::WriteNoAnswEnc { addr, sig, data } => match ecbm.write_no_answ_enc(addr, sig, &data) {
                    Ok(()) => println!("Write ok."),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::OpenEnc { addr, key, store } => {
                    let mut open_enc = |addr: u8, key: Option<Vec<u8>>, store: bool, config: &mut Config|
                        -> Result<(), std::io::Error>
                    {
                        let enc_key = match key {
                            Some(key) => {
                                if key.len() != 16 {
                                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                                        "Key must has size equal to 16 bytes."));
                                }
                                if store {
                                    config.add_key(addr, &key);
                                    config.save()?;
                                }
                                key
                            },
                            None => config.find_key(addr)?,
                        };
                        match ecbm.open_enc_session(addr, &enc_key) {
                            Ok(()) => Ok(()),
                            Err(err) => Err(err.into()),
                        }
                    };

                    match (open_enc)(addr, key, store, &mut config) {
                        Ok(()) => println!("Encryption session success open."),
                        Err(err) => println!("Error: {err:?}"),
                    }
                },
                CliInteractiveSubcommand::OpenStream { addr, sig } => match ecbm.open_stream(addr, sig) {
                    Ok(stream) => start_stream(stream),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::OpenStreamEnc { addr, sig } => match ecbm.open_stream_enc(addr, sig) {
                    Ok(stream) => start_stream(stream),
                    Err(err) => println!("Error: {err:?}."),
                },
                CliInteractiveSubcommand::CloseStream => match ecbm.close_stream() {
                    Ok(()) => println!("Stream successfully closed."),
                    Err(err) => println!("Error: {err:?}."),                    
                },
                CliInteractiveSubcommand::ReadInfo { addr } => match ecbm.read(addr, signals::INFO, None) {
                    Ok(answ) => {
                        let tlvs = iso7816_tlv::simple::Tlv::parse_all(&answ);
                        for tlv in tlvs {
                            match tlv.tag().into() {
                                tlv::NAME => {
                                    let name = String::from_utf8_lossy(tlv.value());
                                    println!("Name: {name}");
                                },
                                tlv::VERSION => println!("Version: {:?}", tlv.value()),
                                tlv::SERIAL => {
                                    let serial = String::from_utf8_lossy(tlv.value());
                                    println!("Serial: {serial}");
                                },
                                tag => println!("[WRN] unknown tlv tag in answer: {tag:?}"),
                            }
                        }
                    },
                    Err(err) => println!("Error: {err:?}."),
                },
            },
            Err(err) => err.print().unwrap(),
        }
    }
}
