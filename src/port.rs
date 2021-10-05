use std::fmt::{self, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum PortStatus {
    Opened { banner: Option<Vec<u8>> },
    Closed,
    Filtered,
}

fn hex_format(f: &mut fmt::Formatter, data: &[u8]) -> fmt::Result {
    f.write_str("hex:")?;
    for b in data {
        write!(f, "{:2x}", b)?;
    }

    Ok(())
}

fn escape_string(f: &mut fmt::Formatter, string: &str) -> fmt::Result {
    for c in string.chars() {
        if c == '\n' {
            f.write_str("\\n")?;
        } else if c == '\t' {
            f.write_str("\\t")?;
        } else if c == '\r' {
            f.write_str("\\r")?;
        } else {
            f.write_char(c)?;
        }
    }

    Ok(())
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opened { ref banner } => {
                f.write_str("opened")?;
                if let Some(banner) = banner {
                    f.write_str(" (banner: \"")?;
                    match std::str::from_utf8(&banner[..]) {
                        Ok(string) => {
                            escape_string(f, string)?;
                        }
                        Err(_) => {
                            hex_format(f, banner)?;
                        }
                    }
                    f.write_str("\")")?;
                }
                Ok(())
            }
            Self::Filtered => f.write_str("filtered"),
            Self::Closed => f.write_str("closed"),
        }
    }
}

#[derive(Debug)]
pub struct Port {
    pub status: PortStatus,
    pub num: u16,
}

impl Port {
    pub fn is_open(&self) -> bool {
        match self.status {
            PortStatus::Opened { .. } => true,
            _ => false,
        }
    }

    pub fn has_banner(&self) -> bool {
        match self.status {
            PortStatus::Opened { ref banner } => banner.is_some(),
            _ => false,
        }
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:5}: {}", self.num, self.status)
    }
}

pub struct PortsListIterator<'a> {
    ports_list: &'a PortsList,
    current: usize,
}

#[derive(Debug)]
pub struct PortsList([u8; 8192]);

impl PortsList {
    pub fn new() -> Self {
        Self([0u8; 8192])
    }

    pub fn len(&self) -> usize {
        self.0.iter().map(|b| b.count_ones()).sum::<u32>() as usize
    }

    pub fn contains(&self, port: u16) -> bool {
        let (index, bit) = Self::get_index_and_bit(port);
        self.0[index] & (1u8 << bit) != 0
    }

    fn get_index_and_bit(port: u16) -> (usize, usize) {
        let port = port as usize;
        (port >> 3, port & 7)
    }

    pub fn add_port(&mut self, port: u16) {
        let (index, bit) = Self::get_index_and_bit(port);
        self.0[index] |= 1u8 << bit;
    }

    pub fn remove_port(&mut self, port: u16) {
        let (index, bit) = Self::get_index_and_bit(port);
        let mask = 0xff ^ (1u8 << bit);
        self.0[index] &= 0xff ^ mask;
    }

    pub fn add_ports(&mut self, ports: &[u16]) {
        for port in ports {
            self.add_port(*port);
        }
    }

    #[allow(dead_code)]
    pub fn remove_ports(&mut self, ports: &[u16]) {
        for port in ports {
            self.remove_port(*port);
        }
    }

    pub fn iter<'a>(&'a self) -> PortsListIterator<'a> {
        PortsListIterator {
            ports_list: &self,
            current: 1,
        }
    }
}

impl std::iter::Iterator for PortsListIterator<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        while self.current <= 0xffff {
            let port = self.current as u16;
            self.current += 1;
            if self.ports_list.contains(port) {
                return Some(port);
            }
        }

        None
    }
}
